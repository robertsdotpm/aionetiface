"""
Extended functionality to allow the UDP stream class to provide 'reliable'
packet delivery. It uses message IDs for each message and acknowledgements.
It doesn't guarantee ordered delivery. Inherited by udp_stream.
"""

import asyncio
import struct
import random
from struct import pack
from typing import Any, Callable, List, Optional, Tuple
from ..utility.utils import async_wrap_errors, rm_done_tasks, timestamp, to_b


UDP_MAX_DICT_LEN = 1000


class ACKUDP:
    """Mixin that adds reliable delivery over UDP via sequence numbers and acknowledgements."""
    def __init__(self) -> None:
        self.seq = {}  # Waiting for acks.
        self.ack_send_tasks = []

    # Returns a sequence number if a message is an ack.
    def is_ack(self, data: bytes, stream: Any) -> Optional[int]:
        """Return the sequence number from data if it is an ACK message, otherwise return None."""
        if len(data) >= 9:
            (seq,) = struct.unpack("!Q", data[0:8])
            is_ack = data[8]
            if is_ack == 1:
                return seq

        return None

    # Received message that needs to be acked.
    # Return its sequence number and valid ack response.
    def is_ackable(self, data: bytes, stream: Any) -> List[Optional[Any]]:
        """Return [seq, ack_response, payload] for a message that requires acknowledgement, or [None, None, None] if invalid."""
        ack = is_ack = seq = None
        if len(data) >= 9:
            (seq,) = struct.unpack("!Q", data[0:8])
            is_ack = data[8]
        else:
            return [None, None, None]

        if is_ack == 0:
            # Build ack message to send in response.
            ack = struct.pack("!Q", seq) + struct.pack("!B", 1)

        return [seq, ack, data[9:]]

    # Clients that receive an ackable message send back the ack every time
    # they receive it, even if already acked, since we can't know if our
    # prior ack was received. Skip acking if a peer sent the same sequence;
    # this prevents the sender from getting into a loop.
    def handle_ack(
        self,
        data: bytes,
        f_is_ack: Callable[..., Any],
        f_is_ackable: Callable[..., Any],
        f_send: Callable[..., Any],
    ) -> Tuple[int, Optional[bytes]]:
        """Process an incoming packet for ACK or ackable content and return a status code with the stripped payload."""
        self.ack_send_tasks = rm_done_tasks(self.ack_send_tasks)
        payload = recv_seq = ack_seq = ack = None
        self.timestamp = timestamp()

        # If this message is an ack then record its seq no.
        if f_is_ack is not None:
            ack_seq = f_is_ack(data, self)
            if ack_seq is not None:
                if ack_seq in self.seq:
                    self.seq[ack_seq].set()

                return 0, payload

        # If it's a regular message check if it needs
        # to be acknowledged and record the seq no.
        if f_is_ackable is not None:
            recv_seq, ack, payload = f_is_ackable(data, self)
            if payload is None:
                return 0, None

            if ack is not None:
                # Seq is set when sending.
                # If they give us back our seq take it as an ACK
                # even if they didn't set the ACK flag.
                if recv_seq in self.seq:
                    # Pretend we received an ACK for our message.
                    self.seq[recv_seq].set()

                    # Don't broadcast an ACK for this.
                    ack = None

        # Keep dicts from taking up too much memory.
        if len(self.seq) > UDP_MAX_DICT_LEN:
            self.seq = {}

        # The TURN client implements a custom is_ackable that wraps an ACK
        # in a channel message which allows the server to deliver the message.
        if ack is not None:
            task = asyncio.create_task(async_wrap_errors(f_send(ack)))

            self.ack_send_tasks.append(task)
            return 2, payload

        return 1, payload

    # Retransmits a UDP packet up to 'tries' times or 'sock_timeout' seconds.
    # If an acknowledgement arrives before an error condition the function
    # returns successfully. Events are used to wait on ACKs so there are no
    # busy-loop checks.
    async def ack_send(
        self,
        data: bytes,
        dest_tup: Tuple[Any, ...],
        seq: Optional[int] = None,
        sock_timeout: int = 0,
        tries: int = 3,
    ) -> Tuple[Any, Any]:
        # Keep sending until max sends reached.
        # For acks we send max transmits as they're small messages.
        if seq is None:
            seq = random.randrange(1, (2 ** (8 * 8)))

        # Mark all messages we send in the same data structure clients use to
        # indicate whether they have acknowledged a message. This prevents
        # the sender from getting into loops.
        event = asyncio.Event()
        self.seq[seq] = event

        # Do the sending concurrently so event can be returned.
        async def worker():
            # Record when the process started.
            start = 0
            if sock_timeout:
                start = timestamp()

            # Build data to send.
            buf = bytearray().join([pack("!Q", seq), pack("!B", 0), memoryview(data)])

            # Await on ACK events.
            # Break on transmits >= tries, timeout, or success.
            send_transmits = 0
            while True:
                # Initial send.
                await self.send(buf, dest_tup)
                send_transmits += 1

                # Finish trying to send.
                # First failure mode reached.
                if send_transmits >= tries:
                    break

                # Recheck for ack every second.
                try:
                    # Will return instantly on receiving a related ACK.
                    # Otherwise it suspends for other code to execute.
                    await asyncio.wait_for(self.seq[seq].wait(), 3)

                    # No timeout error = success.
                    break
                except asyncio.TimeoutError:
                    pass

                # Too much time passed.
                # Second failure mode reached.
                if sock_timeout:
                    elapsed = timestamp() - start
                    if elapsed >= sock_timeout:
                        break

            # Do cleanup.
            if seq in self.seq:
                del self.seq[seq]

        # Schedule sending task.
        task = asyncio.create_task(worker())
        self.ack_send_tasks.append(task)

        # Wait for ACK.
        return task, event


class BaseACKProto(asyncio.Protocol):
    """Base asyncio.Protocol providing duplicate-message detection for UDP streams."""
    def __init__(self, conf: Any) -> None:
        self.conf = conf

    # Supports dropping duplicate messages.
    def is_unique_msg(self, pipe: Any, data: bytes, client_tup: Tuple[Any, ...]) -> int:
        """Return 1 if data has not been seen before from client_tup, or 0 if it is a duplicate."""
        # Reset seen msgs after dict fills.
        if len(self.msg_ids) > self.conf["max_msg_ids"]:
            self.msg_ids = {}

        # Record msg -- drop if already seen.
        # Route by client endpoint.
        # Seen messages are per client IP.
        buf = to_b(client_tup[0]) + data

        # Python's built-in hash is intentionally used here over a
        # cryptographic hash. A secure hash (SHA-256 etc.) would be
        # 100+ ms per message and destroy event loop performance.
        msg_id = hash(buf)
        if msg_id in self.msg_ids:
            return 0
        self.msg_ids[msg_id] = 1
        return 1
