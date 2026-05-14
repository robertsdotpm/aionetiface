"""Self-update helper for the aionetiface package."""
import asyncio
import hashlib
import json
import os
import time
from .servers import INFRA, INFRA_BUF
from .protocol.http.http_client_lib import WebCurl
from .install import (
    get_aionetiface_install_root,
    copy_aionetiface_install_files_as_needed,
)
from .utility.utils import to_s, log_exception
from .utility.error_logger import log


def compute_server_list_checksum(infra):
    """SHA-256 of the server list content, ignoring `timestamp` and
    the `checksum` field itself.

    Used as a tamper / hand-edit detector: when the on-disk file's
    stored `checksum` no longer matches what we compute over the
    rest of its content, the user has been hand-editing it and the
    updater leaves the file alone.
    """
    payload = {
        k: v for k, v in infra.items()
        if k not in ("checksum", "timestamp")
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stamp_checksum(infra):
    """Insert / overwrite the `checksum` field on infra in place."""
    infra["checksum"] = compute_server_list_checksum(infra)


# Exponential backoff for the dealer fetch when ovh1.p2pd.net:8000 is
# unreachable.  Caps at MAX_BACKOFF_SEC so a permanently-offline
# dealer doesn't make us pay the fetch timeout every month forever.
#
# State lives in ~/aionetiface/servers.json.dealer_state as JSON:
#   {"next_check": <unix_ts>, "fail_count": <int>}
# Delete the sidecar to force an immediate retry.
ONE_MONTH_SEC = 2592000
MAX_BACKOFF_SEC = 6 * ONE_MONTH_SEC


def read_dealer_state(path):
    try:
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {"next_check": 0, "fail_count": 0}


def write_dealer_state(path, state):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(state, fp)
        os.replace(tmp, path)
    except OSError:
        log_exception()


def next_check_after_failure(now, fail_count):
    """1mo, 2mo, 4mo, ... capped at 6mo."""
    backoff = ONE_MONTH_SEC * (2 ** max(fail_count - 1, 0))
    backoff = min(backoff, MAX_BACKOFF_SEC)
    return int(now + backoff)

__all__ = ["update_server_list"]


async def update_server_list(nic, sys_clock=time):
    """Ensure ~/aionetiface/servers.json exists and is no more than a
    month stale, then load and return its contents.

    Flow:
      1. If ~/aionetiface/servers.json doesn't exist, seed it from the
         bundled aionetiface/servers.json shipped in the package and
         stamp a checksum onto it.
      2. Read the on-disk file.  If it has no `checksum` field, or
         its stored checksum doesn't match the rest of the content,
         the user has been hand-editing -- skip the refresh entirely
         and return the file as-is.
      3. Otherwise, if the file's mtime is older than 30 days, try
         to fetch a fresh copy from the dealer.  Bounded 4s total --
         a slow or unreachable dealer must NOT hang startup.  Fresh
         content gets a freshly-computed checksum stamped before
         write.
      4. Return (update_req, infra_buf, infra).

    To opt out of automatic updates: edit ~/aionetiface/servers.json
    in any way that breaks the checksum (the simplest is to delete
    the "checksum" field).  To opt back in: delete the file -- the
    next startup will re-seed it from the bundled copy.
    """
    copy_aionetiface_install_files_as_needed()
    install_root = get_aionetiface_install_root()
    servers_path = os.path.join(install_root, "servers.json")
    bundled_path = os.path.join(
        os.path.dirname(__file__), "servers.json",
    )
    dealer_state_path = servers_path + ".dealer_state"
    one_month_sec = ONE_MONTH_SEC
    update_req = False

    # Step 1: seed from the bundled package file if no on-disk copy
    # exists.  Always stamp a checksum on the seeded file so the
    # opt-out detection has a baseline.
    if not os.path.exists(servers_path):
        try:
            with open(bundled_path, "r", encoding="utf-8") as src:
                seed_infra = json.loads(src.read())
            stamp_checksum(seed_infra)
            seed_buf = json.dumps(
                seed_infra, indent=4, sort_keys=False, default=str,
            )
            tmp_path = servers_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as dst:
                dst.write(seed_buf)
            os.replace(tmp_path, servers_path)
            log("update_server_list: seeded servers.json from bundled "
                "package copy at {0}".format(bundled_path))
            update_req = True
        except (OSError, ValueError):
            log("update_server_list: could not seed from bundled "
                "{0}; servers.json missing.".format(bundled_path))
            log_exception()

    # Step 2: load disk, check checksum.  User-managed file (missing
    # or mismatched checksum) -> return immediately without touching
    # anything.
    infra_buf = None
    infra = None
    if os.path.exists(servers_path):
        try:
            with open(servers_path, "r", encoding="utf-8") as fp:
                infra_buf = fp.read()
            infra = json.loads(infra_buf)
        except (OSError, ValueError):
            log("update_server_list: on-disk servers.json unreadable.")
            log_exception()
            infra_buf = None
            infra = None

    if infra is not None:
        stored = infra.get("checksum")
        if stored is None:
            log("update_server_list: servers.json has no checksum; "
                "treating as user-managed and skipping refresh.")
            return update_req, infra_buf, infra
        if stored != compute_server_list_checksum(infra):
            log("update_server_list: servers.json checksum mismatch "
                "(user-edited); skipping refresh.")
            return update_req, infra_buf, infra

    # Step 3: refresh from the dealer if (a) disk file is older than
    # a month AND (b) we're past the backoff window for the dealer.
    # The backoff window grows with consecutive failures (1mo, 2mo,
    # 4mo, capped at 6mo) so a permanently-offline dealer doesn't
    # cost the 4s fetch timeout every startup-after-a-month forever.
    try:
        mtime = os.path.getmtime(servers_path)
    except OSError:
        mtime = 0
    now = sys_clock.time()
    state = read_dealer_state(dealer_state_path)
    mtime_stale = (now - mtime) >= one_month_sec
    backoff_passed = now >= state.get("next_check", 0)

    if mtime_stale and backoff_passed:
        async def fetch_fresh():
            addr = ("ovh1.p2pd.net", 8000)
            # Pick the first supported AF -- ovh1.p2pd.net resolves
            # to both v4 and v6, and we just need a route for the
            # curl client.  AFGroup-friendly.
            client = WebCurl(addr, nic.route(nic.supported()[0]))
            resp = await client.get("/servers")
            resp_buf = to_s(resp.out)
            resp_infra = json.loads(resp_buf)
            return resp_infra

        try:
            # Hard ceiling on total fetch time.  Even if the TCP
            # connect succeeds and the server then never replies,
            # we abandon after 4s and apply the backoff.
            resp_infra = await asyncio.wait_for(fetch_fresh(), timeout=4)
            # Validation gate: a dict with just {"timestamp": "..."}
            # used to pass this check, get a freshly-stamped checksum,
            # and overwrite the on-disk file with content that has no
            # servers in it.  Require at least one well-known section
            # to actually be present and shaped like a dict.  The
            # checksum mechanism can't catch this because the
            # checksum is computed over the corrupt payload before
            # write -- next startup sees a "valid" file with nothing
            # usable in it.
            required_sections = (
                "STUN(see_ip)", "STUN(test_nat)", "MQTT", "TURN", "NTP",
            )
            has_section = (
                isinstance(resp_infra, dict)
                and any(
                    isinstance(resp_infra.get(k), dict)
                    for k in required_sections
                )
            )
            if (isinstance(resp_infra, dict)
                    and "timestamp" in resp_infra
                    and has_section):
                stamp_checksum(resp_infra)
                fresh_buf = json.dumps(
                    resp_infra, indent=4, sort_keys=False, default=str,
                )
                tmp_path = servers_path + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as fp:
                    fp.write(fresh_buf)
                os.replace(tmp_path, servers_path)
                infra_buf = fresh_buf
                infra = resp_infra
                update_req = True
                # Success resets the backoff counter.
                write_dealer_state(dealer_state_path, {
                    "next_check": int(now + one_month_sec),
                    "fail_count": 0,
                })
            else:
                # Successful HTTP round-trip but body wasn't a usable
                # server list.  Treat as "checked, nothing changed" --
                # touch mtime + reset backoff so we wait a normal
                # month before re-checking.
                try:
                    os.utime(servers_path, None)
                except OSError:
                    pass
                write_dealer_state(dealer_state_path, {
                    "next_check": int(now + one_month_sec),
                    "fail_count": 0,
                })
        except (OSError, ConnectionError, ValueError,
                asyncio.TimeoutError, asyncio.CancelledError) as exc:
            fail_count = int(state.get("fail_count", 0)) + 1
            next_check = next_check_after_failure(now, fail_count)
            log("update_server_list: dealer fetch failed ({0}); "
                "fail_count={1}, retrying after {2}s.".format(
                    type(exc).__name__, fail_count,
                    next_check - int(now),
                ))
            log_exception()
            write_dealer_state(dealer_state_path, {
                "next_check": next_check,
                "fail_count": fail_count,
            })
            # Also touch mtime so the next startup's mtime gate
            # treats the file as "checked", preventing repeated
            # gate trips between now and next_check.
            if os.path.exists(servers_path):
                try:
                    os.utime(servers_path, None)
                except OSError:
                    pass

    return update_req, infra_buf, infra
