"""Custom exception types for aionetiface."""
# Defines all custon exceptions.

__all__ = [
    "NoGatewayForAF",
    "InterfaceNotFound",
    "InterfaceInvalidAF",
    "ErrorNoReply",
    "ErrorPipeOpen",
    "ErrorFeatureDeprecated",
    "ErrorCantLoadNATInfo",
    "AlreadyClosedError",
    "TunnelFailed",
    "StartNodeNicknameFailed",
    "BadProtoResp",
]


# There's no gateway defined for that address family.
class NoGatewayForAF(Exception):
    """Raised when no gateway is available for the requested address family."""
    pass


class InterfaceNotFound(Exception):
    """Raised when a named network interface cannot be located on the system."""
    pass


class InterfaceInvalidAF(Exception):
    """Raised when an interface does not support the requested address family."""
    pass


class ErrorNoReply(Exception):
    """Raised when a remote peer does not send a reply within the timeout."""
    pass


class ErrorPipeOpen(Exception):
    """Raised when a pipe cannot be opened or is already in a broken state."""
    pass


class ErrorFeatureDeprecated(Exception):
    """Raised when a caller invokes a feature that has been removed or superseded."""
    pass


class ErrorCantLoadNATInfo(Exception):
    """Raised when NAT type detection fails and no fallback result is available."""
    pass


class AlreadyClosedError(Exception):
    """Raised when an operation is attempted on a pipe or socket that is already closed."""
    pass


class TunnelFailed(Exception):
    """Raised when a tunnel cannot be established between two endpoints."""
    pass


class StartNodeNicknameFailed(Exception):
    """Raised when registering a nickname for a node fails."""
    pass


class BadProtoResp(Exception):
    """Raised when a protocol response does not conform to the expected format."""
    pass
