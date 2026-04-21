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
    pass

class InterfaceNotFound(Exception):
    pass

class InterfaceInvalidAF(Exception):
    pass

class ErrorNoReply(Exception):
    pass

class ErrorPipeOpen(Exception):
    pass

class ErrorFeatureDeprecated(Exception):
    pass

class ErrorCantLoadNATInfo(Exception):
    pass

class AlreadyClosedError(Exception):
    pass

class TunnelFailed(Exception):
    pass

class StartNodeNicknameFailed(Exception):
    pass

class BadProtoResp(Exception):
    pass