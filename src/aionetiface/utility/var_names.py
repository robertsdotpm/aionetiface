from ..nic.nat.nat_defs import (
    OPEN_INTERNET,
    SYMMETRIC_UDP_FIREWALL,
    FULL_CONE,
    RESTRICT_NAT,
    RESTRICT_PORT_NAT,
    SYMMETRIC_NAT,
    BLOCKED_NAT,
    NA_DELTA,
    EQUAL_DELTA,
    PRESERV_DELTA,
    INDEPENDENT_DELTA,
    DEPENDENT_DELTA,
    RANDOM_DELTA,
)

TXT = {
    "nat": {
        OPEN_INTERNET: "open internet (no NAT)",
        SYMMETRIC_UDP_FIREWALL: "possible firewall (no NAT)",
        FULL_CONE: "full cone",
        RESTRICT_NAT: "restrict reuse",
        RESTRICT_PORT_NAT: "restrict port",
        SYMMETRIC_NAT: "symetric",
        BLOCKED_NAT: "unknown (all responses blocked)",
    },
    "delta": {
        NA_DELTA: "not applicable",
        EQUAL_DELTA: "equal delta (local port == mapped port)",
        PRESERV_DELTA: "preserving delta ((local port + dist) == (mapped_start + dist))",
        INDEPENDENT_DELTA: "independent delta (rand port == (last_mapped += delta))",
        DEPENDENT_DELTA: "dependent delta ((local port += [1 to delta]) == (last_mapped += [1 to delta]))",
        RANDOM_DELTA: "random delta (local port == rand port)",
    },
}
