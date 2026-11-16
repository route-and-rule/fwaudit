import ipaddress
from dataclasses import dataclass

ANY_NET = ipaddress.ip_network("0.0.0.0/0")
ANY_PORT = (0,65535)

@dataclass
class Rule:
    line: int
    chain: str
    action: str
    proto: str = "any"
    src: ipaddress.IPv4Network = ANY_NET
    dst: ipaddress.IPv4Network = ANY_NET
    dport: tuple = ANY_PORT
    in_if: str = None
    out_if: str = None
    state: str = None



