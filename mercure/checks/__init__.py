from .spf import SPFCheck
from .dkim import DKIMCheck
from .dmarc import DMARCCheck
from .caa import CAACheck
from .mx import MXCheck
from .ipv6 import IPv6Check
from .srv import SRVCheck
from .dnssec import DNSSECCheck
from .ns import NSCheck
from .ptr import PTRCheck
from .tlsa import TLSACheck
from .ghost import GhostSenderCheck

ALL_CHECKS = [
   SPFCheck,
   DKIMCheck,
   DMARCCheck,
   CAACheck,
   MXCheck,
   IPv6Check,
   SRVCheck,
   DNSSECCheck,
   NSCheck,
   PTRCheck,
   TLSACheck,
   GhostSenderCheck,
]

CHECK_MAP = {cls.name: cls for cls in ALL_CHECKS}


def get_check_by_name(name: str):
   return CHECK_MAP.get(name.lower())
