from checks.spf import SPFCheck
from checks.dkim import DKIMCheck
from checks.dmarc import DMARCCheck
from checks.caa import CAACheck
from checks.mx import MXCheck
from checks.ipv6 import IPv6Check
from checks.srv import SRVCheck
from checks.dnssec import DNSSECCheck
from checks.ns import NSCheck
from checks.ptr import PTRCheck
from checks.tlsa import TLSACheck

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
]

CHECK_MAP = {cls.name: cls for cls in ALL_CHECKS}


def get_check_by_name(name: str):
   return CHECK_MAP.get(name.lower())
