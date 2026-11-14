from typing import List, Dict

import httpx

from . import logger

_TIMEOUT = 15.0


def crtsh_subdomains(domain: str) -> List[str]:
   url = f"https://crt.sh/?q=%25.{domain}&output=json"
   try:
      with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
         resp = client.get(url)
         if resp.status_code != 200:
            logger.debug(f"crt.sh returned {resp.status_code}")
            return []
         data = resp.json()
         names = set()
         d_lower = domain.lower()
         for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
               name = name.strip().lower().lstrip("*.")
               if name and (name == d_lower or name.endswith(f".{d_lower}")):
                  names.add(name)
         return sorted(names)
   except Exception as exc:
      logger.debug(f"crt.sh query {domain}: {exc}")
      return []


def shodan_internetdb(ip: str) -> Dict:
   url = f"https://internetdb.shodan.io/{ip}"
   try:
      with httpx.Client(timeout=_TIMEOUT) as client:
         resp = client.get(url)
         if resp.status_code == 200:
            return resp.json()
         return {}
   except Exception as exc:
      logger.debug(f"shodan internetdb {ip}: {exc}")
      return {}


def rdap_lookup(domain: str) -> Dict:
   tld = domain.rsplit(".", 1)[-1].lower()
   rdap_servers = {
      "com": "https://rdap.verisign.com/com/v1",
      "net": "https://rdap.verisign.com/net/v1",
      "org": "https://rdap.org/org/v1",
      "io": "https://rdap.nic.io/v1",
      "dev": "https://rdap.nic.google/v1",
      "app": "https://rdap.nic.google/v1",
   }
   base = rdap_servers.get(tld)
   if not base:
      try:
         with httpx.Client(timeout=_TIMEOUT) as client:
            bootstrap = client.get("https://data.iana.org/rdap/dns.json")
            if bootstrap.status_code == 200:
               for entry in bootstrap.json().get("services", []):
                  tlds, urls = entry
                  if tld in tlds and urls:
                     base = urls[0].rstrip("/")
                     break
      except Exception:
         pass
   if not base:
      return {}
   url = f"{base}/domain/{domain}"
   try:
      with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
         resp = client.get(url)
         if resp.status_code == 200:
            return resp.json()
         return {}
   except Exception as exc:
      logger.debug(f"rdap lookup {domain}: {exc}")
      return {}
