#!/usr/bin/env python3
"""
adcs_probe.py — Active Directory Certificate Services discovery & mapping (v3).

External-perspective asset mapper for AD CS / Microsoft PKI deployments.

Capabilities
------------
  * DNS pre-flight (A / CNAME / PTR) and sibling-host discovery on the parent
    domain (pki., ca., crl., ocsp., issuing., …).
  * Endpoint surface walk: certsrv, CES, CEP, NDES/SCEP, CertEnroll, /pki,
    /CertData, OCSP — over HTTP and (optionally) HTTPS.
  * Renewal-index sweep across CertEnroll / pki / CertData filename patterns.
  * Unauthenticated SCEP GetCACert / GetCACertChain retrieval and parsing.
  * NTLM Type-2 challenge harvesting → NetBIOS / DNS / forest / OS info.
  * Auto-parse of downloaded CRLs and certificates (issuer DN, AIA, CDP,
    SANs, SKI/AKI, validity, key info, MS Published-CRL-Locations LDAP URLs
    that leak the CA host name).
  * AIA chain walking — follow caIssuers URLs upward until self-signed root.
  * JSON / CSV output, on-disk download of all DER/PEM artefacts.

Examples
--------
    # Quick surface sweep
    python3 adcs_probe.py http://pki.example.com/

    # Full external mapping
    python3 adcs_probe.py http://pki.example.com/ --full

    # Targeted, with known names
    python3 adcs_probe.py http://pki.example.com/ \\
        --ca-name "Example-Issuing-CA" --server "PKI01" \\
        --enumerate-renewals 5 --ntlm-info --scep --walk-aia \\
        --download ./loot --json results.json

Dependencies
------------
    requests           (required)
    cryptography       (optional — enables artefact parsing & AIA walking)

For lawful, authorised testing only.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import socket
import struct
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    sys.stderr.write("[!] requests is required: pip install requests\n")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# --------------------------------------------------------------------------- #
# ANSI                                                                        #
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"

USE_COLOUR = True
def col(s: str, *codes: str) -> str:
    return ("".join(codes) + s + C.RESET) if USE_COLOUR else s


# --------------------------------------------------------------------------- #
# Data                                                                        #
# --------------------------------------------------------------------------- #
@dataclass
class Endpoint:
    category: str
    path: str
    description: str
    method: str = "GET"
    high_value: bool = False


@dataclass
class Result:
    category: str
    path: str
    description: str
    url: str
    status: Optional[int] = None
    server: str = ""
    auth: str = ""
    length: Optional[int] = None
    redirect: str = ""
    content_type: str = ""
    error: str = ""
    high_value: bool = False
    ntlm_info: dict = field(default_factory=dict)
    saved_to: str = ""
    parsed: dict = field(default_factory=dict)


def _is_placeholder(name: str) -> bool:
    return name.startswith("<") and name.endswith(">")


# --------------------------------------------------------------------------- #
# Artefact parsing — certificates                                             #
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(rb'(?:ldap|ldaps|https?)://[A-Za-z0-9._\-/?=&%:,+@()*~ ]+')


def _extract_urls_raw(data: bytes) -> list[str]:
    """Last-ditch URL extraction by regex over raw bytes."""
    found = []
    for m in _URL_RE.finditer(data):
        try:
            url = m.group(0).decode("ascii", errors="ignore").strip()
        except Exception:
            continue
        # Trim trailing junk
        url = url.rstrip(" \t\r\n.,;)")
        if url and url not in found:
            found.append(url)
    return found


def _server_names_from_ldap_urls(urls: list[str]) -> list[str]:
    """AD CS LDAP CRL URLs are of the form
       ldap:///CN=<CA>,CN=<SERVER>,CN=CDP,CN=Public Key Services,...
       The second CN is the CA host's NetBIOS name."""
    names = set()
    for u in urls:
        if not u.lower().startswith(("ldap://", "ldaps://")):
            continue
        # Look for CN=...,CN=...,CN=CDP / CN=AIA / CN=Enrollment Services
        m = re.search(
            r"CN=[^,]+,CN=([^,]+),CN=(?:CDP|AIA|Enrollment Services|KRA|Certificate Authorities)",
            u, re.IGNORECASE
        )
        if m:
            names.add(m.group(1))
    return sorted(names)


def parse_certificate(data: bytes) -> dict:
    info: dict = {}
    if not data:
        return info
    if not HAVE_CRYPTO:
        info["urls_raw"] = _extract_urls_raw(data)
        return info

    cert = None
    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try:
            cert = loader(data)
            break
        except Exception:
            continue
    if cert is None:
        info["urls_raw"] = _extract_urls_raw(data)
        return info

    try:
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"]  = cert.issuer.rfc4514_string()
        info["serial"]  = format(cert.serial_number, "x")
        info["not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat()
        info["not_after"]  = cert.not_valid_after_utc.isoformat()  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after.isoformat()
        info["sig_algo"] = cert.signature_algorithm_oid._name
        info["self_signed"] = (cert.subject == cert.issuer)
    except Exception:
        pass

    try:
        pub = cert.public_key()
        info["key_type"] = type(pub).__name__
        if hasattr(pub, "key_size"):
            info["key_size"] = pub.key_size
    except Exception:
        pass

    aia: list = []
    cdp: list = []
    sans: list = []
    is_ca = False
    try:
        for ext in cert.extensions:
            v = ext.value
            try:
                if isinstance(v, x509.AuthorityInformationAccess):
                    for ad in v:
                        kind = "ocsp" if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP else "ca_issuers"
                        if hasattr(ad.access_location, "value"):
                            aia.append({"type": kind, "url": ad.access_location.value})
                elif isinstance(v, x509.CRLDistributionPoints):
                    for dp in v:
                        if dp.full_name:
                            for n in dp.full_name:
                                if hasattr(n, "value"):
                                    cdp.append(n.value)
                elif isinstance(v, x509.SubjectAlternativeName):
                    for n in v:
                        sans.append(getattr(n, "value", str(n)))
                elif isinstance(v, x509.BasicConstraints):
                    is_ca = bool(v.ca)
            except Exception:
                continue
    except Exception:
        pass

    if aia:  info["aia"]  = aia
    if cdp:  info["cdp"]  = cdp
    if sans: info["sans"] = sans
    info["is_ca"] = is_ca

    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        info["ski"] = ski.value.digest.hex()
    except Exception:
        pass
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if aki.value.key_identifier:
            info["aki"] = aki.value.key_identifier.hex()
    except Exception:
        pass

    # Server names hinted in CDP / AIA / SAN
    all_urls = [a["url"] for a in aia if isinstance(a, dict)] + cdp
    leaks = _server_names_from_ldap_urls(all_urls)
    if leaks:
        info["probable_server_names"] = leaks
    return info


def parse_crl(data: bytes) -> dict:
    info: dict = {}
    if not data:
        return info
    if not HAVE_CRYPTO:
        urls = _extract_urls_raw(data)
        info["urls_raw"] = urls
        leaks = _server_names_from_ldap_urls(urls)
        if leaks:
            info["probable_server_names"] = leaks
        return info

    crl = None
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            crl = loader(data)
            break
        except Exception:
            continue
    if crl is None:
        urls = _extract_urls_raw(data)
        info["urls_raw"] = urls
        leaks = _server_names_from_ldap_urls(urls)
        if leaks:
            info["probable_server_names"] = leaks
        return info

    try:
        info["issuer"] = crl.issuer.rfc4514_string()
        info["this_update"] = (crl.last_update_utc if hasattr(crl, "last_update_utc") else crl.last_update).isoformat()
        nu = (crl.next_update_utc if hasattr(crl, "next_update_utc") else crl.next_update)
        info["next_update"] = nu.isoformat() if nu else None
        info["sig_algo"] = crl.signature_algorithm_oid._name
        info["revoked_count"] = sum(1 for _ in crl)
    except Exception:
        pass

    aia: list = []
    idp: list = []
    freshest: list = []
    published: list = []

    try:
        for ext in crl.extensions:
            try:
                v = ext.value
                if isinstance(v, x509.AuthorityInformationAccess):
                    for ad in v:
                        if hasattr(ad.access_location, "value"):
                            aia.append(ad.access_location.value)
                elif isinstance(v, x509.IssuingDistributionPoint):
                    if v.full_name:
                        for n in v.full_name:
                            if hasattr(n, "value"):
                                idp.append(n.value)
                elif isinstance(v, x509.FreshestCRL):
                    for dp in v:
                        if dp.full_name:
                            for n in dp.full_name:
                                if hasattr(n, "value"):
                                    freshest.append(n.value)
                elif ext.oid.dotted_string == "1.3.6.1.4.1.311.21.14":
                    # MS Published CRL Locations — not natively parsed
                    raw = bytes(v.value) if hasattr(v, "value") and isinstance(v.value, (bytes, bytearray)) else None
                    if raw is None:
                        try:
                            raw = ext.public_bytes()
                        except Exception:
                            raw = b""
                    published = _extract_urls_raw(raw)
            except Exception:
                continue
    except Exception:
        pass

    if aia:       info["aia"] = aia
    if idp:       info["idp"] = idp
    if freshest:  info["freshest_crl"] = freshest
    if published: info["published_locations"] = published

    leaks = _server_names_from_ldap_urls(aia + idp + freshest + published)
    if leaks:
        info["probable_server_names"] = leaks
    return info


def parse_artefact(path: str) -> dict:
    """Inspect a downloaded file and parse as cert or CRL based on extension/contents."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return {}
    low = path.lower()
    if low.endswith(".crl"):
        return parse_crl(data)
    if low.endswith((".crt", ".cer", ".pem")):
        return parse_certificate(data)
    if low.endswith((".p7b", ".p7c")):
        # PKCS#7 bundle
        if HAVE_CRYPTO:
            for loader in (pkcs7.load_der_pkcs7_certificates,
                           pkcs7.load_pem_pkcs7_certificates):
                try:
                    certs = loader(data)
                    return {"pkcs7_certs": [
                        parse_certificate(c.public_bytes(serialization.Encoding.DER))
                        for c in certs
                    ]}
                except Exception:
                    continue
        return {"urls_raw": _extract_urls_raw(data)}
    # Unknown — try cert then CRL
    info = parse_certificate(data)
    if not info.get("subject"):
        info = parse_crl(data)
    return info


# --------------------------------------------------------------------------- #
# Endpoint catalogues                                                         #
# --------------------------------------------------------------------------- #
def build_endpoints(ca_name: str, server: str) -> list[Endpoint]:
    ca = urllib.parse.quote(ca_name, safe="")
    srv = urllib.parse.quote(server, safe="")
    have_names = not (_is_placeholder(ca_name) or _is_placeholder(server))

    out = [
        # Web Enrollment
        Endpoint("WebEnroll", "/certsrv/",                                                     "Web Enrollment root",            high_value=True),
        Endpoint("WebEnroll", "/certsrv/Default.asp",                                          "Default landing"),
        Endpoint("WebEnroll", "/certsrv/certrqus.asp",                                         "Request menu"),
        Endpoint("WebEnroll", "/certsrv/certrqad.asp",                                         "Advanced cert request"),
        Endpoint("WebEnroll", "/certsrv/certrqxt.asp",                                         "Submit PKCS#10/CMC",             high_value=True),
        Endpoint("WebEnroll", "/certsrv/certrqbi.asp?type=0",                                  "Renewal request"),
        Endpoint("WebEnroll", "/certsrv/certrqma.asp",                                         "Request on behalf (EOBO)",       high_value=True),
        Endpoint("WebEnroll", "/certsrv/certfnsh.asp",                                         "Submit / finish",                high_value=True),
        Endpoint("WebEnroll", "/certsrv/certckpn.asp",                                         "Pending request status"),
        Endpoint("WebEnroll", "/certsrv/certcarc.asp",                                         "Download CA cert / CRL menu"),
        Endpoint("WebEnroll", "/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Mode=inst&Enc=bin", "CA cert via certnew (DER)",       high_value=True),
        Endpoint("WebEnroll", "/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Mode=inst&Enc=b64", "CA cert via certnew (Base64)"),
        Endpoint("WebEnroll", "/certsrv/certnew.p7b?ReqID=CACert&Renewal=0&Enc=bin",           "CA chain via certnew (PKCS#7)",  high_value=True),
        Endpoint("WebEnroll", "/certsrv/certcrl.crl",                                          "CRL via certsrv"),
    ]

    if have_names:
        out += [
            Endpoint("CES", f"/{ca}_CES_Kerberos/service.svc",                                 "CES Kerberos",                   high_value=True),
            Endpoint("CES", f"/{ca}_CES_Kerberos/service.svc/mex",                             "CES Kerberos MEX"),
            Endpoint("CES", f"/{ca}_CES_UsernamePassword/service.svc",                         "CES Username/Password",          high_value=True),
            Endpoint("CES", f"/{ca}_CES_UsernamePassword/service.svc/mex",                     "CES Username/Password MEX"),
            Endpoint("CES", f"/{ca}_CES_Certificate/service.svc",                              "CES Certificate"),
            Endpoint("CES", f"/{ca}_CES_Certificate/service.svc/mex",                          "CES Certificate MEX"),
        ]

    out += [
        Endpoint("CEP", "/ADPolicyProvider_CEP_Kerberos/service.svc",                          "CEP Kerberos"),
        Endpoint("CEP", "/ADPolicyProvider_CEP_Kerberos/service.svc/mex",                      "CEP Kerberos MEX"),
        Endpoint("CEP", "/ADPolicyProvider_CEP_UsernamePassword/service.svc",                  "CEP Username/Password"),
        Endpoint("CEP", "/ADPolicyProvider_CEP_UsernamePassword/service.svc/mex",              "CEP Username/Password MEX"),
        Endpoint("CEP", "/ADPolicyProvider_CEP_Certificate/service.svc",                       "CEP Certificate"),
        Endpoint("CEP", "/ADPolicyProvider_CEP_Certificate/service.svc/mex",                   "CEP Certificate MEX"),

        Endpoint("NDES", "/certsrv/mscep/",                                                    "NDES root"),
        Endpoint("NDES", "/certsrv/mscep/mscep.dll",                                           "SCEP handler"),
        Endpoint("NDES", "/certsrv/mscep/mscep.dll?operation=GetCACaps",                       "SCEP GetCACaps"),
        Endpoint("NDES", "/certsrv/mscep/mscep.dll?operation=GetCACert&message=CAIdentifier",  "SCEP GetCACert",                 high_value=True),
        Endpoint("NDES", "/certsrv/mscep/mscep.dll?operation=GetCACertChain&message=CAIdentifier","SCEP GetCACertChain",         high_value=True),
        Endpoint("NDES", "/certsrv/mscep/mscep.dll?operation=GetNextCACert",                   "SCEP GetNextCACert"),
        Endpoint("NDES", "/certsrv/mscep/pkiclient.exe",                                       "Legacy pkiclient alias"),
        Endpoint("NDES", "/certsrv/mscep_admin/",                                              "NDES admin (challenge pwd)",     high_value=True),

        Endpoint("CDP", "/CertEnroll/",                                                        "CertEnroll directory"),
    ]

    if have_names:
        out += [
            Endpoint("CDP", f"/CertEnroll/{ca}.crl",                                           "Base CRL (CertEnroll)",          high_value=True),
            Endpoint("CDP", f"/CertEnroll/{ca}%2B.crl",                                        "Delta CRL (CertEnroll)"),
            Endpoint("CDP", f"/pki/{ca}.crl",                                                  "Base CRL (/pki)",                high_value=True),
            Endpoint("CDP", f"/pki/{ca}%2B.crl",                                               "Delta CRL (/pki)"),
            Endpoint("CDP", f"/CertData/{ca}.crl",                                             "Base CRL (CertData)"),
            Endpoint("AIA", f"/CertEnroll/{srv}_{ca}.crt",                                     "Issuing CA cert (CertEnroll)",   high_value=True),
            Endpoint("AIA", f"/pki/{ca}.crt",                                                  "Issuing CA cert (/pki)",         high_value=True),
            Endpoint("AIA", f"/CertData/{ca}.crt",                                             "Issuing CA cert (CertData)"),
            Endpoint("CertEnroll", f"/CertEnroll/nsrev_{ca}.asp",                              "Legacy nsrev page"),
            Endpoint("CertEnroll", f"/CertEnroll/{srv}_{ca}-cross.crt",                        "Cross certificate"),
        ]

    out += [
        Endpoint("OCSP", "/ocsp",                                                              "OCSP responder",                 high_value=True),
        Endpoint("OCSP", "/ocsp/",                                                             "OCSP responder (slash)"),

        Endpoint("Misc", "/pki/",                                                              "PKI repository root"),
        Endpoint("Misc", "/pki/cps.html",                                                      "CPS (HTML)"),
        Endpoint("Misc", "/pki/cps.pdf",                                                       "CPS (PDF)"),
        Endpoint("Misc", "/pki/index.html",                                                    "Repository index"),
        Endpoint("Misc", "/CertEnroll/web.config",                                             "Exposed web.config (misconfig)"),
        Endpoint("Misc", "/certsrv/web.config",                                                "Exposed web.config (misconfig)"),
    ]

    return out


def build_renewal_endpoints(ca_name: str, server: str, max_n: int,
                             root_ca: Optional[str] = None) -> list[Endpoint]:
    ca = urllib.parse.quote(ca_name, safe="")
    srv = urllib.parse.quote(server, safe="")
    out: list[Endpoint] = []
    dirs = ["/CertEnroll", "/pki", "/CertData"]

    for d in dirs:
        out.append(Endpoint("Renewals", f"{d}/{srv}_{ca}.crt",      f"CA cert (current) [{d}]",  high_value=True))
        out.append(Endpoint("Renewals", f"{d}/{ca}.crl",            f"Base CRL (current) [{d}]", high_value=True))
        out.append(Endpoint("Renewals", f"{d}/{ca}%2B.crl",         f"Delta CRL (current) [{d}]"))
        for n in range(max_n + 1):
            out.append(Endpoint("Renewals", f"{d}/{srv}_{ca}({n}).crt",   f"CA cert renewal #{n} [{d}]"))
            out.append(Endpoint("Renewals", f"{d}/{ca}({n}).crl",         f"Base CRL #{n} [{d}]"))
            out.append(Endpoint("Renewals", f"{d}/{ca}({n})%2B.crl",      f"Delta CRL #{n} [{d}]"))

    if root_ca and not _is_placeholder(root_ca):
        rca = urllib.parse.quote(root_ca, safe="")
        for d in dirs:
            out.append(Endpoint("Renewals", f"{d}/{rca}.crt",       f"Root CA cert [{d}]",       high_value=True))
            out.append(Endpoint("Renewals", f"{d}/{rca}.crl",       f"Root CA CRL [{d}]",        high_value=True))
            for n in range(max_n + 1):
                out.append(Endpoint("Renewals", f"{d}/{rca}({n}).crt", f"Root CA cert #{n} [{d}]"))
                out.append(Endpoint("Renewals", f"{d}/{rca}({n}).crl", f"Root CA CRL #{n} [{d}]"))

    return out


# --------------------------------------------------------------------------- #
# NTLM Type-2 parsing                                                         #
# --------------------------------------------------------------------------- #
NTLM_TYPE1 = base64.b64decode(
    "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
)
_AV_PAIRS = {
    1: "NetBIOS_Computer", 2: "NetBIOS_Domain",
    3: "DNS_Computer",     4: "DNS_Domain",     5: "DNS_Forest",
}


def parse_ntlm_type2(data: bytes) -> dict:
    info: dict = {}
    if len(data) < 48 or not data.startswith(b"NTLMSSP\x00"):
        return info
    if struct.unpack("<I", data[8:12])[0] != 2:
        return info

    tn_len, _, tn_off = struct.unpack("<HHI", data[12:20])
    if tn_len and tn_off + tn_len <= len(data):
        try:
            info["TargetName"] = data[tn_off:tn_off + tn_len].decode("utf-16-le", errors="replace")
        except Exception:
            pass

    ti_len, _, ti_off = struct.unpack("<HHI", data[40:48])
    if ti_len and ti_off + ti_len <= len(data):
        ti = data[ti_off:ti_off + ti_len]
        i = 0
        while i + 4 <= len(ti):
            av_id, av_len = struct.unpack("<HH", ti[i:i + 4])
            if av_id == 0:
                break
            if av_id in _AV_PAIRS and i + 4 + av_len <= len(ti):
                try:
                    info[_AV_PAIRS[av_id]] = ti[i + 4:i + 4 + av_len].decode("utf-16-le", errors="replace")
                except Exception:
                    pass
            i += 4 + av_len

    if len(data) >= 56:
        try:
            major, minor = data[48], data[49]
            build = struct.unpack("<H", data[50:52])[0]
            if major:
                info["OS_Version"] = f"{major}.{minor}.{build}"
        except Exception:
            pass
    return info


def fetch_ntlm_info(session: requests.Session, url: str, timeout: int) -> dict:
    try:
        token = base64.b64encode(NTLM_TYPE1).decode("ascii")
        r = session.get(url, headers={"Authorization": f"NTLM {token}"},
                        timeout=timeout, allow_redirects=False, verify=False)
        wa = r.headers.get("WWW-Authenticate", "")
        for part in wa.split(","):
            part = part.strip()
            if part.upper().startswith("NTLM "):
                try:
                    return parse_ntlm_type2(base64.b64decode(part[5:].strip()))
                except Exception:
                    return {}
    except RequestException:
        pass
    return {}


# --------------------------------------------------------------------------- #
# Probe & download                                                            #
# --------------------------------------------------------------------------- #
def probe(session: requests.Session, base: str, ep: Endpoint, timeout: int) -> Result:
    url = base.rstrip("/") + ep.path
    res = Result(category=ep.category, path=ep.path, description=ep.description,
                 url=url, high_value=ep.high_value)
    try:
        r = session.request(ep.method, url, timeout=timeout,
                            allow_redirects=False, verify=False)
        res.status = r.status_code
        res.server = r.headers.get("Server", "")
        res.auth = r.headers.get("WWW-Authenticate", "")
        res.content_type = r.headers.get("Content-Type", "")
        try:
            res.length = int(r.headers.get("Content-Length", len(r.content) if r.content else 0))
        except ValueError:
            res.length = len(r.content) if r.content else 0
        if 300 <= r.status_code < 400:
            res.redirect = r.headers.get("Location", "")
    except RequestException as e:
        res.error = f"{type(e).__name__}: {str(e)[:140]}"
    return res


_DOWNLOADABLE_EXT = (".crl", ".crt", ".cer", ".pem", ".p7b", ".p7c", ".der")


def _looks_downloadable(result: Result) -> bool:
    if result.status != 200 or not result.length:
        return False
    p = result.path.split("?")[0].lower()
    if any(p.endswith(e) for e in _DOWNLOADABLE_EXT):
        return True
    ct = (result.content_type or "").lower()
    if any(t in ct for t in ("pkix-crl", "x-x509", "pkcs7", "pkix-cert", "octet-stream")):
        return True
    return False


def download_artefact(session: requests.Session, url: str, out_dir: str,
                      timeout: int) -> str:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True,
                        verify=False, stream=True)
        if r.status_code != 200 or not r.content:
            return ""
        name = urllib.parse.unquote(urllib.parse.urlparse(url).path).rstrip("/").split("/")[-1] or "index"
        safe = "".join(c if c.isalnum() or c in "._-+()" else "_" for c in name)
        # Heuristic extension fix-up based on content-type
        ct = r.headers.get("Content-Type", "").lower()
        if "." not in safe:
            if "crl" in ct: safe += ".crl"
            elif "pkcs7" in ct: safe += ".p7b"
            elif "x509" in ct or "cert" in ct: safe += ".crt"
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, safe)
        base, ext = os.path.splitext(path)
        i = 1
        while os.path.exists(path):
            path = f"{base}_{i}{ext}"
            i += 1
        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        return path
    except RequestException:
        return ""


# --------------------------------------------------------------------------- #
# SCEP                                                                        #
# --------------------------------------------------------------------------- #
def scep_get_ca(session: requests.Session, base: str, timeout: int,
                operation: str = "GetCACert") -> dict:
    url = base.rstrip("/") + f"/certsrv/mscep/mscep.dll?operation={operation}&message=CAIdentifier"
    out: dict = {"url": url, "operation": operation}
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        out["status"] = r.status_code
        out["content_type"] = r.headers.get("Content-Type", "")
        out["length"] = len(r.content)
        if r.status_code != 200 or not r.content:
            return out
        ct = out["content_type"].lower()
        certs: list = []
        if HAVE_CRYPTO:
            # Try PKCS#7 first (multi-cert response), fall back to single cert
            for loader in (pkcs7.load_der_pkcs7_certificates,
                           pkcs7.load_pem_pkcs7_certificates):
                try:
                    parsed = loader(r.content)
                    for c in parsed:
                        certs.append(parse_certificate(c.public_bytes(serialization.Encoding.DER)))
                    break
                except Exception:
                    continue
            if not certs:
                pc = parse_certificate(r.content)
                if pc:
                    certs.append(pc)
        else:
            out["urls_raw"] = _extract_urls_raw(r.content)
        if certs:
            out["certs"] = certs
        out["bytes"] = r.content  # keep so caller can save
    except RequestException as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:140]}"
    return out


# --------------------------------------------------------------------------- #
# DNS                                                                         #
# --------------------------------------------------------------------------- #
_PKI_PREFIXES = [
    "pki", "ca", "crl", "ocsp", "certs", "cert", "aia",
    "pki1", "pki2", "ca1", "ca2", "rootca", "issuingca", "subca",
    "intermediate", "policy", "enroll", "enrollment", "ndes", "scep",
    "pki-int", "pki-ext", "pki-crl", "pki-ocsp",
]


def dns_recon(hostname: str) -> dict:
    info: dict = {"host": hostname}
    try:
        ip = socket.gethostbyname(hostname)
        info["ip"] = ip
    except (socket.gaierror, socket.herror):
        return info
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        if ptr.lower() != hostname.lower():
            info["ptr"] = ptr
    except (socket.gaierror, socket.herror):
        pass
    # Capture all A records (CNAME chain end), aliases
    try:
        h, aliases, ips = socket.gethostbyname_ex(hostname)
        if h.lower() != hostname.lower():
            info["canonical"] = h
        if aliases:
            info["aliases"] = aliases
        if ips and len(ips) > 1:
            info["all_ips"] = ips
    except socket.gaierror:
        pass
    return info


def find_sibling_hosts(hostname: str) -> list[dict]:
    """Probe the parent domain for common PKI subdomain prefixes."""
    parts = hostname.split(".")
    if len(parts) < 2:
        return []
    # Walk every parent suffix, since some orgs put CAs at apex
    candidates: set[str] = set()
    for i in range(len(parts) - 1):
        domain = ".".join(parts[i + 1:])
        for p in _PKI_PREFIXES:
            cand = f"{p}.{domain}"
            if cand.lower() != hostname.lower():
                candidates.add(cand)
    found: list[dict] = []
    for cand in sorted(candidates):
        try:
            ip = socket.gethostbyname(cand)
            entry = {"host": cand, "ip": ip}
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if ptr.lower() != cand.lower():
                    entry["ptr"] = ptr
            except (socket.gaierror, socket.herror):
                pass
            found.append(entry)
        except (socket.gaierror, socket.herror):
            continue
    return found


# --------------------------------------------------------------------------- #
# AIA chain walker                                                            #
# --------------------------------------------------------------------------- #
def walk_aia_chain(session: requests.Session, start_path: str, out_dir: str,
                   timeout: int, max_depth: int = 6) -> list[dict]:
    if not HAVE_CRYPTO:
        return []
    chain: list[dict] = []
    visited: set[str] = set()
    try:
        with open(start_path, "rb") as f:
            data = f.read()
    except OSError:
        return chain
    current = parse_certificate(data)
    chain.append({"path": start_path, "parsed": current})

    for _ in range(max_depth):
        if current.get("self_signed"):
            break
        aia_urls = [a["url"] for a in current.get("aia", [])
                    if isinstance(a, dict) and a.get("type") == "ca_issuers"
                    and a.get("url", "").lower().startswith(("http://", "https://"))]
        if not aia_urls:
            break
        next_url = next((u for u in aia_urls if u not in visited), None)
        if not next_url:
            break
        visited.add(next_url)
        try:
            r = session.get(next_url, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code != 200 or not r.content:
                break
            saved = download_artefact(session, next_url, out_dir, timeout)
            current = parse_certificate(r.content)
            chain.append({"url": next_url, "path": saved, "parsed": current})
        except RequestException:
            break
    return chain


# --------------------------------------------------------------------------- #
# Output                                                                      #
# --------------------------------------------------------------------------- #
def colourise_status(status: Optional[int]) -> str:
    if status is None:        return col("ERR", C.RED, C.BOLD)
    if 200 <= status < 300:   return col(str(status), C.GREEN, C.BOLD)
    if 300 <= status < 400:   return col(str(status), C.CYAN)
    if status in (401, 407):  return col(str(status), C.YELLOW, C.BOLD)
    if status == 403:         return col(str(status), C.YELLOW)
    if 400 <= status < 500:   return col(str(status), C.MAGENTA)
    return col(str(status), C.RED)


def short_auth(auth: str) -> str:
    if not auth:
        return ""
    schemes: list[str] = []
    for part in auth.split(","):
        s = part.strip().split(" ", 1)[0]
        if s and s not in schemes:
            schemes.append(s)
    return ",".join(schemes)


_CAT_ORDER = ["WebEnroll", "CES", "CEP", "NDES", "CDP", "AIA",
              "OCSP", "CertEnroll", "Renewals", "Misc"]


def print_grouped(results: list[Result], only_found: bool) -> None:
    by_cat: dict[str, list[Result]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)
    for cat in _CAT_ORDER:
        if cat not in by_cat:
            continue
        rows = by_cat[cat]
        if only_found:
            rows = [r for r in rows if r.status is not None and r.status != 404]
        if not rows:
            continue
        print(col(f"\n── {cat} " + "─" * (76 - len(cat)), C.BOLD, C.BLUE))
        for r in rows:
            star = col("★ ", C.YELLOW, C.BOLD) if r.high_value else "  "
            status = colourise_status(r.status)
            length = f"{r.length:>7}" if r.length is not None else "      -"
            print(f" {star}{status}  {length}  {col(r.path, C.DIM)}")
            extra: list[str] = []
            if r.server: extra.append(f"server={r.server}")
            if r.content_type: extra.append(f"type={r.content_type.split(';')[0]}")
            a = short_auth(r.auth)
            if a: extra.append(f"auth={col(a, C.YELLOW)}")
            if r.redirect: extra.append(f"→ {col(r.redirect, C.CYAN)}")
            if r.saved_to: extra.append(col(f"saved→{r.saved_to}", C.GREEN))
            if r.error: extra.append(col(r.error, C.RED))
            if r.ntlm_info:
                bits = " ".join(f"{k}={col(v, C.GREEN, C.BOLD)}" for k, v in r.ntlm_info.items())
                extra.append(f"NTLM[{bits}]")
            if extra:
                print("        " + col("│ ", C.DIM) + "  ".join(extra))


def print_artefact_intel(results: list[Result]) -> None:
    parsed = [r for r in results if r.parsed]
    if not parsed:
        return
    print(col("\n── Artefact intelligence " + "─" * 56, C.BOLD, C.BLUE))
    for r in parsed:
        info = r.parsed
        if not info:
            continue
        print(f"  {col(r.saved_to or r.url, C.CYAN)}")
        for key in ("subject", "issuer", "self_signed", "is_ca",
                    "not_before", "not_after", "sig_algo",
                    "key_type", "key_size", "ski", "aki",
                    "this_update", "next_update", "revoked_count"):
            if key in info and info[key] not in (None, ""):
                print(f"      {key:<14} = {info[key]}")
        if info.get("sans"):
            print(f"      {'sans':<14} = {', '.join(map(str, info['sans']))}")
        if info.get("aia"):
            for a in info["aia"]:
                if isinstance(a, dict):
                    print(f"      {'aia':<14} = [{a.get('type','')}] {a.get('url','')}")
                else:
                    print(f"      {'aia':<14} = {a}")
        if info.get("cdp"):
            for u in info["cdp"]:
                print(f"      {'cdp':<14} = {u}")
        for key in ("idp", "freshest_crl", "published_locations"):
            if info.get(key):
                for u in info[key]:
                    print(f"      {key:<14} = {u}")
        if info.get("probable_server_names"):
            for n in info["probable_server_names"]:
                print(f"      {'server-leak':<14} = {col(n, C.GREEN, C.BOLD)}")
        if info.get("urls_raw"):
            for u in info["urls_raw"][:10]:
                print(f"      {'url':<14} = {u}")
        if info.get("pkcs7_certs"):
            print(f"      {'pkcs7_certs':<14} = {len(info['pkcs7_certs'])} cert(s):")
            for sub in info["pkcs7_certs"]:
                print(f"          - subject: {sub.get('subject','?')}")
                print(f"            issuer:  {sub.get('issuer','?')}")


def print_dns_findings(dns: dict, siblings: list[dict]) -> None:
    if not dns and not siblings:
        return
    print(col("\n── DNS reconnaissance " + "─" * 59, C.BOLD, C.BLUE))
    if dns:
        for k, v in dns.items():
            if isinstance(v, list):
                v = ", ".join(map(str, v))
            print(f"  {k:<14} = {v}")
    if siblings:
        print(col(f"\n  Sibling PKI hosts on parent domain ({len(siblings)} found):", C.BOLD))
        for s in siblings:
            extra = ""
            if "ptr" in s: extra = f"  ({col(s['ptr'], C.DIM)})"
            print(f"    {col(s['host'], C.GREEN, C.BOLD)} → {s['ip']}{extra}")


def print_scep_results(scep: list[dict]) -> None:
    if not scep:
        return
    print(col("\n── SCEP responses " + "─" * 63, C.BOLD, C.BLUE))
    for r in scep:
        print(f"  {col(r.get('operation','?'), C.BOLD)}  →  status={r.get('status','?')}  "
              f"type={r.get('content_type','')}  bytes={r.get('length',0)}")
        if r.get("error"):
            print(f"      {col(r['error'], C.RED)}")
        for c in r.get("certs", []) or []:
            print(f"      cert: {c.get('subject','?')}")
            print(f"            issuer: {c.get('issuer','?')}")
            if c.get("probable_server_names"):
                for n in c["probable_server_names"]:
                    print(f"            {col('server-leak', C.GREEN)} = {col(n, C.GREEN, C.BOLD)}")


def print_aia_chain(chain: list[dict]) -> None:
    if not chain:
        return
    print(col("\n── AIA chain walk " + "─" * 63, C.BOLD, C.BLUE))
    for i, link in enumerate(chain):
        info = link.get("parsed", {})
        url = link.get("url") or link.get("path", "")
        marker = "└─" if i == len(chain) - 1 else "├─"
        print(f"  {marker} [{i}] {col(info.get('subject','?'), C.BOLD)}")
        print(f"        issuer: {info.get('issuer','?')}")
        if url:
            print(f"        from:   {col(url, C.DIM)}")
        if info.get("self_signed"):
            print(f"        {col('(self-signed root)', C.GREEN)}")


def summarise(results: list[Result], dns: dict, siblings: list[dict],
              scep: list[dict], chain: list[dict]) -> None:
    total = len(results)
    by_status: dict[str, int] = {}
    interesting: list[Result] = []
    ntlm_hosts: dict[str, dict] = {}
    server_names: set[str] = set()

    for r in results:
        key = "ERR" if r.status is None else str(r.status)
        by_status[key] = by_status.get(key, 0) + 1
        if r.high_value and r.status is not None and r.status != 404:
            interesting.append(r)
        if r.ntlm_info:
            for k, v in r.ntlm_info.items():
                ntlm_hosts.setdefault(k, {}).setdefault(v, 0)
                ntlm_hosts[k][v] += 1
        if r.parsed.get("probable_server_names"):
            server_names.update(r.parsed["probable_server_names"])

    for s in scep:
        for c in s.get("certs", []) or []:
            for n in c.get("probable_server_names", []) or []:
                server_names.add(n)
    for link in chain:
        for n in link.get("parsed", {}).get("probable_server_names", []) or []:
            server_names.add(n)

    print(col("\n── Summary " + "─" * 70, C.BOLD, C.BLUE))
    print(f"  Endpoints probed   : {total}")
    bits = ", ".join(f"{colourise_status(int(k) if k.isdigit() else None)}={v}"
                     for k, v in sorted(by_status.items()))
    print(f"  Status breakdown   : {bits}")
    if siblings:
        print(f"  Sibling hosts      : {len(siblings)}")
    if scep:
        print(f"  SCEP responses     : {len([s for s in scep if s.get('certs')])}/{len(scep)} parsed")
    if chain:
        print(f"  AIA chain depth    : {len(chain)}")

    if interesting:
        print(col("\n  High-value endpoints with response:", C.YELLOW, C.BOLD))
        for r in interesting:
            a = short_auth(r.auth)
            extra = f"  [{a}]" if a else ""
            print(f"    {colourise_status(r.status)}  {r.path}{col(extra, C.YELLOW)}")

    if ntlm_hosts:
        print(col("\n  NTLM host info gathered:", C.GREEN, C.BOLD))
        for field_name, values in ntlm_hosts.items():
            for v, count in sorted(values.items(), key=lambda x: -x[1]):
                print(f"    {field_name:<18} = {col(v, C.GREEN, C.BOLD)}  "
                      f"{col(f'(seen {count}x)', C.DIM)}")

    if server_names:
        print(col("\n  Probable CA server names (from parsed artefacts):", C.GREEN, C.BOLD))
        for n in sorted(server_names):
            print(f"    {col(n, C.GREEN, C.BOLD)}")


def write_json(path: str, results: list[Result], dns: dict,
               siblings: list[dict], scep: list[dict], chain: list[dict]) -> None:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "dns": dns,
        "siblings": siblings,
        "scep": [{k: v for k, v in s.items() if k != "bytes"} for s in scep],
        "aia_chain": chain,
        "endpoints": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


def write_csv(path: str, results: list[Result]) -> None:
    fields = ["category", "path", "description", "url", "status", "server",
              "auth", "length", "content_type", "redirect", "error",
              "high_value", "saved_to", "ntlm_info", "parsed_summary"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = asdict(r)
            row["ntlm_info"] = json.dumps(row["ntlm_info"]) if row["ntlm_info"] else ""
            p = row.pop("parsed", {}) or {}
            row["parsed_summary"] = json.dumps({
                k: v for k, v in p.items()
                if k in ("subject", "issuer", "is_ca", "self_signed",
                         "probable_server_names", "sans")
            }) if p else ""
            w.writerow(row)


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(
        description="Map AD CS / Microsoft PKI assets from an external perspective.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("base_url", help="e.g. http://pki.example.com/")
    p.add_argument("--ca-name", default="<CA-NAME>",
                   help="Issuing CA common name. Placeholder = skip CA-named paths.")
    p.add_argument("--server",  default="<SERVER>",
                   help="CA host short name (used in AIA filename).")
    p.add_argument("--root-ca", default=None,
                   help="Root CA common name for additional renewal-sweep paths.")
    p.add_argument("--enumerate-renewals", type=int, default=0, metavar="N",
                   help="Sweep CertEnroll/pki/CertData for renewal indexes 0..N.")
    p.add_argument("--ntlm-info", action="store_true",
                   help="Decode NTLM Type-2 from 401-returning endpoints.")
    p.add_argument("--scep", action="store_true",
                   help="Run unauthenticated SCEP GetCACert / GetCACertChain.")
    p.add_argument("--dns-recon", action="store_true",
                   help="Resolve target, find aliases, PTR, and probe sibling hosts.")
    p.add_argument("--probe-https", action="store_true",
                   help="Re-probe high-value endpoints over HTTPS as well.")
    p.add_argument("--walk-aia", action="store_true",
                   help="Walk AIA caIssuers chain upward from any downloaded CA cert.")
    p.add_argument("--full", action="store_true",
                   help="Shortcut: enable renewals=5, ntlm-info, scep, dns-recon, "
                        "probe-https, walk-aia, and download to ./loot/.")
    p.add_argument("--download", metavar="DIR",
                   help="Save 200-OK CRL/cert responses (and parse them).")
    p.add_argument("--timeout", type=int, default=8, help="Per-request timeout (s)")
    p.add_argument("--threads", type=int, default=10, help="Concurrent workers")
    p.add_argument("--user-agent", default="adcs-probe/3.0", help="User-Agent header")
    p.add_argument("--proxy", help="HTTP/S proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--json", help="Write full results to JSON file")
    p.add_argument("--csv",  help="Write endpoint results to CSV file")
    p.add_argument("--only-found", action="store_true",
                   help="Hide endpoints that errored or returned 404.")
    p.add_argument("--no-colour", action="store_true", help="Disable ANSI colours")
    args = p.parse_args()

    if args.full:
        if args.enumerate_renewals == 0:
            args.enumerate_renewals = 5
        args.ntlm_info = True
        args.scep = True
        args.dns_recon = True
        args.probe_https = True
        args.walk_aia = True
        if not args.download:
            args.download = "./loot"

    global USE_COLOUR
    if args.no_colour or not sys.stdout.isatty():
        USE_COLOUR = False

    base = args.base_url
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    parsed_base = urllib.parse.urlparse(base)
    hostname = parsed_base.hostname or ""

    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent, "Accept": "*/*"})
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    # Banner ----------------------------------------------------------------
    print(col(f"[*] Target            : {base}", C.BOLD))
    print(col(f"[*] Hostname          : {hostname}", C.DIM))
    print(col(f"[*] CA name           : {args.ca_name}", C.DIM))
    print(col(f"[*] Server            : {args.server}", C.DIM))
    if args.root_ca:
        print(col(f"[*] Root CA           : {args.root_ca}", C.DIM))
    print(col(f"[*] cryptography lib  : {'available' if HAVE_CRYPTO else col('not installed (limited parsing)', C.YELLOW)}", C.DIM))
    print(col(f"[*] Renewal sweep     : {args.enumerate_renewals or 'off'}", C.DIM))
    print(col(f"[*] NTLM info pass    : {'on' if args.ntlm_info else 'off'}", C.DIM))
    print(col(f"[*] SCEP pull         : {'on' if args.scep else 'off'}", C.DIM))
    print(col(f"[*] DNS recon         : {'on' if args.dns_recon else 'off'}", C.DIM))
    print(col(f"[*] HTTPS pass        : {'on' if args.probe_https else 'off'}", C.DIM))
    print(col(f"[*] AIA chain walk    : {'on' if args.walk_aia else 'off'}", C.DIM))
    print(col(f"[*] Download          : {args.download or 'off'}", C.DIM))

    # Phase 0: DNS recon ---------------------------------------------------
    dns: dict = {}
    siblings: list[dict] = []
    if args.dns_recon and hostname:
        print(col("\n[*] DNS reconnaissance…", C.BOLD))
        dns = dns_recon(hostname)
        siblings = find_sibling_hosts(hostname)

    # Build endpoint list ---------------------------------------------------
    endpoints = build_endpoints(args.ca_name, args.server)
    placeholders = _is_placeholder(args.ca_name) or _is_placeholder(args.server)
    if args.enumerate_renewals > 0:
        if placeholders:
            print(col("[!] --enumerate-renewals requires real --ca-name and --server; skipping.",
                      C.YELLOW))
        else:
            endpoints += build_renewal_endpoints(
                args.ca_name, args.server, args.enumerate_renewals, args.root_ca
            )

    # Phase 1: probe HTTP --------------------------------------------------
    print(col(f"\n[*] Probing {len(endpoints)} endpoint(s) on {parsed_base.scheme}://…",
              C.BOLD))
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(probe, session, base, ep, args.timeout): ep for ep in endpoints}
        for fut in as_completed(futs):
            results.append(fut.result())

    # Phase 1b: HTTPS pass on high-value if requested ----------------------
    if args.probe_https:
        alt_scheme = "https" if parsed_base.scheme == "http" else "http"
        alt_base = base.replace(f"{parsed_base.scheme}://", f"{alt_scheme}://", 1)
        hv_endpoints = [e for e in endpoints if e.high_value]
        print(col(f"[*] {alt_scheme.upper()} pass on {len(hv_endpoints)} high-value endpoint(s)…",
                  C.BOLD))
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(probe, session, alt_base, ep, args.timeout): ep
                    for ep in hv_endpoints}
            for fut in as_completed(futs):
                r = fut.result()
                r.category = r.category + f"-{alt_scheme.upper()}"
                results.append(r)

    order = {(ep.category, ep.path): i for i, ep in enumerate(endpoints)}
    results.sort(key=lambda r: (r.category.endswith(("-HTTPS", "-HTTP")),
                                order.get((r.category.replace("-HTTPS", "").replace("-HTTP", ""),
                                           r.path), 1_000_000)))

    # Phase 2: NTLM info pass ----------------------------------------------
    if args.ntlm_info:
        targets = [r for r in results
                   if r.status in (401, 403) and "NTLM" in (r.auth or "").upper()]
        if not targets:
            targets = [r for r in results
                       if r.status == 401 and "NEGOTIATE" in (r.auth or "").upper()]
        if targets:
            print(col(f"\n[*] NTLM probe on {len(targets)} endpoint(s)…", C.BOLD))
            with ThreadPoolExecutor(max_workers=min(args.threads, 5)) as pool:
                futs = {pool.submit(fetch_ntlm_info, session, r.url, args.timeout): r
                        for r in targets}
                for fut in as_completed(futs):
                    info = fut.result()
                    if info:
                        futs[fut].ntlm_info = info
        else:
            print(col("\n[*] NTLM probe: no endpoints advertised NTLM/Negotiate.", C.DIM))

    # Phase 3: SCEP pull ---------------------------------------------------
    scep_results: list[dict] = []
    if args.scep:
        print(col("\n[*] SCEP pull (unauthenticated)…", C.BOLD))
        for op in ("GetCACert", "GetCACertChain"):
            scep_results.append(scep_get_ca(session, base, args.timeout, op))
        # Save SCEP bytes if download configured
        if args.download:
            os.makedirs(args.download, exist_ok=True)
            for s in scep_results:
                if "bytes" in s and s["bytes"]:
                    name = f"scep_{s['operation']}.bin"
                    pth = os.path.join(args.download, name)
                    base_p, ext = os.path.splitext(pth); i = 1
                    while os.path.exists(pth):
                        pth = f"{base_p}_{i}{ext}"; i += 1
                    with open(pth, "wb") as f:
                        f.write(s["bytes"])
                    s["saved_to"] = pth

    # Phase 4: download artefacts -----------------------------------------
    if args.download:
        downloadable = [r for r in results if _looks_downloadable(r)]
        if downloadable:
            print(col(f"\n[*] Downloading {len(downloadable)} artefact(s) → {args.download}",
                      C.BOLD))
            for r in downloadable:
                saved = download_artefact(session, r.url, args.download, args.timeout)
                if saved:
                    r.saved_to = saved
                    r.parsed = parse_artefact(saved)
        else:
            print(col("\n[*] Download pass: no downloadable 200 responses found.", C.DIM))

    # Phase 5: AIA chain walk ----------------------------------------------
    aia_chain: list[dict] = []
    if args.walk_aia and args.download and HAVE_CRYPTO:
        # Pick the most useful starting cert: an issuing CA cert, or any cert really
        starts = [r.saved_to for r in results
                  if r.saved_to and r.parsed.get("subject")
                  and r.parsed.get("is_ca")]
        if not starts and scep_results:
            for s in scep_results:
                if s.get("saved_to"):
                    starts.append(s["saved_to"])
        if starts:
            print(col(f"\n[*] Walking AIA chain from {starts[0]}…", C.BOLD))
            aia_chain = walk_aia_chain(session, starts[0], args.download, args.timeout)
        else:
            print(col("\n[*] AIA walk: no starting CA cert available.", C.DIM))

    # Output ---------------------------------------------------------------
    print_dns_findings(dns, siblings)
    print_grouped(results, args.only_found)
    print_artefact_intel(results)
    print_scep_results(scep_results)
    print_aia_chain(aia_chain)
    summarise(results, dns, siblings, scep_results, aia_chain)

    if args.json:
        write_json(args.json, results, dns, siblings, scep_results, aia_chain)
        print(col(f"\n[+] JSON written to {args.json}", C.GREEN))
    if args.csv:
        write_csv(args.csv, results)
        print(col(f"[+] CSV written to {args.csv}", C.GREEN))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Interrupted.\n")
        sys.exit(130)
