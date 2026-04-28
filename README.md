# ADCS-Mapper
Quick Vibe Coded Python Tool to enumerate resources of an Exposed ADCS instance.

External-perspective discovery and asset-mapping tool for Microsoft **Active Directory Certificate Services** (AD CS) and the wider Microsoft PKI surface.

`adcs-probe` walks the standard AD CS endpoint matrix on a target host, harvests host metadata from NTLM challenges, pulls CA certificates over unauthenticated SCEP, downloads and parses CRLs / certificates to extract issuer DNs, AIA / CDP pointers, SANs and key material, walks the AIA chain upward to the root, and discovers sibling PKI hosts on the parent domain. Designed for authorised security assessment, attack-surface mapping, and PKI inventory work.

> [!CAUTION]
> **Authorisation required.** This tool actively probes services on a remote host. Run it only against infrastructure you own, operate, or have explicit written permission to test. Unauthorised use against third-party systems may violate the Computer Misuse Act 1990 (UK), the Computer Fraud and Abuse Act (US), or equivalent legislation in your jurisdiction. The author accepts no liability for misuse.

---

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Output](#output)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Background reading](#background-reading)
- [Licence](#licence)

---

## Features

**Endpoint surface coverage** — every well-known AD CS web endpoint:

- Web Enrolment (`/certsrv/`) — every ASP page, `certnew.cer`, `certnew.p7b`
- Certificate Enrolment Web Service (CES) — Kerberos, Username/Password, Certificate auth bindings + MEX
- Certificate Enrolment Policy Web Service (CEP) — same three bindings + MEX
- Network Device Enrolment Service (NDES) — `mscep.dll` with every documented `operation=` parameter, plus the admin challenge page
- CRL Distribution Points across `/CertEnroll/`, `/pki/`, and `/CertData/`
- Authority Information Access — issuing-CA cert publication paths
- OCSP responder
- Common ancillary paths (CPS documents, repository indexes, exposed `web.config`)

**Renewal-index sweep** — generates and probes `<SERVER>_<CA-NAME>(N).crt`, `<CA-NAME>(N).crl`, and delta-CRL variants across every renewal generation 0..N and across all three publication directories.

**NTLM Type-2 host info extraction** — sends a standard NTLMSSP Type-1 negotiate to any endpoint advertising `NTLM` or `Negotiate`, decodes the Type-2 challenge, and pulls out:

- NetBIOS computer name (your `--server` value)
- NetBIOS domain
- DNS computer / domain / forest names
- OS version (when the version flag is set)

Same technique as `nmap --script http-ntlm-info`, integrated and aggregated across every endpoint that responds.

**Unauthenticated SCEP retrieval** — fires `GetCACert` and `GetCACertChain` against `/certsrv/mscep/mscep.dll`. SCEP is designed for non-domain devices that don't yet have credentials, so it almost never requires authentication. Returns single-cert DER or PKCS#7 bundles, both parsed automatically.

**Artefact parsing** — every downloaded CRL or certificate is inspected:

- *Certificates*: subject, issuer, serial, validity, signature algorithm, key type & size, SKI, AKI, SANs, AIA URLs (`caIssuers` and `OCSP`), CDP URLs, BasicConstraints CA flag, self-signed detection
- *CRLs*: issuer DN, `thisUpdate` / `nextUpdate`, signature algorithm, revoked-entry count, AIA, IDP (Issuing Distribution Point), Freshest CRL pointer, and the Microsoft **Published CRL Locations** extension (`1.3.6.1.4.1.311.21.14`)
- *PKCS#7 bundles*: each embedded certificate parsed individually

**Server-name leak detection** — AD CS LDAP CRL URLs follow the canonical form
`ldap:///CN=<CA>,CN=<SERVER>,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`
The second `CN=` is the CA host's NetBIOS name. The tool extracts and aggregates these across every parsed artefact, deduplicates them, and surfaces them in the summary.

**AIA chain walking** — given any downloaded CA cert, follows its AIA `caIssuers` URLs upward, downloading and parsing each issuer in turn, until reaching a self-signed root. Builds a complete picture of the certificate hierarchy.

**DNS reconnaissance** — A / CNAME / PTR resolution of the target plus probing of the parent domain (and every parent suffix) for ~25 common PKI subdomain prefixes (`pki.`, `ca.`, `crl.`, `ocsp.`, `issuingca.`, `rootca.`, `ndes.`, `scep.`, etc.) to discover sibling hosts in the same PKI estate.

**HTTPS coverage** — `--probe-https` re-runs high-value endpoints on the alternate scheme. Many CES/CEP/`/certsrv/` deployments are HTTPS-only.

**Output formats**:

- Coloured grouped table to terminal, with high-value endpoints starred and per-row metadata (server header, content type, auth scheme, redirects, NTLM info, parsed artefact summary)
- JSON document containing the full result tree (endpoints, DNS, siblings, SCEP, AIA chain, parsed artefacts)
- CSV of endpoint probe results
- Optional disk download of every successful CRL/cert response, sanitised filenames, auto-extension fix-up by content type

---

## Installation

**Requirements:**

- Python 3.9+
- `requests` (required)
- `cryptography` (optional but strongly recommended — enables artefact parsing and AIA walking)

```bash
# Clone
git clone https://github.com/<your-username>/adcs-probe.git
cd adcs-probe

# Install dependencies
pip install requests cryptography

# Or minimal install (loses cert/CRL parsing)
pip install requests

# Optional: make executable
chmod +x adcs_probe.py
```

No system dependencies, no compilation, runs anywhere Python runs.

---

## Quick start

```bash
# Basic surface sweep — no prior knowledge required
python3 adcs_probe.py http://pki.example.com/

# Full external mapping in one shot
python3 adcs_probe.py http://pki.example.com/ --full

# Targeted run with known CA + server names (after first pass identifies them)
python3 adcs_probe.py http://pki.example.com/ \
    --ca-name "Example-Issuing-CA" --server "PKI01" \
    --root-ca "Example-Root-CA" \
    --full --json results.json
```

`--full` enables: renewal sweep depth 5, NTLM info, SCEP pull, DNS recon, HTTPS pass, AIA chain walk, and downloads everything to `./loot/`.

---

## Usage

```
usage: adcs_probe.py [-h] [--ca-name CA_NAME] [--server SERVER]
                     [--root-ca ROOT_CA] [--enumerate-renewals N]
                     [--ntlm-info] [--scep] [--dns-recon] [--probe-https]
                     [--walk-aia] [--full] [--download DIR]
                     [--timeout TIMEOUT] [--threads THREADS]
                     [--user-agent USER_AGENT] [--proxy PROXY]
                     [--json JSON] [--csv CSV]
                     [--only-found] [--no-colour]
                     base_url
```

### Required

| Argument | Description |
|---|---|
| `base_url` | Target base URL, e.g. `http://pki.example.com/`. Scheme defaults to `http://` if omitted. |

### Discovery flags

| Flag | Description |
|---|---|
| `--ca-name <NAME>` | Issuing CA common name. Required for CES, CDP, and AIA path generation. If left as the default placeholder, those path families are skipped to avoid generating noise against `<CA-NAME>` literals. |
| `--server <NAME>` | CA host short name. Used in the canonical AIA filename `<SERVER>_<CA-NAME>.crt`. |
| `--root-ca <NAME>` | Root CA common name; adds root cert/CRL paths to the renewal sweep. |
| `--enumerate-renewals N` | Sweep `(0)` through `(N)` for every CA cert / base CRL / delta CRL across `/CertEnroll/`, `/pki/`, and `/CertData/`. Recommended depth: 5. |
| `--ntlm-info` | After the main scan, send NTLM Type-1 to every endpoint that returned 401 with `NTLM` or `Negotiate`, decode the Type-2 challenge for host info. |
| `--scep` | Run unauthenticated SCEP `GetCACert` and `GetCACertChain` against `/certsrv/mscep/mscep.dll`. |
| `--dns-recon` | Resolve the target, find aliases / PTR / all A records, and probe the parent domain for sibling PKI hosts. |
| `--probe-https` | Re-probe high-value endpoints over the alternate scheme (HTTP↔HTTPS). |
| `--walk-aia` | Once a CA cert is downloaded, follow its AIA `caIssuers` URLs upward to the root. Requires `--download` and the `cryptography` library. |
| `--full` | Shortcut for `--enumerate-renewals 5 --ntlm-info --scep --dns-recon --probe-https --walk-aia --download ./loot`. |

### Output flags

| Flag | Description |
|---|---|
| `--download <DIR>` | Save every 200-OK CRL/cert response to disk and parse it. Filenames are sanitised; duplicates get `_1`, `_2` suffixes. |
| `--json <FILE>` | Write the full result tree (endpoints, DNS, SCEP, AIA chain, parsed artefacts) to a JSON file. |
| `--csv <FILE>` | Write endpoint results to a CSV file. |
| `--only-found` | Hide endpoints that errored or returned 404. |
| `--no-colour` | Disable ANSI colours. (Auto-disabled when stdout isn't a TTY.) |

### Networking flags

| Flag | Default | Description |
|---|---|---|
| `--timeout <S>` | 8 | Per-request timeout in seconds. |
| `--threads <N>` | 10 | Concurrent worker threads for the main probe phase. |
| `--user-agent <UA>` | `adcs-probe/3.0` | Override the User-Agent header. |
| `--proxy <URL>` | — | HTTP/S proxy, e.g. `http://127.0.0.1:8080` for routing through Burp Suite. |

---

## Output

### Terminal

Endpoints are grouped by category (WebEnroll, CES, CEP, NDES, CDP, AIA, OCSP, Renewals, Misc). Each line shows status code, content length, and path; sub-lines show server header, auth scheme, redirect target, NTLM-extracted info, and parsed-artefact summary. High-value endpoints are starred (`★`).

Example excerpt:

```
── WebEnroll ───────────────────────────────────────────────────────────────────
 ★ 401     1452  /certsrv/
        │ server=Microsoft-IIS/10.0  auth=Negotiate,NTLM
        │ NTLM[NetBIOS_Computer=PKI01 NetBIOS_Domain=CORP DNS_Computer=pki01.corp.example.com ...]
   200    8742  /certsrv/certnew.cer?ReqID=CACert&Renewal=0&Mode=inst&Enc=bin
        │ type=application/pkix-cert  saved→./loot/certnew.cer

── CDP ─────────────────────────────────────────────────────────────────────────
 ★ 200    1284  /CertEnroll/Example-Issuing-CA.crl
        │ type=application/pkix-crl  saved→./loot/Example-Issuing-CA.crl

── Artefact intelligence ────────────────────────────────────────────────────
  ./loot/Example-Issuing-CA.crl
      issuer         = CN=Example-Issuing-CA,DC=corp,DC=example,DC=com
      this_update    = 2026-04-20T10:14:00+00:00
      next_update    = 2026-04-27T10:34:00+00:00
      sig_algo       = sha256WithRSAEncryption
      revoked_count  = 47
      idp            = ldap:///CN=Example-Issuing-CA,CN=PKI01,CN=CDP,...
      published_locations = http://pki.example.com/CertEnroll/Example-Issuing-CA.crl
      server-leak    = PKI01
```

### JSON

The `--json` output contains:

```jsonc
{
  "generated_at": "2026-04-28T12:00:00Z",
  "dns": { "host": "pki.example.com", "ip": "203.0.113.10", "ptr": "lb-01.example.com" },
  "siblings": [
    { "host": "ocsp.example.com", "ip": "203.0.113.11" }
  ],
  "scep": [
    { "operation": "GetCACert", "status": 200, "certs": [ {...} ] }
  ],
  "aia_chain": [
    { "path": "...", "parsed": { "subject": "...", "issuer": "...", ... } }
  ],
  "endpoints": [ /* every probed endpoint with status, headers, parsed CRL/cert info */ ]
}
```

---

## How it works

`adcs-probe` runs as an ordered set of phases:

**Phase 0 — DNS reconnaissance** *(optional, `--dns-recon`)*. Resolves the target, captures CNAME chain, all A records, and PTR. Walks every parent suffix of the hostname, probing common PKI prefixes. Any host that resolves is reported with its IP and PTR.

**Phase 1 — Endpoint probe** *(always)*. The main pass. Builds a catalogue of endpoints from the surface-level templates plus `--enumerate-renewals` if specified, then probes them concurrently via a thread pool. Redirects are not followed — we want to see the 302s themselves. Captures status, server banner, content type, content length, `WWW-Authenticate` header, and `Location` for redirects.

**Phase 1b — HTTPS pass** *(optional, `--probe-https`)*. Re-probes high-value endpoints on the alternate scheme.

**Phase 2 — NTLM info pass** *(optional, `--ntlm-info`)*. Picks every endpoint that returned 401 with `NTLM` or `Negotiate` in `WWW-Authenticate`, sends a standard NTLMSSP Type-1 negotiate, base64-decodes the Type-2 challenge from the response header, and walks the AV_PAIR target-info structure to extract host metadata.

**Phase 3 — SCEP pull** *(optional, `--scep`)*. Fetches `GetCACert` and `GetCACertChain` over HTTP. Single-cert responses are parsed as DER X.509; multi-cert responses are unwrapped from PKCS#7. Every certificate is parsed for subject, issuer, validity, AIA, CDP, etc.

**Phase 4 — Download** *(optional, `--download`)*. Every endpoint that returned 200 with a `.crl`/`.crt`/`.cer`/`.pem`/`.p7b`/`.p7c` extension or a CRL/cert content type is downloaded to the specified directory. Filenames are derived from the URL path with non-alphanumeric characters sanitised; duplicates are suffixed. Each downloaded file is automatically parsed.

**Phase 5 — AIA chain walk** *(optional, `--walk-aia`)*. Picks the first downloaded CA-flagged certificate, follows its AIA `caIssuers` URL to fetch the issuer, parses that, and repeats. Stops at a self-signed root, when no AIA URL is present, when an AIA URL has been visited before, or after `max_depth` (default 6) iterations.

The endpoint catalogue is built by `build_endpoints()` and `build_renewal_endpoints()`. The latter generates the `<SERVER>_<CA>(N).crt` / `<CA>(N).crl` / `<CA>(N)+.crl` filename matrix across `/CertEnroll/`, `/pki/`, and `/CertData/` for renewal generations `0..N`, with `+` URL-encoded as `%2B` for delta CRLs.

---

## Troubleshooting

**"Everything returns 404 with the same content length."**
The target is sitting behind a reverse proxy or WAF returning a canned response for unknown paths. The 200-/403-/500-responses with *different* content lengths are the ones reaching a real backend. Look at those, and use `--ntlm-info` against any 401 to confirm what's behind the front door.

**"CES / CDP / AIA paths are skipped."**
You haven't supplied `--ca-name` and `--server`. Without them, those path families would generate requests against the literal `<CA-NAME>` / `<SERVER>` placeholders, which is just noise. Run a basic sweep first to identify a CA cert or CRL endpoint, parse it, then re-run with the discovered names.

**"`cryptography` not installed."**
The script still runs. CRLs and certs that get downloaded are searched with a regex over raw bytes for `ldap://` / `http://` URLs — so you still get the LDAP server-name leak, just not structured cert metadata. Install with `pip install cryptography` for the full feature set.

**"No NTLM endpoints found."**
The endpoint front-end probably terminates auth at the proxy layer. Try `--probe-https` — many AD CS deployments require HTTPS for any auth-bearing endpoint.

**"AIA chain walk returned nothing."**
Either no CA cert was successfully downloaded, the cryptography library isn't installed, or every AIA URL pointed at LDAP (some hardened deployments only publish via LDAP, no HTTP). Pull the CA cert manually via SCEP `GetCACert` if `/certsrv/` and `/CertEnroll/` are unreachable.

**"Short content length on a known cert URL."**
Some IIS configurations 302-redirect to login when you `HEAD` an unauthenticated path; add `--probe-https` and look for the redirect target in the row's metadata. The script doesn't follow redirects automatically because the redirect target is itself useful intel.

---

## Background reading

- Microsoft, *AD CS HTTP/HTTPS-based protocols* — [MS-WCCE], [MS-XCEP], [MS-WSTEP] — the protocol references for CES, CEP, and the wire formats.
- RFC 5280 — *Internet X.509 PKI Certificate and CRL Profile* (the CRL/AIA/CDP extension definitions).
- RFC 8894 — *Simple Certificate Enrolment Protocol* (SCEP, formalised).
- Schroeder & Christensen, *Certified Pre-Owned: Abusing Active Directory Certificate Services* (SpecterOps, 2021) — the canonical writeup of AD CS attack paths (ESC1–ESC8). Useful context for understanding which endpoints carry the highest assessment value.
- Microsoft Open Specifications: `[MS-NLMP]` — NTLMSSP wire format reference, including the AV_PAIR structure used by the NTLM info extractor.

---

## Contributing

Issues and pull requests welcome. Useful additions to consider:

- LDAP-based discovery from the AD configuration container (`CN=Public Key Services,CN=Services,CN=Configuration`) for authenticated runs
- CA template enumeration (post-auth, via WSTEP / `IX509CertificateRequestPkcs10` introspection)
- OCSP request generation / response parsing
- Detection of common ESC-class misconfigurations from collected data

Keep contributions in plain Python with no new mandatory dependencies. The `cryptography` library remains the only optional dep.

---

## Licence

MIT. See `LICENSE`.

---

## Disclaimer

This software is provided for educational and authorised security-assessment purposes only. The authors and contributors accept no responsibility for misuse. By using this tool you confirm that you have authorisation to probe the target systems.
