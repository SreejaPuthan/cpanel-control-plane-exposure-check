# cPanel Control Plane Exposure Check

Lightweight security validation utility for identifying internet-exposed cPanel, WHM, and webmail administrative interfaces across external attack surfaces.

The utility performs service validation, exposure classification, HTTP response analysis, and basic security context identification to assist with authorized attack surface assessments and hardening verification.

---

## Features

- Detects exposed cPanel administrative interfaces
- Identifies publicly accessible WHM portals
- Checks common cPanel/Webmail management ports
- Supports HTTP and HTTPS validation
- Performs response classification
- Detects non-cPanel/WAF responses
- Provides structured tabular output
- Includes basic remediation guidance

---

## Supported Ports

| Service | Ports |
|----------|------|
| cPanel | 2082, 2083 |
| WHM | 2086, 2087 |
| Webmail | 2095, 2096 |

---

## Installation

```bash
git clone https://github.com/SreejaPuthan/cpanel-control-plane-exposure-check.git
cd cpanel-control-plane-exposure-check
pip install -r requirements.txt
```

---

## Usage

```bash
python scanner.py -f targets.txt
```

---

## Example Output

```text
HOST            PORT    SERVICE                  STATUS                        HTTP_CODE   SECURITY_NOTE
example.com     2082    cPanel_HTTP             NON_CPANEL_RESPONSE           403         Cloudflare/WAF present
example.com     2096    Webmail_HTTPS           CPANEL_INTERFACE_EXPOSED      200         Administrative interface exposed
example.com     2083    cPanel_HTTPS            CPANEL_INTERFACE_EXPOSED      200         Validate patch status for CVE-2026-41940
```

---

## Use Cases

- External attack surface validation
- Internet-facing management plane exposure checks
- Security hardening verification
- Exposure assessment during authorized engagements
- Patch validation support for cPanel-related vulnerabilities

---

## Disclaimer

This utility is intended strictly for authorized security assessments and defensive security validation activities.

---

## License

MIT License
