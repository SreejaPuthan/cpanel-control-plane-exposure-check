# CVE-2026-41940 – cPanel Control Plane Exposure Assessment

## Overview

**CVE-2026-41940** is a critical authentication bypass vulnerability affecting
**cPanel, WHM, and WP Squared**, caused by improper session handling in the
`cpsrvd` service prior to authentication.

Successful exploitation requires the affected management service to be
**externally reachable**. As a result, identifying exposed cPanel/WHM/Webmail
interfaces is a critical first step in reducing operational risk.

This repository provides a **defensive, non-intrusive method** to help identify
publicly accessible cPanel control plane services across external-facing
domains, URLs, IPs, and web applications.

> ⚠️ This project does **not** exploit vulnerabilities and does **not** attempt
> authentication bypass or compromise validation.

---

## Purpose of This Repository

This tool is intended to support:

- External attack surface discovery
- Identification of exposed cPanel / WHM / Webmail services
- Risk assessment activities related to CVE-2026-41940
- Patch prioritization and access hardening decisions
- Infrastructure hygiene in shared or cloud-hosted Linux environments

The script represents **one practical method** to determine whether
external-facing assets *may be vulnerable* based on service exposure.

---

## Repository Contents
.
├── cpanel_exposure_check.py   # Exposure detection script
├── targets.txt                # Sample input file (user-managed locally)
└── README.md                  # Documentation

---

## How the Script Works

The script performs safe HTTP(S) checks against common cPanel-related ports:

- **cPanel**: 2082 / 2083  
- **WHM**: 2086 / 2087  
- **Webmail**: 2095 / 2096  

It identifies:
- Reachable management interfaces
- `cpsrvd` service indicators
- Insecure HTTP management exposure
- Redirected or access-controlled endpoints
- Presence of WAF or reverse proxy protection (for visibility only)

No exploitation logic or authentication flaws are exercised.

---

## Input File: targets.txt

`targets.txt` defines the list of systems to be assessed.

- The file included in this repository contains **placeholder example values only**
- Users are expected to **update `targets.txt` locally** before running the script
- Each line should contain **exactly one domain, hostname, or IP address**

### Example format


example.com
subdomain.example.com
203.0.113.10

⚠️ **Do not commit real production or customer targets to GitHub.**  
This file is intentionally designed to be customized per user and per environment.

---

## Usage

1. Update `targets.txt` locally with authorized targets
2. Run the script:


python3 cpanel_exposure_check.py

3. Review the output to identify exposed cPanel / WHM / Webmail interfaces

---

## Interpreting Results

- **CPANEL_EXPOSED**  
  Indicates that a management interface is externally reachable and requires
  patch verification and access control review.

- **Insecure HTTP management port**  
  Indicates a high-risk configuration that should be remediated immediately.

- **Blocked / redirected / WAF-protected**  
  Indicates exposure with access filtering. WAF presence does not guarantee safety.

---

## Important Clarification

This tool **does not confirm vulnerability status**.

Determining whether a system is affected by CVE-2026-41940 requires:

- Version and patch validation
- Confirmation that `cpsrvd` was restarted after patching
- Compromise assessment if exposure existed prior to remediation

---

## What This Tool Does NOT Do

- No authentication bypass attempts
- No exploit testing
- No payload injection
- No session manipulation
- No post-exploitation activity

## Disclaimer

This project is provided strictly for **defensive security assessment purposes**.
Users are responsible for ensuring they have proper authorization to assess any
systems included in `targets.txt`.

---

## License

MIT License

---
