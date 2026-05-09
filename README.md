# cPanel Control Plane Exposure Check

Lightweight security utility to identify internet-exposed cPanel, WHM, and webmail administrative interfaces for authorized attack surface validation and hardening assessments.

## Features

- Detects exposed cPanel interfaces
- Identifies publicly accessible WHM portals
- Checks common cPanel administrative ports
- Supports HTTP and HTTPS validation
- Lightweight and simple to use

## Ports Checked

| Service | Ports |
|----------|------|
| cPanel | 2082, 2083 |
| WHM | 2086, 2087 |
| Webmail | 2095, 2096 |

## Usage

```bash
python scanner.py targets.txt
```

## Example Output

```text
[+] example.com:2087 - WHM administrative interface detected
[+] example.com:2083 - cPanel login interface detected
[-] example.com:2096 - Not accessible
```

## Use Cases

- External attack surface validation
- Internet-facing management plane exposure checks
- Security hardening verification
- Reconnaissance during authorized assessments

## Disclaimer

This utility is intended only for authorized security assessments and defensive security validation activities.

## License

MIT License
