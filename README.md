# Priority Validator

Validation script for Priority Software.

## What it does
- Takes a list of domains as input
- Resolves DNS records: A, AAAA and CNAME
- Follows CNAMEs recursively (including subdomains)
- Validates common ports:
  - HTTP: 80 / 443
  - MySQL: 3306
- Uses OpenSSL CLI to extract TLS certificate data:
  - Valid from
  - Valid to
  - SHA256 fingerprint

## Requirements
- Python 3.9+
- OpenSSL installed and available in PATH
- dnspython


## Installation
```bash
pip install dnspython
