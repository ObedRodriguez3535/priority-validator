#!/usr/bin/env python3
import argparse
import json
import re
import socket
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple

import dns.resolver

HTTP_PORTS = [80, 443]
MYSQL_PORTS = [3306]

PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL
)

@dataclass
class DNSRecord:
    source_domain: str
    owner: str
    rtype: str
    value: str

@dataclass
class CertInfo:
    valid_from: Optional[str]
    valid_to: Optional[str]
    fingerprint_sha256: Optional[str]

@dataclass
class ServiceCheck:
    source_domain: str
    target: str
    protocol: str
    port: int
    open: bool
    tls_present: bool
    cert: Optional[CertInfo]
    error: Optional[str] = None

def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def run_openssl_get_cert(host: str, port: int, protocol: str, timeout: int = 12) -> Tuple[Optional[bytes], Optional[str]]:
    if protocol == "HTTP" and port == 443:
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"]
    elif protocol == "MySQL" and port == 3306:
        cmd = ["openssl", "s_client", "-starttls", "mysql", "-connect", f"{host}:{port}", "-showcerts"]
    else:
        return None, "TLS not applicable"

    try:
        proc = subprocess.run(
            cmd,
            input=b"Q\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "openssl timeout"
    except FileNotFoundError:
        return None, "openssl not found"

    out = proc.stdout or b""
    m = PEM_CERT_RE.search(out)
    if not m:
        return None, "no certificate found"

    leaf = b"-----BEGIN CERTIFICATE-----" + m.group(1) + b"-----END CERTIFICATE-----\n"
    return leaf, None

def parse_cert_info(cert_pem: bytes) -> Tuple[Optional[CertInfo], Optional[str]]:
    cmd = ["openssl", "x509", "-noout", "-dates", "-fingerprint", "-sha256"]
    try:
        proc = subprocess.run(
            cmd,
            input=cert_pem,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return None, "openssl timeout"
    except FileNotFoundError:
        return None, "openssl not found"

    text = (proc.stdout or b"").decode(errors="ignore").splitlines()

    valid_from = None
    valid_to = None
    fingerprint = None

    for line in text:
        line = line.strip()
        if line.startswith("notBefore="):
            valid_from = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            valid_to = line.split("=", 1)[1].strip()
        elif "Fingerprint=" in line:
            fingerprint = line.split("Fingerprint=", 1)[1].strip()

    return CertInfo(valid_from, valid_to, fingerprint), None

def resolve_one(hostname: str, resolver: dns.resolver.Resolver) -> List[Tuple[str, str]]:
    results = []
    for rtype in ["A", "AAAA", "CNAME"]:
        try:
            answers = resolver.resolve(hostname, rtype)
            for ans in answers:
                if rtype in ("A", "AAAA"):
                    results.append((rtype, ans.address))
                else:
                    results.append((rtype, str(ans.target).rstrip(".")))
        except Exception:
            continue
    return results

def collect_dns_records(domain: str, max_nodes: int = 300) -> List[DNSRecord]:
    resolver = dns.resolver.Resolver()
    queue = [domain]
    visited: Set[str] = set()
    records: List[DNSRecord] = []

    while queue and len(visited) < max_nodes:
        host = queue.pop(0)
        if host in visited:
            continue
        visited.add(host)

        resolved = resolve_one(host, resolver)
        for rtype, value in resolved:
            records.append(DNSRecord(domain, host, rtype, value))
            if rtype == "CNAME" and value not in visited:
                queue.append(value)

    return records

def build_targets(records: List[DNSRecord]) -> Set[str]:
    return {r.value for r in records}

def check_services_for_target(source_domain: str, target: str) -> List[ServiceCheck]:
    checks: List[ServiceCheck] = []

    for port in HTTP_PORTS:
        open_ = is_port_open(target, port)
        tls_present = False
        cert_info = None
        error = None

        if open_ and port == 443:
            cert_pem, err = run_openssl_get_cert(target, port, "HTTP")
            if cert_pem:
                cert_info, error = parse_cert_info(cert_pem)
                tls_present = cert_info is not None
            else:
                error = err

        checks.append(ServiceCheck(
            source_domain,
            target,
            "HTTP",
            port,
            open_,
            tls_present,
            cert_info,
            error
        ))

    for port in MYSQL_PORTS:
        open_ = is_port_open(target, port)
        tls_present = False
        cert_info = None
        error = None

        if open_:
            cert_pem, err = run_openssl_get_cert(target, port, "MySQL")
            if cert_pem:
                cert_info, error = parse_cert_info(cert_pem)
                tls_present = cert_info is not None
            else:
                error = err

        checks.append(ServiceCheck(
            source_domain,
            target,
            "MySQL",
            port,
            open_,
            tls_present,
            cert_info,
            error
        ))

    return checks

def format_human(domain: str, records: List[DNSRecord], checks: List[ServiceCheck]) -> str:
    lines: List[str] = []
    lines.append(f"Domain: {domain}")
    lines.append("")

    cname = [r for r in records if r.rtype == "CNAME"]
    a = [r for r in records if r.rtype == "A"]
    aaaa = [r for r in records if r.rtype == "AAAA"]

    lines.append("Discovered DNS records:")
    if not records:
        lines.append("  (none)")
    else:
        for r in cname:
            lines.append(f"  CNAME  {r.owner} -> {r.value}")
        for r in a:
            lines.append(f"  A      {r.owner} -> {r.value}")
        for r in aaaa:
            lines.append(f"  AAAA   {r.owner} -> {r.value}")
    lines.append("")

    by_target: Dict[str, List[ServiceCheck]] = {}
    for c in checks:
        by_target.setdefault(c.target, []).append(c)

    def proto_sort_key(c: ServiceCheck) -> Tuple[int, int]:
        p = 0 if c.protocol == "HTTP" else 1
        return (p, c.port)

    for target in sorted(by_target.keys()):
        lines.append(f"Target: {target}")
        entries = sorted(by_target[target], key=proto_sort_key)
        for c in entries:
            label = "HTTP" if (c.protocol == "HTTP" and c.port == 80) else \
                    "HTTPS" if (c.protocol == "HTTP" and c.port == 443) else \
                    "MySQL"
            status = "OPEN" if c.open else "CLOSED"
            if c.protocol == "HTTP" and c.port == 443 and c.open:
                if c.tls_present and c.cert:
                    lines.append(f"  {label}:{c.port:<5} {status} (TLS)")
                    lines.append("    Certificate:")
                    lines.append(f"      Valid from : {c.cert.valid_from or 'unknown'}")
                    lines.append(f"      Valid to   : {c.cert.valid_to or 'unknown'}")
                    lines.append(f"      Fingerprint: {c.cert.fingerprint_sha256 or 'unknown'}")
                else:
                    msg = c.error or "no certificate"
                    lines.append(f"  {label}:{c.port:<5} {status} (NO TLS CERTIFICATE: {msg})")
            elif c.protocol == "MySQL" and c.open:
                if c.tls_present and c.cert:
                    lines.append(f"  {label}:{c.port:<5} {status} (TLS)")
                    lines.append("    Certificate:")
                    lines.append(f"      Valid from : {c.cert.valid_from or 'unknown'}")
                    lines.append(f"      Valid to   : {c.cert.valid_to or 'unknown'}")
                    lines.append(f"      Fingerprint: {c.cert.fingerprint_sha256 or 'unknown'}")
                else:
                    msg = c.error or "no certificate"
                    lines.append(f"  {label}:{c.port:<5} {status} (NO TLS CERTIFICATE: {msg})")
            else:
                lines.append(f"  {label}:{c.port:<5} {status}")
        lines.append("")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", nargs="+")
    parser.add_argument("--domains-file")
    parser.add_argument("--max-nodes", type=int, default=300)
    parser.add_argument("--out", default="-")
    parser.add_argument("--format", choices=["jsonl", "human"], default="jsonl")
    args = parser.parse_args()

    domains: List[str] = []

    if args.domains:
        domains.extend(args.domains)

    if args.domains_file:
        with open(args.domains_file, "r") as f:
            for line in f:
                d = line.strip()
                if d:
                    domains.append(d)

    if not domains:
        domains = ["example.com"]

    out_f = open(args.out, "w") if args.out != "-" else None

    def write_line(s: str):
        if out_f:
            out_f.write(s + "\n")
        else:
            print(s)

    for domain in domains:
        records = collect_dns_records(domain, args.max_nodes)
        targets = build_targets(records)

        all_checks: List[ServiceCheck] = []
        for target in sorted(targets):
            all_checks.extend(check_services_for_target(domain, target))

        if args.format == "human":
            write_line(format_human(domain, records, all_checks))
        else:
            for r in records:
                line = json.dumps({"type": "dns_record", **asdict(r)})
                write_line(line)
            for c in all_checks:
                line = json.dumps({"type": "service_check", **asdict(c)})
                write_line(line)

    if out_f:
        out_f.close()

if __name__ == "__main__":
    main()
