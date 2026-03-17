import dns.resolver
import dns.reversename
import dns.exception
import socket
import re

def is_valid_ip(ip: str) -> bool:
    ipv4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6 = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4.match(ip) or ipv6.match(ip))

def reverse_lookup(ip: str) -> dict:
    ip = ip.strip()

    if not is_valid_ip(ip):
        return {"ip": ip, "found": False, "error": "Invalid IP address format"}

    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", lifetime=5)
        hostnames = [str(rdata) for rdata in answers]

        # Also try forward lookup to verify
        forward_verified = []
        for hostname in hostnames:
            clean = hostname.rstrip(".")
            try:
                fwd = dns.resolver.resolve(clean, "A", lifetime=5)
                fwd_ips = [str(r) for r in fwd]
                forward_verified.append({
                    "hostname": clean,
                    "forward_ips": fwd_ips,
                    "verified": ip in fwd_ips
                })
            except Exception:
                forward_verified.append({
                    "hostname": clean,
                    "forward_ips": [],
                    "verified": False
                })

        return {
            "ip": ip,
            "found": True,
            "ptr_record": str(rev_name),
            "hostnames": forward_verified
        }

    except dns.resolver.NXDOMAIN:
        return {"ip": ip, "found": False, "error": "No PTR record found for this IP address"}
    except dns.resolver.NoAnswer:
        return {"ip": ip, "found": False, "error": "No PTR record configured"}
    except dns.exception.Timeout:
        return {"ip": ip, "found": False, "error": "Query timed out"}
    except Exception as e:
        return {"ip": ip, "found": False, "error": str(e)}
