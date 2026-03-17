import dns.resolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]

def lookup_dns(domain: str) -> dict:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    results = {}

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append({"priority": rdata.preference, "value": str(rdata.exchange)})
                elif rtype == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "ttl": rdata.minimum
                    })
                else:
                    records.append(str(rdata))
            results[rtype] = {"found": True, "records": records, "ttl": answers.rrset.ttl}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"found": False, "error": "Domain does not exist"}
            break
        except dns.resolver.NoAnswer:
            results[rtype] = {"found": False, "records": []}
        except dns.exception.Timeout:
            results[rtype] = {"found": False, "error": "Query timed out"}
        except Exception as e:
            results[rtype] = {"found": False, "error": str(e)}

    return {"domain": domain, "records": results}
