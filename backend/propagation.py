import dns.resolver
import dns.exception
import concurrent.futures

RESOLVERS = [
    {"name": "Google",         "ip": "8.8.8.8",         "location": "🌐 Global"},
    {"name": "Cloudflare",     "ip": "1.1.1.1",         "location": "🌐 Global"},
    {"name": "OpenDNS",        "ip": "208.67.222.222",  "location": "🇺🇸 US"},
    {"name": "Quad9",          "ip": "9.9.9.9",         "location": "🌐 Global"},
    {"name": "Comodo",         "ip": "8.26.56.26",      "location": "🇺🇸 US"},
    {"name": "Level3",         "ip": "4.2.2.1",         "location": "🇺🇸 US"},
    {"name": "Verisign",       "ip": "64.6.64.6",       "location": "🇺🇸 US"},
    {"name": "DNS.Watch",      "ip": "84.200.69.80",    "location": "🇩🇪 Germany"},
    {"name": "Freenom",        "ip": "80.80.80.80",     "location": "🇳🇱 Netherlands"},
    {"name": "CleanBrowsing",  "ip": "185.228.168.9",   "location": "🌐 Global"},
]

def query_resolver(domain: str, record_type: str, resolver_info: dict) -> dict:
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_info["ip"]]
        resolver.lifetime = 5

        answers = resolver.resolve(domain, record_type)
        records = []
        for rdata in answers:
            if record_type == "MX":
                records.append(f"{rdata.preference} {rdata.exchange}")
            else:
                records.append(str(rdata))

        return {
            "resolver": resolver_info["name"],
            "location": resolver_info["location"],
            "ip": resolver_info["ip"],
            "status": "resolved",
            "records": records,
            "ttl": answers.rrset.ttl
        }
    except dns.resolver.NXDOMAIN:
        return {**resolver_info, "status": "nxdomain", "records": [], "error": "Domain not found"}
    except dns.resolver.NoAnswer:
        return {**resolver_info, "status": "no_answer", "records": [], "error": "No records found"}
    except dns.exception.Timeout:
        return {**resolver_info, "status": "timeout", "records": [], "error": "Timed out"}
    except Exception as e:
        return {**resolver_info, "status": "error", "records": [], "error": str(e)}

def check_propagation(domain: str, record_type: str = "A") -> dict:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    record_type = record_type.upper()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(query_resolver, domain, record_type, r)
            for r in RESOLVERS
        ]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Sort by resolver name for consistent display
    results.sort(key=lambda x: x.get("name", x.get("resolver", "")))

    # Determine propagation status
    resolved = [r for r in results if r["status"] == "resolved"]
    unique_values = set(tuple(sorted(r["records"])) for r in resolved)
    propagated = len(resolved)
    total = len(RESOLVERS)
    consistent = len(unique_values) <= 1

    return {
        "domain": domain,
        "record_type": record_type,
        "propagated": propagated,
        "total": total,
        "percent": round((propagated / total) * 100),
        "consistent": consistent,
        "results": results
    }
