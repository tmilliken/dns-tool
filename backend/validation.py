import dns.resolver
import dns.exception
import re

def get_txt_records(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [b"".join(rdata.strings).decode("utf-8", errors="ignore") for rdata in answers]
    except Exception:
        return []

def validate_spf(domain: str) -> dict:
    records = get_txt_records(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return {"found": False, "status": "missing", "message": "No SPF record found. Email spoofing is possible.", "record": None}

    if len(spf_records) > 1:
        return {"found": True, "status": "error", "message": "Multiple SPF records found. This is invalid — only one is allowed.", "record": spf_records}

    spf = spf_records[0]
    issues = []

    if "-all" in spf:
        policy = "fail (strict) — unauthorized senders are rejected ✅"
    elif "~all" in spf:
        policy = "softfail — unauthorized senders are marked but not rejected ⚠️"
    elif "?all" in spf:
        policy = "neutral — no policy enforced ⚠️"
        issues.append("Consider using -all or ~all for better protection")
    elif "+all" in spf:
        policy = "pass all — allows ANY sender ❌ (very insecure)"
        issues.append("Remove +all immediately — this allows anyone to send email as your domain")
    else:
        policy = "unknown"

    lookup_count = spf.count("include:") + spf.count("a:") + spf.count("mx") + spf.count("ptr")
    if lookup_count > 10:
        issues.append(f"SPF record has {lookup_count} DNS lookups (max is 10). This may cause delivery failures.")

    return {
        "found": True,
        "status": "warning" if issues else "valid",
        "record": spf,
        "policy": policy,
        "issues": issues
    }

def validate_dmarc(domain: str) -> dict:
    dmarc_domain = f"_dmarc.{domain}"
    records = get_txt_records(dmarc_domain)
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {"found": False, "status": "missing", "message": "No DMARC record found. You have no email authentication reporting.", "record": None}

    dmarc = dmarc_records[0]
    issues = []
    tags = dict(re.findall(r'(\w+)=([^;]+)', dmarc))

    policy = tags.get("p", "none")
    if policy == "none":
        issues.append("Policy is 'none' — emails are not rejected or quarantined. Consider upgrading to 'quarantine' or 'reject'.")
    elif policy == "quarantine":
        policy_desc = "quarantine — suspicious emails go to spam ⚠️"
    elif policy == "reject":
        policy_desc = "reject — unauthorized emails are blocked ✅"
    else:
        policy_desc = policy

    pct = tags.get("pct", "100")
    if int(pct) < 100:
        issues.append(f"Policy applies to only {pct}% of emails. Consider increasing to 100%.")

    rua = tags.get("rua", None)
    ruf = tags.get("ruf", None)

    return {
        "found": True,
        "status": "warning" if issues else "valid",
        "record": dmarc,
        "policy": policy,
        "policy_description": policy_desc if policy not in ["none"] else "none — monitoring only ⚠️",
        "reporting_uri": rua,
        "forensic_uri": ruf,
        "percentage": pct,
        "issues": issues
    }

def validate_dkim(domain: str, selectors: list = None) -> dict:
    if selectors is None:
        selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2", "mandrill", "mailchimp", "smtp"]

    found_selectors = []
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = get_txt_records(dkim_domain)
        dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
        if dkim_records:
            found_selectors.append({"selector": selector, "record": dkim_records[0]})

    if not found_selectors:
        return {
            "found": False,
            "status": "unknown",
            "message": f"No DKIM records found for common selectors ({', '.join(selectors[:5])}...). DKIM may still be configured with a custom selector.",
            "selectors": []
        }

    return {
        "found": True,
        "status": "valid",
        "message": f"Found DKIM records for {len(found_selectors)} selector(s).",
        "selectors": found_selectors
    }

def validate_email_security(domain: str) -> dict:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]

    spf = validate_spf(domain)
    dmarc = validate_dmarc(domain)
    dkim = validate_dkim(domain)

    # Overall score
    score = 0
    if spf["found"] and spf["status"] == "valid": score += 33
    elif spf["found"]: score += 15
    if dmarc["found"] and dmarc["status"] == "valid": score += 34
    elif dmarc["found"]: score += 15
    if dkim["found"]: score += 33

    if score >= 90:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 40:
        grade = "C"
    else:
        grade = "F"

    return {
        "domain": domain,
        "score": score,
        "grade": grade,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim
    }
