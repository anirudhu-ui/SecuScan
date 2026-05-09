import json
from typing import Dict, Any, List

def parse(output: str) -> Dict[str, Any]:
    """
    Parse WHOIS output (JSON format from whois_tool.py).
    """
    try:
        # Robust JSON extraction: find the first '{' and last '}'
        start = output.find('{')
        end = output.rfind('}')
        if start != -1 and end != -1:
            json_content = output[start:end+1]
            data = json.loads(json_content)
        else:
            data = json.loads(output)
    except Exception:
        # Fallback if output is not JSON
        return {"findings": [], "error": "Invalid output format"}

    findings = []
    
    registrar = data.get("registrar") or data.get("registrar_name", "Unknown")
    expiry = data.get("expiration_date")
    if isinstance(expiry, list):
        expiry = expiry[0]
    
    nameservers = data.get("name_servers", [])
    if isinstance(nameservers, list):
        nameservers = ", ".join(nameservers)
    
    creation = data.get("creation_date")
    if isinstance(creation, list):
        creation = creation[0]
    # Format date string (e.g. 1997-09-15)
    creation_str = str(creation).split(' ')[0] if creation else "Unknown"
    expiry_str = str(expiry).split(' ')[0] if expiry else "Unknown"
    
    summary_data = {
        "registrar": registrar,
        "organization": data.get("org") or "N/A",
        "country": data.get("country") or "N/A",
        "creation": creation_str,
        "expiry": expiry_str,
        "nameservers": nameservers or "N/A"
    }
    
    findings.append({
        "title": f"WHOIS Record for {data.get('domain_name', 'Target')}",
        "category": "Domain Info",
        "severity": "info",
        "description": f"Registrar: {summary_data['registrar']}\nExpiry: {summary_data['expiry']}\nName Servers: {', '.join(summary_data['nameservers'])}",
        "remediation": "Review domain registration data for accuracy and privacy settings (WHOIS privacy).",
        "metadata": data
    })
    
    return {
        "findings": findings,
        "rows": [summary_data],
        "detail": summary_data
    }
