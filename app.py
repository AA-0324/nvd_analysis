import re
from datetime import datetime, timedelta
import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_LIMIT = 30

# Note: Word-boundary regex (\b) is critical here. Initial prototype without \b 
# resulted in false positives (e.g., matching "chromebook" when scanning for "chrome").
ECOSYSTEM_REGEX = {
    "Linux": re.compile(r"\b(linux|ubuntu|debian|redhat)\b"),
    "Google": re.compile(r"\b(google|android|chrome)\b"),
    "Apple": re.compile(r"\b(apple|macos|ios|ipados)\b"),
    "Microsoft": re.compile(r"\b(microsoft|windows|exchange)\b")
}

def get_cve_id_fallback(item):
    """
    Emergency backup helper: if a record is so broken it crashes parse_single_cve,
    we still try to snag the ID so we know which record ruined our day.
    """
    try:
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "unknown-id")
        return cve_id
    except Exception:
        return "unknown-id"

def assign_ecosystems(text_description):
    # Some CVEs affect multiple stacks at once (e.g. Chrome engine bugs hitting Linux distros).
    # Catch all matches instead of stopping at the first one.
    matched_tags = []
    
    for name, pattern in ECOSYSTEM_REGEX.items():
        if pattern.search(text_description):
            matched_tags.append(name)
            
    # Redundant check just in case, but safe
    if len(matched_tags) > 0:
        return matched_tags
    else:
        return ["Other"]

def get_cvss_score_and_vector(cve_dict):
    metrics_data = cve_dict.get("metrics", {})
    cvss_list = (
        metrics_data.get("cvssMetricV31") or
        metrics_data.get("cvssMetricV30") or
        metrics_data.get("cvssMetricV2") or
        []
    )
    if not cvss_list:
        return None, "UNKNOWN"
        
    primary_metric = cvss_list[0].get("cvssData", {})
    base_score = primary_metric.get("baseScore")
    attack_vector = primary_metric.get("attackVector", primary_metric.get("accessVector", "UNKNOWN"))
    cleaned_vector = str(attack_vector).upper() if attack_vector else "UNKNOWN"
    return base_score, cleaned_vector

def parse_single_cve(item, tracking_stats):
    try:
        cve_data = item.get("cve", {})
        descriptions_list = cve_data.get("descriptions", [])
        
        # Joined with spaces so fragment boundaries don't smash words together!
        full_text = " ".join([d.get("value", "").lower() for d in descriptions_list])
        
        score, vector = get_cvss_score_and_vector(cve_data)
        if score is None:
            tracking_stats["no_score_count"] += 1
            return None
            
        return {
            "CVE_ID": cve_data.get("id"),
            "Attack_Vector": vector,
            "Ecosystems": assign_ecosystems(full_text),
            "CVSS_Score": float(score)
        }
    except Exception as err:
        tracking_stats["malformed_count"] += 1
        bad_id = get_cve_id_fallback(item)
        print(f"  [!] Skipping malformed record ({bad_id}): {err}")
        return None

def run_nvd_analysis():
    today_date = datetime.now()
    start_date = today_date - timedelta(days=30)

    query_params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": today_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    tracking_stats = {"no_score_count": 0, "malformed_count": 0}
    response = requests.get(API_URL, params=query_params, timeout=TIMEOUT_LIMIT)
    
    if response.status_code == 200:
        data = response.json()
        cve_list = data.get("vulnerabilities", [])
        collected = []
        for item in cve_list:
            parsed = parse_single_cve(item, tracking_stats)
            if parsed:
                collected.append(parsed)
        print(f"Sample parsed item: {collected[0]}")

if __name__ == "__main__":
    run_nvd_analysis()
