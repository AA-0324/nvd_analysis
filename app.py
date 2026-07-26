import re
import time
from datetime import datetime, timedelta
import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_LIMIT = 30
SLEEP_BACKOFF = 15 
MAX_RETRY_ATTEMPTS = 5

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
    matched_tags = []
    for name, pattern in ECOSYSTEM_REGEX.items():
        if pattern.search(text_description):
            matched_tags.append(name)
            
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

    collected_rows = []
    tracking_stats = {"no_score_count": 0, "malformed_count": 0}
    consecutive_retries = 0

    print("Gathering full 30-day dataset from NVD...")
    print("Note: implementing a 6-second delay between requests to respect NVD's public rate limits.\n")

    while True:
        curr_index = query_params["startIndex"]
        print(f"Fetching records starting from index: {curr_index}...")

        try:
            response = requests.get(API_URL, params=query_params, timeout=TIMEOUT_LIMIT)
        except requests.exceptions.RequestException as net_err:
            consecutive_retries += 1
            if consecutive_retries > MAX_RETRY_ATTEMPTS:
                print(f"Network failure after {MAX_RETRY_ATTEMPTS} attempts: {net_err}. Bailing out.")
                break
            wait_time = SLEEP_BACKOFF * consecutive_retries
            print(f"Network hitch: {net_err}. Retry {consecutive_retries}/{MAX_RETRY_ATTEMPTS}, waiting {wait_time}s...")
            time.sleep(wait_time)
            continue

        if response.status_code != 200:
            if response.status_code in (403, 503):
                consecutive_retries += 1
                if consecutive_retries > MAX_RETRY_ATTEMPTS:
                    print(f"HTTP {response.status_code} limit hit {MAX_RETRY_ATTEMPTS} times. Stopping loop.")
                    break
                wait_time = SLEEP_BACKOFF * consecutive_retries
                print(f"Rate limited (HTTP {response.status_code}). Retry {consecutive_retries}/{MAX_RETRY_ATTEMPTS}, sleeping {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                print(f"Unhandled API error: HTTP {response.status_code}")
                break

        consecutive_retries = 0

        try:
            json_payload = response.json()
        except ValueError as json_err:
            print(f"JSON decoding error: {json_err}")
            break

        cve_list = json_payload.get("vulnerabilities", [])
        if not cve_list:
            break

        fetched_so_far = query_params["startIndex"] + len(cve_list)
        total_api_results = json_payload.get("totalResults", fetched_so_far)

        for cve_item in cve_list:
            parsed_row = parse_single_cve(cve_item, tracking_stats)
            if parsed_row is not None:
                collected_rows.append(parsed_row)

        query_params["startIndex"] += len(cve_list)
        
        if query_params["startIndex"] >= total_api_results:
            break

        time.sleep(6)

if __name__ == "__main__":
    run_nvd_analysis()
