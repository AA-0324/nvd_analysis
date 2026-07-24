from datetime import datetime, timedelta
import requests

# NVD API v2.0 endpoint (if NIST ever changes this again I'm going to cry)
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_LIMIT = 30

# Note to self: turn off debug mode before final paper run!
debug_mode = True

def run_nvd_analysis():
    today_date = datetime.now()
    start_date = today_date - timedelta(days=30)

    query_params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": today_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    print("Gathering NVD data from endpoint...")
    response = requests.get(API_URL, params=query_params, timeout=TIMEOUT_LIMIT)
    
    if response.status_code == 200:
        data = response.json()
        cve_list = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        print(f"Initial fetch success! Grabbed {len(cve_list)} records out of {total_results}.")
    else:
        print(f"API error: HTTP {response.status_code}")

if __name__ == "__main__":
    run_nvd_analysis()
