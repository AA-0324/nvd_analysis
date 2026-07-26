# NVD Analysis

This repository contains the Python data pipeline built for my research on vulnerability distributions and threat vectors across major software ecosystems. 

The script `app.py` goes through the NIST National Vulnerability Database (NVD) API v2.0, gets a 30-day window of published CVEs, analyzes the severity metrics, and generates a statistical summary.

> **Read the Paper:** Arvind, A. "Empirical Vulnerability Analysis and Threat Vector Mapping Across Major Software Ecosystems." *Zenodo* (2026).  
> **DOI:** https://doi.org/10.5281/zenodo.21610629 



## Technical Details

Working with the raw NVD API presented a few technical problems. 

* Rate Limits: NIST limits unauthenticated API requests. So, the script implements a retry backoff and has a mandatory 6-second 'sleep' to keep the connection alive.
* CVSS Metric: NVD records have different scores depending on the standards of the year they were published. So, the parser has a fallback hierarchy. Records with no published scores are still tracked but excluded from the final averages.
* Boundary Tagging: The script maps CVEs to ecosystems (Linux, Microsoft, Apple, Google) with explicit word boundaries. This prevents false positives (for example, tagging "chrome" when the description actually says "chromebook").
* Multiple Tags: CVEs that affect more than one platform get assigned multiple tags. The pipeline uses `pandas.explode()` to expand these rows, ensuring the final statistical counts are accurate.

## Running It

**Requirements:** Python 3.8+, `requests`, `pandas`

   ```bash
   git clone https://github.com/AA-0324/nvd_analysis.git
   cd nvd_analysis
   python app.py
   ```

## License
See LICENSE file for more details :)
