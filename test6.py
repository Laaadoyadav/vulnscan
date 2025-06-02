import requests
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
     
# Load CVEs from Excel
df = pd.read_excel("Cve.xlsx")
cve_ids = df['cve_id'].dropna().tolist()

# Download and read KEV data
url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
kev_df = pd.read_csv(url)
kev_df['cveID'] = kev_df['cveID'].str.lower()

def get_epss_details(cve_id):
    time.sleep(random.uniform(0.2, 0.5))
    api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if 'data' in data and data['data']:
            item = data['data'][0]
            return cve_id, {
                'cve': item.get('cve', cve_id),
                'epss': item.get('epss', 'N/A'),
                'percentile': item.get('percentile', 'N/A'),
                'date': item.get('date', 'N/A')
            }
    except:
        pass
    return cve_id, {'cve': cve_id, 'epss': 'Error', 'percentile': 'Error', 'date': 'Error'}

def get_cve_details(cve_id):
    time.sleep(random.uniform(0.2, 0.5))
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        cvss_data = data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']
        return cve_id, {
            'Severity': cvss_data.get('baseSeverity', 'N/A'),
            'Score': cvss_data.get('baseScore', 'N/A'),
            'Vector': cvss_data.get('vectorString', 'N/A')
        }
    except:
        return cve_id, {'Severity': 'Error', 'Score': 'Error', 'Vector': 'Error'}

# Run API calls in parallel
epss_results = {}
cvss_results = {}

with ThreadPoolExecutor(max_workers=5) as executor:
    epss_futures = {executor.submit(get_epss_details, cve): cve for cve in cve_ids}
    for future in as_completed(epss_futures):
        cve_id, data = future.result()
        epss_results[cve_id] = data

with ThreadPoolExecutor(max_workers=5) as executor:
    cvss_futures = {executor.submit(get_cve_details, cve): cve for cve in cve_ids}
    for future in as_completed(cvss_futures):
        cve_id, data = future.result()
        cvss_results[cve_id] = data

# Merge results
merged_data = []
for cve_id in cve_ids:
    row = {**epss_results.get(cve_id, {}), **cvss_results.get(cve_id, {})}
    merged_data.append(row)

# Build DataFrame
scan_df = pd.DataFrame(merged_data)
scan_df['cve'] = scan_df['cve'].str.lower()
scan_df['In_KEV'] = scan_df['cve'].isin(kev_df['cveID']).replace({True: 'Yes', False: 'No'})

# Export to Excel
scan_df.to_excel("cve_combined_details.xlsx", index=False)
print("Excel saved as 'cve_combined_details.xlsx'")
