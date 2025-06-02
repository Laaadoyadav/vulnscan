import requests
import time
import pandas as pd
import threading
import itertools
import sys
import os

# Spinner class for visual feedback during long tasks
class Spinner:
    def __init__(self, message="Loading..."):
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self.running = False
        self.thread = None
        self.message = message

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def _spin(self):
        while self.running:
            sys.stdout.write(f'\r{self.message} {next(self.spinner)}')
            sys.stdout.flush()
            time.sleep(0.1)

    def stop(self):
        self.running = False
        self.thread.join()
        sys.stdout.write('\r' + ' ' * 50 + '\r')  # Clear the line

# Load CVEs from Excel
print("Loading CVE list from Excel...")
df = pd.read_excel("Cve.xlsx")  # Make sure this file exists
cve_ids = df['cve_id'].dropna().tolist()

# Load KEV data
print("Loading KEV data from CISA...")
kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
response = requests.get(kev_url)
with open("known_exploited_vulnerabilities.csv", "wb") as f:
    f.write(response.content)
kev_df = pd.read_csv("known_exploited_vulnerabilities.csv")
kev_df['cveID'] = kev_df['cveID'].str.lower()

# Define EPSS API call
def get_epss_details(cve_id):
    
    api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}&pretty=true"
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if 'data' in data and data['data']:
            item = data['data'][0]
            return {
                'cve': item.get('cve', 'N/A'),
                'epss': item.get('epss', 'N/A'),
                'percentile': item.get('percentile', 'N/A'),
                'date': item.get('date', 'N/A')
            }
        else:
            return {'cve': cve_id, 'epss': 'N/A', 'percentile': 'N/A', 'date': 'N/A'}
    except Exception:
        return {'cve': cve_id, 'epss': 'Error', 'percentile': 'Error', 'date': 'Error'}
    
# Define CVSS API call
def get_cve_details(cve_id):
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        cvss_data = data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']
        return {
            'Severity': cvss_data.get('baseSeverity', 'N/A'),
            'Score': cvss_data.get('baseScore', 'N/A'),
            'Vector': cvss_data.get('vectorString', 'N/A')
        }
    except Exception:
        return {'Severity': 'Error', 'Score': 'Error', 'Vector': 'Error'}
    
# Download + merge EPSS and CVSS data
merged_data = []
spinner = Spinner("Compiling data for each CVE")
spinner.start()

for cve_id in cve_ids:
    cvss = get_cve_details(cve_id)
    epss = get_epss_details(cve_id)
    merged_row = {**epss, **cvss}
    merged_data.append(merged_row)
    time.sleep(1.2)  # Throttle requests

spinner.stop()

# Create DataFrame and compare with KEV
scan_df = pd.DataFrame(merged_data)
scan_df['cve'] = scan_df['cve'].str.lower()
scan_df['In_KEV'] = scan_df['cve'].isin(kev_df['cveID']).replace({True: 'Yes', False: 'No'})

# Save to Excel
print("Saving Excel file...")
scan_df.to_excel("cve_combined_details.xlsx", index=False)
print("Excel saved as 'cve_combined_details.xlsx'")

# Cleanup
def cleanup():
    if os.path.exists("known_exploited_vulnerabilities.csv"):
        os.remove("known_exploited_vulnerabilities.csv")

cleanup()
print("Cleanup complete. KEV file removed.")
