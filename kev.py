import pandas as pd
import requests

# Step 1: Download and load KEV list from CISA
url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
response = requests.get(url)

with open("known_exploited_vulnerabilities.csv", "wb") as f:
    f.write(response.content)

kev_df = pd.read_csv("known_exploited_vulnerabilities.csv")
kev_df['cveID'] = kev_df['cveID'].str.lower()

# Step 2: Load your Excel file with scan CVEs
# Replace 'your_scan_file.xlsx' with the actual filename

scan_df = pd.read_excel("sample.xlsx") 
# Step 3: Normalize the 'cve' column for comparison
scan_df['cve'] = scan_df['cve'].str.lower()

# Step 4: Compare and create new column
scan_df['In_KEV'] = scan_df['cve'].isin(kev_df['cveID']).replace({True: 'Yes', False: ''})

# # Step 5: Save the updated file
scan_df.to_excel("scan_vs_kev.xlsx", index=False)

# Optional: Display result
print(scan_df.head())
print(scan_df)