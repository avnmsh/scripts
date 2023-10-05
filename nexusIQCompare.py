import json

# Define the file paths for the current and previous Nexus IQ reports
current_report_path = 'current_report.json'
previous_report_path = 'previous_report.json'

# Load the contents of the reports
with open(current_report_path, 'r') as current_report_file, open(previous_report_path, 'r') as previous_report_file:
    current_report = json.load(current_report_file)
    previous_report = json.load(previous_report_file)

# Extract CVE IDs from the "Components" > "securityData" > "securityIssues" > "reference" structure
current_components = current_report.get('components', [])
previous_components = previous_report.get('components', [])

# Function to extract CVE IDs from the reference field of a component
def extract_cve_ids(component):
    references = component.get('securityData', {}).get('securityIssues', {}).get('reference', [])
    cve_ids = set()
    for reference in references:
        if reference.startswith("CVE-"):
            cve_ids.add(reference)
    return cve_ids

# Extract CVE IDs from the current and previous reports
current_cve_ids = set(cve_id for component in current_components for cve_id in extract_cve_ids(component))
previous_cve_ids = set(cve_id for component in previous_components for cve_id in extract_cve_ids(component))

# Find new CVEs introduced in the current report
new_cves = current_cve_ids - previous_cve_ids

# Print or handle the new CVEs
if new_cves:
    print("New CVEs:")
    for cve_id in new_cves:
        print(f"CVE ID: {cve_id}")
else:
    print("No new CVEs found.")
