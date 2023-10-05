import json

# Define the file paths for the current and previous Nexus IQ reports
current_report_path = 'current_report.json'
previous_report_path = 'previous_report.json'

# Load the contents of the reports
with open(current_report_path, 'r') as current_report_file, open(previous_report_path, 'r') as previous_report_file:
    current_report = json.load(current_report_file)
    previous_report = json.load(previous_report_file)

# Extract CVEs from the current and previous reports
current_components = current_report.get('components', [])
previous_components = previous_report.get('components', [])

# Function to extract CVE IDs from a list of components
def extract_cve_ids(components):
    cve_ids = set()
    for component in components:
        security_data = component.get('securityData', {})
        security_issues = security_data.get('securityIssues', [])
        for issue in security_issues:
            references = issue.get('reference', [])
            for reference in references:
                if reference.startswith("CVE-"):
                    cve_ids.add(reference)
    return cve_ids

# Extract CVE IDs from the current and previous reports
current_cve_ids = extract_cve_ids(current_components)
previous_cve_ids = extract_cve_ids(previous_components)

# Find new CVEs introduced in the current report
new_cves = current_cve_ids - previous_cve_ids

# Print or handle the new CVEs
if new_cves:
    print("New CVEs:")
    for cve_id in new_cves:
        print(f"CVE ID: {cve_id}")
else:
    print("No new CVEs found.")
