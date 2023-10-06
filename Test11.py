import json

# Load data from the old and new reports
with open('old_report.json', 'r') as old_file, open('new_report.json', 'r') as new_file:
    old_data = json.load(old_file)
    new_data = json.load(new_file)

# Initialize dictionaries for old and new references with their corresponding severities
old_references = {}
new_references = {}

# Extract "reference" values and their corresponding "severity" values from "securityIssues" where "source" is "cve" in the old report
for component in old_data.get("components", []):
    security_data = component.get("securityData")
    if security_data:
        for issue in security_data.get("securityIssues", []):
            if issue.get("source") == "cve":
                reference = issue.get("reference")
                severity = issue.get("severity")
                if reference and severity:
                    old_references[reference] = severity

# Extract "reference" values and their corresponding "severity" values from "securityIssues" where "source" is "cve" in the new report
for component in new_data.get("components", []):
    security_data = component.get("securityData")
    if security_data:
        for issue in security_data.get("securityIssues", []):
            if issue.get("source") == "cve":
                reference = issue.get("reference")
                severity = issue.get("severity")
                if reference and severity:
                    new_references[reference] = severity

# Find new references in the new report compared to the old report
new_references_only = set(new_references.keys()) - set(old_references.keys())

# Print references whose severity has increased
print("References whose severity has increased in the new report:")
for reference, new_severity in new_references.items():
    old_severity = old_references.get(reference)
    if old_severity is not None and new_severity > old_severity:
        print(f"Reference: {reference}, Old Severity: {old_severity}, New Severity: {new_severity}")

# Print new references found in the latest report
print("New references found in the latest report:")
for reference in new_references_only:
    print(f"Reference: {reference}, Severity: {new_references[reference]}")

print(f"Total references compared: {len(new_references)}")
