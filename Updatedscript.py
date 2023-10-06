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

# Sort the new references by severity in descending order
sorted_new_references = sorted(new_references_only, key=lambda x: new_references[x], reverse=True)

# Print references whose severity has increased
print("References whose severity has increased in the new report:")
for reference in sorted_new_references:
    new_severity = new_references[reference]
    old_severity = old_references.get(reference)
    if old_severity is not None and new_severity > old_severity:
        print(f"Reference: {reference}, Old Severity: {old_severity}, New Severity: {new_severity}")

print(f"Count of new references where source is 'cve': {len(new_references_only)}")
