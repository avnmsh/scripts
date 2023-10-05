import json

# Load data from the old and new reports
with open('old_report.json', 'r') as old_file, open('new_report.json', 'r') as new_file:
    old_data = json.load(old_file)
    new_data = json.load(new_file)

# Initialize empty sets for old and new references
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

# Print the new references, their corresponding "severity" values, and the count of new references
print("New references in the new report where source is 'cve':")
for reference in new_references_only:
    severity = new_references[reference]
    print(f"Reference: {reference}, Severity: {severity}")

print(f"Count of new references where source is 'cve': {len(new_references_only)}")
