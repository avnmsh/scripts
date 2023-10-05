import json

# Load data from the old and new reports
with open('old_report.json', 'r') as old_file, open('new_report.json', 'r') as new_file:
    old_data = json.load(old_file)
    new_data = json.load(new_file)

# Extract the "reference" values from both reports
old_references = set()
for component in old_data.get("components", []):
    security_data = component.get("securityData")
    if security_data:
        for issue in security_data.get("securityIssues", []):
            reference = issue.get("reference")
            if reference:
                old_references.add(reference)

new_references = set()
for component in new_data.get("components", []):
    security_data = component.get("securityData")
    if security_data:
        for issue in security_data.get("securityIssues", []):
            reference = issue.get("reference")
            if reference:
                new_references.add(reference)

# Find new references in the new report compared to the old report
new_references_only = new_references - old_references

# Print the new references and the count of new references
print("New references in the new report:")
for reference in new_references_only:
    print(reference)

print(f"Count of new references: {len(new_references_only)}")
