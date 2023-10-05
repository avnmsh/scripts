import json

# Load data from the old and new reports
with open('old_report.json', 'r') as old_file, open('new_report.json', 'r') as new_file:
    old_data = json.load(old_file)
    new_data = json.load(new_file)

# Extract the "reference" values from both reports
old_references = set(issue['reference'] for issue in old_data['components'][0]['securityData']['securityIssues'])
new_references = set(issue['reference'] for issue in new_data['components'][0]['securityData']['securityIssues'])

# Find new references in the new report compared to the old report
new_references_only = new_references - old_references

# Print the new references and the count of new references
print("New references in the new report:")
for reference in new_references_only:
    print(reference)

print(f"Count of new references: {len(new_references_only)}")
