import csv
from collections import Counter

rules = {
    "4625": "Failed login attempt",
    "4624": "Successful login",
    "4672": "Special privileges assigned",
    "4720": "New user account created",
    "4726": "User account deleted",
    "4732": "User added to local group",
    "1102": "Security log cleared"
}
severity_map = {
    "4624": "LOW",
    "4625": "MEDIUM",
    "4648": "MEDIUM",
    "4672": "HIGH",
    "4720": "HIGH",
    "4726": "HIGH",
    "4732": "HIGH",
    "1102": "CRITICAL"
}

input_file = "sample_logs/sample_events.csv"
output_file = "reports/sample_report.txt"

events = []

with open(input_file, newline="", encoding="utf-8") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        event_id = row.get("Id")
        if event_id in rules:
            events.append({
                "time": row.get("TimeCreated"),
                "id": event_id,
                "description": rules[event_id],
                "message": row.get("Message", "")[:250]
            })

counts = Counter(event["id"] for event in events)

with open(output_file, "w", encoding="utf-8") as report:
    report.write("Windows SIEM Mini Log Analyzer Report\n")
    report.write("=" * 40 + "\n\n")

    report.write("Event Summary:\n")
    for event_id, count in counts.items():
        report.write(f"{event_id} - {rules[event_id]}: {count}\n")

    report.write("\nFlagged Events:\n")
    for event in events:
        report.write("-" * 40 + "\n")
        report.write(f"Time: {event['time']}\n")
        report.write(f"Event ID: {event['id']}\n")
        report.write(f"Detection: {event['description']}\n")
        report.write(f"Message Preview: {event['message']}\n")
        report.write(f"Severity: {severity_map[event['id']]}\n")
        report.write(f"Detection: {event['description']}\n")
print(f"Analysis complete. Report saved to {output_file}")