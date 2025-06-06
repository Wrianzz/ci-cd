import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "..", "reports")

def load_json(filename):
    full_path = os.path.join(REPORT_DIR, filename)
    try:
        with open(full_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error reading {full_path}: {e}")
        return None

def format_bandit(data):
    output = ["=== Bandit Report ==="]
    if not data or 'results' not in data:
        output.append("No issues found or invalid format.")
        return "\n".join(output)

    for issue in data['results']:
        output.append(f"[{issue['issue_severity']}] {issue['issue_text']} (File: {issue['filename']}, Line: {issue['line_number']})")
    return "\n".join(output)

def format_semgrep(data):
    output = ["\n=== Semgrep Report ==="]
    if not data or 'results' not in data:
        output.append("No issues found or invalid format.")
        return "\n".join(output)

    for issue in data['results']:
        severity = issue.get('extra', {}).get('severity', 'UNKNOWN')
        message = issue.get('extra', {}).get('message', 'No message')
        path = issue.get('path', 'unknown')
        line = issue.get('start', {}).get('line', '?')
        output.append(f"[{severity}] {message} (File: {path}, Line: {line})")
    return "\n".join(output)

def format_nuclei(filename):
    full_path = os.path.join(REPORT_DIR, filename)
    output = ["\n=== Nuclei Report ==="]
    if not os.path.exists(full_path):
        output.append("Report not found.")
        return "\n".join(output)

    try:
        with open(full_path) as f:
            for line in f:
                data = json.loads(line)
                severity = data.get("info", {}).get("severity", "UNKNOWN").upper()
                name = data.get("info", {}).get("name", "Unknown template")
                matched = data.get("matched-at", "unknown")
                output.append(f"[{severity}] {name} (Target: {matched})")
    except Exception as e:
        output.append(f"Failed to parse Nuclei report: {e}")
    return "\n".join(output)

def main():
    bandit = load_json("bandit-report.json")
    semgrep = load_json("semgrep-report.json")

    report = []
    report.append(format_bandit(bandit))
    report.append(format_semgrep(semgrep))
    report.append(format_nuclei("nuclei-report.json"))

    output_path = os.path.join(REPORT_DIR, "final-security-report.txt")
    with open(output_path, "w") as f:
        f.write("\n\n".join(report))
    
    print("[✓] Final security report saved as final-security-report.txt")

if __name__ == "__main__":
    main()
