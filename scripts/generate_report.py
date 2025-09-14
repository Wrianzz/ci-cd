import json
import os
from collections import defaultdict

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
        # Semgrep JSON v1: locations ada di issue['start']['line']; v2: issue['start']['line'] juga
        line = (issue.get('start') or {}).get('line', '?')
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
                if not line.strip():
                    continue
                data = json.loads(line)
                severity = data.get("info", {}).get("severity", "UNKNOWN").upper()
                name = data.get("info", {}).get("name", "Unknown template")
                matched = data.get("matched-at", data.get("host", "unknown"))
                output.append(f"[{severity}] {name} (Target: {matched})")
    except Exception as e:
        output.append(f"Failed to parse Nuclei report: {e}")
    return "\n".join(output)

def format_grype_fs(data):
    """
    Grype JSON (dir scan) generally:
    {
      "matches": [
        {
          "vulnerability": {"id": "CVE-...", "severity": "High", "fix": {"state": "fixed", "versions": ["1.2.3"]}, ...},
          "artifact": {"name": "pkg", "version": "x.y.z", "type": "python", ...},
          ...
        }
      ],
      ...
    }
    """
    output = ["\n=== Grype Filesystem Report ==="]
    if not data or 'matches' not in data:
        output.append("No vulnerabilities found or invalid format.")
        return "\n".join(output)

    sev_count = defaultdict(int)
    for m in data.get('matches', []):
        sev = (m.get('vulnerability', {}).get('severity') or 'UNKNOWN').upper()
        sev_count[sev] += 1

    # Summary
    if sev_count:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
        summary = ", ".join([f"{s}: {sev_count[s]}" for s in order if sev_count.get(s, 0) > 0])
        output.append(f"Summary -> {summary}")

    # Details
    for m in data.get('matches', []):
        v = m.get('vulnerability', {}) or {}
        a = m.get('artifact', {}) or {}
        sev = (v.get('severity') or 'UNKNOWN').upper()
        vid = v.get('id', 'UNKNOWN-ID')
        pkg = a.get('name', 'unknown')
        ver = a.get('version', '?')
        ptype = a.get('type', '?')
        fix = v.get('fix', {}) or {}
        fix_state = fix.get('state', 'unknown')
        fixed_in = ""
        if isinstance(fix.get('versions'), list) and fix['versions']:
            fixed_in = ", ".join(fix['versions'])
        elif isinstance(fix.get('version'), str):
            fixed_in = fix['version']
        fix_txt = f"fix={fix_state}" + (f"-> {fixed_in}" if fixed_in else "")
        output.append(f"[{sev}] {vid} pkg={pkg}@{ver} type={ptype} ({fix_txt})")
    return "\n".join(output)

def format_trufflehog(filename):
    """
    TruffleHog JSON Lines; each line is a JSON object. Key fields commonly:
    Detector / DetectorName, File, StartLine/EndLine, Verified (bool), Redacted, RepositoryURL/SourceType.
    """
    full_path = os.path.join(REPORT_DIR, filename)
    output = ["\n=== TruffleHog Secrets Report ==="]
    if not os.path.exists(full_path):
        output.append("Report not found.")
        return "\n".join(output)

    total = 0
    verified = 0
    try:
        with open(full_path) as f:
            for line in f:
                if not line.strip():
                    continue
                obj = json.loads(line)
                total += 1
                det = obj.get("Detector") or obj.get("DetectorName") or "UnknownDetector"
                file_path = obj.get("File") or obj.get("Path") or "unknown"
                start = obj.get("StartLine") or obj.get("Line") or "?"
                end = obj.get("EndLine") or start
                verif = obj.get("Verified")
                if isinstance(verif, bool) and verif:
                    verified += 1
                commit = obj.get("Commit") or obj.get("CommitHash")
                src = obj.get("RepositoryURL") or obj.get("SourceID") or ""
                output.append(f"[SECRET]{' [VERIFIED]' if verif else ''} {det} (File: {file_path}, Line: {start}-{end}){f', Commit: {commit}' if commit else ''}{f', Src: {src}' if src else ''}")
    except Exception as e:
        output.append(f"Failed to parse TruffleHog report: {e}")
        return "\n".join(output)

    output.insert(1, f"Summary -> Findings: {total}, Verified: {verified}")
    return "\n".join(output)

def format_trivy_image(data):
    """
    Trivy JSON (image scan) with vuln + secret scanners:
    {
      "Results": [
        {
          "Target": "...",
          "Type": "os"|"library"|"secret"|...,
          "Vulnerabilities": [{ "VulnerabilityID": "...", "PkgName":"...", "InstalledVersion":"...", "Severity":"HIGH", "FixedVersion":"...", "Title": "..."}],
          "Secrets": [{ "RuleID":"...", "Target":"...", "Severity":"CRITICAL", "Title":"...", ...}]
        }
      ]
    }
    """
    output = ["\n=== Trivy Image Report ==="]
    if not data or 'Results' not in data:
        output.append("No results found or invalid format.")
        return "\n".join(output)

    # Aggregate
    vulns_by_sev = defaultdict(int)
    secrets_by_sev = defaultdict(int)
    for res in data.get('Results', []):
        for v in res.get('Vulnerabilities', []) or []:
            vulns_by_sev[(v.get('Severity') or 'UNKNOWN').upper()] += 1
        for s in res.get('Secrets', []) or []:
            secrets_by_sev[(s.get('Severity') or 'UNKNOWN').upper()] += 1

    def fmt_counts(d):
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        return ", ".join([f"{k}: {d[k]}" for k in order if d.get(k)])

    output.append("Summary -> Vulns: " + (fmt_counts(vulns_by_sev) if vulns_by_sev else "0"))
    output.append("Summary -> Secrets: " + (fmt_counts(secrets_by_sev) if secrets_by_sev else "0"))

    # Details (Vulnerabilities)
    any_v = False
    for res in data.get('Results', []):
        vulns = res.get('Vulnerabilities') or []
        if not vulns:
            continue
        any_v = True
        target = res.get('Target', 'unknown')
        rtype = res.get('Type', 'unknown')
        output.append(f"\n-- Vulnerabilities in {target} (type={rtype}) --")
        for v in vulns:
            sev = (v.get('Severity') or 'UNKNOWN').upper()
            vid = v.get('VulnerabilityID') or v.get('VulnID') or "UNKNOWN-ID"
            pkg = v.get('PkgName', 'unknown')
            inst = v.get('InstalledVersion', '?')
            fixed = v.get('FixedVersion') or ""
            title = v.get('Title') or v.get('Description') or ""
            fix_txt = f" -> fixed in {fixed}" if fixed else ""
            output.append(f"[{sev}] {vid} {pkg}@{inst}{fix_txt}{f' | {title}' if title else ''}")
    if not any_v:
        output.append("\n(No vulnerabilities)")

    # Details (Secrets)
    any_s = False
    for res in data.get('Results', []):
        secrets = res.get('Secrets') or []
        if not secrets:
            continue
        any_s = True
        target = res.get('Target', 'unknown')
        output.append(f"\n-- Secrets in {target} --")
        for s in secrets:
            sev = (s.get('Severity') or 'UNKNOWN').upper()
            rid = s.get('RuleID') or s.get('Rule') or "Rule"
            title = s.get('Title') or s.get('Category') or "Secret"
            loc = s.get('Target') or target
            output.append(f"[{sev}] {rid} - {title} (Target: {loc})")
    if not any_s:
        output.append("\n(No secrets)")

    return "\n".join(output)

def main():
    # Existing reports
    bandit = load_json("bandit-report.json")
    semgrep = load_json("semgrep-report.json")

    # New reports
    grype_fs = load_json("grype-fs.json")
    trivy_img = load_json("trivy-image-report.json")
    # TruffleHog is JSONL; parsed by formatter via filename
    trufflehog_file = "trufflehog-report.json"

    report_parts = []
    report_parts.append(format_bandit(bandit))
    report_parts.append(format_semgrep(semgrep))
    report_parts.append(format_grype_fs(grype_fs))
    report_parts.append(format_trufflehog(trufflehog_file))
    report_parts.append(format_trivy_image(trivy_img))
    report_parts.append(format_nuclei("nuclei-report.json"))

    output_path = os.path.join(REPORT_DIR, "final-security-report.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n\n".join(report_parts))

    print("[✓] Final security report saved as final-security-report.txt")

if __name__ == "__main__":
    main()
