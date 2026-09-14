from __future__ import annotations

import json
import os
import signal
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.ensemble import IsolationForest

LOG_PATH = Path("/data/security.log")
OUTPUT_PATH = Path("/output/findings.json")

FULL_MITRE_PATH = Path("/mitre/enterprise-attack.json")
MINI_MITRE_PATH = Path("/mitre/enterprise-attack-mini.json")

FAILED_PASSWORD_THRESHOLD = int(
    os.getenv("FAILED_PASSWORD_THRESHOLD", "3")
)
SCAN_INTERVAL_SECONDS = int(
    os.getenv("SCAN_INTERVAL_SECONDS", "5")
)

running = True
mitre_index: dict[str, dict[str, Any]] = {}
mitre_source_path: Path | None = None
mitre_last_modified: float | None = None
mitre_loaded_at: str | None = None


def stop_handler(signum: int, frame: object) -> None:
    global running
    running = False


signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)


def select_mitre_path() -> Path | None:
    if FULL_MITRE_PATH.exists():
        return FULL_MITRE_PATH
    if MINI_MITRE_PATH.exists():
        return MINI_MITRE_PATH
    return None


def extract_external_reference(
    attack_pattern: dict[str, Any],
) -> tuple[str | None, str | None]:
    for reference in attack_pattern.get("external_references", []):
        if reference.get("source_name") != "mitre-attack":
            continue
        technique_id = reference.get("external_id")
        technique_url = reference.get("url")
        if technique_id:
            return str(technique_id), (
                str(technique_url) if technique_url else None
            )
    return None, None


def load_mitre_knowledge(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    objects = data.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("The STIX bundle does not contain an objects list.")

    index: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        technique_id, technique_url = extract_external_reference(obj)
        if not technique_id:
            continue

        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if not isinstance(phase, dict):
                continue
            phase_name = phase.get("phase_name")
            if phase_name:
                tactics.append(
                    str(phase_name).replace("-", " ").title()
                )

        index[technique_id] = {
            "name": obj.get("name", "Unknown"),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "url": technique_url,
            "stix_id": obj.get("id"),
            "created": obj.get("created"),
            "modified": obj.get("modified"),
            "version": obj.get("x_mitre_version"),
        }
    return index


def refresh_mitre_index() -> None:
    global mitre_index, mitre_source_path, mitre_last_modified, mitre_loaded_at
    selected_path = select_mitre_path()

    if selected_path is None:
        mitre_index = {}
        mitre_source_path = None
        mitre_last_modified = None
        mitre_loaded_at = None
        return

    current_modified = selected_path.stat().st_mtime
    if (
        mitre_source_path == selected_path
        and mitre_last_modified == current_modified
        and bool(mitre_index)
    ):
        return

    try:
        new_index = load_mitre_knowledge(selected_path)
    except Exception as exc:
        print(f"MITRE reload failed: {exc}", flush=True)
        return

    mitre_index = new_index
    mitre_source_path = selected_path
    mitre_last_modified = current_modified
    mitre_loaded_at = datetime.now(timezone.utc).isoformat()
    print(f"MITRE knowledge loaded: {len(mitre_index)} techniques.", flush=True)


def extract_source_ip(line: str) -> str:
    if " from " not in line:
        return "unknown"
    return line.split(" from ", 1)[1].split()[0]


def create_candidate_findings(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").splitlines()
    findings: list[dict[str, Any]] = []
    failed_password_sources: Counter[str] = Counter()

    for line_number, line in enumerate(lines, start=1):
        normalized = line.lower()
        source_ip = extract_source_ip(line)

        if "failed password" in normalized and source_ip != "unknown":
            failed_password_sources[source_ip] += 1

        if "network scan detected" in normalized:
            findings.append({
                "finding": "Possible network service discovery",
                "source_ip": source_ip,
                "candidate_mitre_technique": "T1046",
                "severity": "Medium",
                "detection_type": "Signature-based",
                "evidence": line,
                "line_number": line_number,
                "detection_rule": "The log contains 'network scan detected'."
            })

    for source_ip, count in sorted(failed_password_sources.items()):
        if count >= FAILED_PASSWORD_THRESHOLD:
            findings.append({
                "finding": "Possible brute-force login attempt",
                "source_ip": source_ip,
                "failed_attempts": count,
                "candidate_mitre_technique": "T1110",
                "severity": "High",
                "detection_type": "Signature-based",
                "evidence": f"{count} failed password events were detected from {source_ip}.",
                "detection_rule": f"At least {FAILED_PASSWORD_THRESHOLD} failed password events from same IP."
            })
    return findings


def create_isolation_forest_findings(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 5:
        return []

    ip_stats = defaultdict(lambda: {"total": 0, "failed_pwd": 0, "total_len": 0})
    for line in lines:
        ip = extract_source_ip(line)
        if ip == "unknown":
            continue
        ip_stats[ip]["total"] += 1
        ip_stats[ip]["total_len"] += len(line)
        if "failed password" in line.lower():
            ip_stats[ip]["failed_pwd"] += 1

    ips = list(ip_stats.keys())
    if len(ips) < 3:
        return []

    X = []
    for ip in ips:
        stats = ip_stats[ip]
        avg_len = stats["total_len"] / stats["total"] if stats["total"] > 0 else 0
        X.append([stats["total"], stats["failed_pwd"], avg_len])

    X_arr = np.array(X)
    contamination = min(0.25, max(0.05, 1.0 / len(ips)))
    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(X_arr)
    scores = model.decision_function(X_arr)

    findings: list[dict[str, Any]] = []
    for idx, ip in enumerate(ips):
        if predictions[idx] == -1:
            findings.append({
                "finding": "Behavioral statistical anomaly detected",
                "source_ip": ip,
                "anomaly_score": round(float(scores[idx]), 4),
                "candidate_mitre_technique": "T1078",
                "severity": "Medium-High",
                "detection_type": "Anomaly-based (Isolation Forest)",
                "evidence": f"IP {ip} outlier: Volume={X_arr[idx][0]}, FailedAuth={X_arr[idx][1]}, AvgLen={round(X_arr[idx][2], 1)}",
                "detection_rule": "Isolation Forest multivariate outlier detection.",
                "mitre_lookup_status": "Requires Analyst Review (Uncertainty / Heuristic Mapping)"
            })
    return findings


def enrich_findings_with_mitre(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []
    for finding in findings:
        candidate_id = finding.get("candidate_mitre_technique")
        technique = mitre_index.get(str(candidate_id))
        item = dict(finding)
        item["mitre_technique"] = candidate_id

        if technique:
            item["mitre_name"] = technique.get("name")
            item["mitre_tactics"] = technique.get("tactics", [])
            item["tactic"] = ", ".join(technique.get("tactics", []))
            item["mitre_url"] = technique.get("url")
            item["mitre_stix_id"] = technique.get("stix_id")
            if "mitre_lookup_status" not in item:
                item["mitre_lookup_status"] = "Resolved from STIX"
        else:
            item["mitre_name"] = "Unknown"
            item["mitre_tactics"] = []
            item["tactic"] = ""
            item["mitre_url"] = None
            item["mitre_stix_id"] = None
            item["mitre_lookup_status"] = "Technique not found in STIX"
        enriched.append(item)
    return enriched


def extract_operational_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    sig_count = sum(1 for f in findings if f.get("detection_type") == "Signature-based")
    ml_count = sum(1 for f in findings if "Isolation Forest" in f.get("detection_type", ""))
    high_sev = sum(1 for f in findings if f.get("severity") == "High")
    med_sev = sum(1 for f in findings if "Medium" in f.get("severity", ""))

    return {
        "total_active_findings": len(findings),
        "signature_detections": sig_count,
        "anomaly_detections": ml_count,
        "high_severity_count": high_sev,
        "medium_severity_count": med_sev,
        "pipeline_status": "Operational (Real-time Evaluation via evaluator.py)"
    }


def save_findings(findings: list[dict[str, Any]], summary_dict: dict[str, Any]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_interval_seconds": SCAN_INTERVAL_SECONDS,
        "failed_password_threshold": FAILED_PASSWORD_THRESHOLD,
        "finding_count": len(findings),
        "mitre_knowledge": {
            "source_file": mitre_source_path.name if mitre_source_path else None,
            "technique_count": len(mitre_index),
            "loaded_at": mitre_loaded_at,
            "status": "Loaded" if mitre_source_path else "Not available",
        },
        "findings": findings,
        "operational_summary": summary_dict,
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    print("HYBRID SOC DETECTOR ENGINE STARTED", flush=True)
    while running:
        refresh_mitre_index()
        try:
            rule_candidates = create_candidate_findings(LOG_PATH)
            ml_candidates = create_isolation_forest_findings(LOG_PATH)
            candidates = rule_candidates + ml_candidates
            findings = enrich_findings_with_mitre(candidates)

            summary_dict = extract_operational_summary(findings)
            save_findings(findings, summary_dict)

            print(f"Scan complete: {len(findings)} finding(s).", flush=True)
        except Exception as exc:
            print(f"Scan error: {exc}", flush=True)

        for _ in range(SCAN_INTERVAL_SECONDS):
            if not running:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
