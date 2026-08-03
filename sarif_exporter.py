import json
import os
from datetime import datetime

def generate_sarif(findings, repo_name):
    """
    Generate a SARIF v2.1.0 compliant JSON export from PQ-Audit findings.
    Maps high/medium risks to the 'error' level to fail CI/CD pipelines.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PQ-Audit",
                        "informationUri": "https://github.com/MDTahaZaki/PQ-Audit",
                        "rules": [
                            {
                                "id": "PQ-001",
                                "name": "QuantumVulnerablePrimitive",
                                "shortDescription": {
                                    "text": "Identified a classical cryptographic primitive vulnerable to quantum attacks."
                                }
                            },
                            {
                                "id": "PQ-002",
                                "name": "SupplyChainRisk",
                                "shortDescription": {
                                    "text": "Identified a legacy cryptographic dependency lacking PQC support."
                                }
                            }
                        ]
                    }
                },
                "results": []
            }
        ]
    }

    results = []
    for f in findings:
        # Determine severity level
        level = "warning"
        if "High Risk" in f.get("risk", "") or "Medium Risk" in f.get("risk", "") or "Supply Chain" in f.get("risk", ""):
            level = "error"  # Fails CI/CD pipelines

        rule_id = "PQ-002" if "Supply Chain" in f.get("risk", "") else "PQ-001"
        msg_text = f"Found vulnerable primitive/dependency: {f['primitive']}. Risk: {f['risk']}. Recommendation: {f.get('recommendation', 'Upgrade dependency')}."

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": msg_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("file", "unknown")
                        },
                        "region": {
                            "startLine": int(f.get("line", 1))
                        }
                    }
                }
            ]
        }
        results.append(result)

    sarif["runs"][0]["results"] = results

    os.makedirs("reports", exist_ok=True)
    report_path = os.path.join("reports", "results.sarif")
    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(sarif, file, indent=4)
    
    return report_path
