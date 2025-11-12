#!/usr/bin/env python3
import json
import sys
import argparse
import math
from datetime import datetime

def calculate_risk_score(vulnerabilities):
    """Calcule un score de risque global à partir des vulnérabilités détectées"""
    score = 0
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}

    for vuln in vulnerabilities:
        level = vuln.get("severity", "").lower()
        score += weights.get(level, 0)

    return min(100, score)

def determine_risk_level(score):
    """Retourne le niveau de risque en fonction du score"""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"

def load_vulnerability_report(file_path):
    """Charge un rapport JSON de vulnérabilités"""
    if not file_path or not os.path.exists(file_path):
        return []
    with open(file_path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def generate_risk_report(sast, sca, dast, container):
    """Génère un rapport de risque consolidé"""
    vulnerabilities = sast + sca + dast + container
    total = len(vulnerabilities)
    risk_score = calculate_risk_score(vulnerabilities)
    risk_level = determine_risk_level(risk_score)

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_vulnerabilities": total,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "details": vulnerabilities
    }
    return report

def save_report(report, output_file):
    """Enregistre le rapport dans un fichier JSON"""
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Évaluation du risque DevSecOps consolidé")
    parser.add_argument("--sast", help="Rapport SAST (fichier JSON)")
    parser.add_argument("--sca", help="Rapport SCA (fichier JSON)")
    parser.add_argument("--dast", help="Rapport DAST (fichier JSON)")
    parser.add_argument("--container", help="Rapport Container (fichier JSON)")
    parser.add_argument("--output", default="risk-report.json", help="Fichier de sortie")

    args = parser.parse_args()

    sast = load_vulnerability_report(args.sast)
    sca = load_vulnerability_report(args.sca)
    dast = load_vulnerability_report(args.dast)
    container = load_vulnerability_report(args.container)

    report = generate_risk_report(sast, sca, dast, container)
    save_report(report, args.output)

    print(f"✅ Rapport de risque généré : {args.output}")
