#!/usr/bin/env python3
import json
import sys
import argparse
import math
import os
from datetime import datetime

def calculate_risk_score(vulnerabilities, context=None):
    """Calcule un score de risque global à partir des vulnérabilités détectées et du contexte"""
    score = 0
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}

    for vuln in vulnerabilities:
        level = vuln.get("severity", "").lower()
        score += weights.get(level, 0)

    # Ajustement selon le contexte applicatif
    if context:
        exposure = context.get("exposure", "internal")
        sensitivity = context.get("data_sensitivity", "low")
        impact = context.get("business_impact", "low")

        exposure_factor = {"internal": 1.0, "public": 1.5}.get(exposure, 1.0)
        sensitivity_factor = {"low": 1.0, "confidential": 1.5, "high": 2.0}.get(sensitivity, 1.0)
        impact_factor = {"low": 1.0, "medium": 1.3, "high": 1.7}.get(impact, 1.0)

        score *= exposure_factor * sensitivity_factor * impact_factor

    return min(100, round(score, 2))

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

def load_app_context(file_path):
    """Charge le contexte applicatif si fourni"""
    if not file_path or not os.path.exists(file_path):
        return {}
    with open(file_path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def generate_risk_report(sast, sca, dast, container, context):
    """Génère un rapport de risque consolidé"""
    vulnerabilities = sast + sca + dast + container
    total = len(vulnerabilities)
    risk_score = calculate_risk_score(vulnerabilities, context)
    risk_level = determine_risk_level(risk_score)

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_vulnerabilities": total,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "context": context,
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
    parser.add_argument("--app-context", help="Fichier JSON décrivant le contexte applicatif")
    parser.add_argument("--output", default="risk-report.json", help="Fichier de sortie")

    args = parser.parse_args()

    sast = load_vulnerability_report(args.sast)
    sca = load_vulnerability_report(args.sca)
    dast = load_vulnerability_report(args.dast)
    container = load_vulnerability_report(args.container)
    context = load_app_context(args.app_context)

    report = generate_risk_report(sast, sca, dast, container, context)
    save_report(report, args.output)

    print(f"✅ Rapport de risque généré : {args.output}")
    print(f"Niveau de risque : {report['risk_level']}")
    print(f"Score : {report['risk_score']}")
