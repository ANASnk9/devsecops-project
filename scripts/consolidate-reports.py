#!/usr/bin/env python3
"""
Script de consolidation des rapports de sécurité DevSecOps
Consolide les rapports SAST, SCA, DAST en un dashboard unique
"""

import json
import argparse
import os
from datetime import datetime

def generate_security_dashboard(sast_data, sca_data, dast_data, container_data):
    """Génère un dashboard de sécurité consolidé"""

    dashboard = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "sast": {"vulnerabilities": len(sast_data), "critical": sum(1 for v in sast_data if v.get('severity') == 'CRITICAL'), "high": sum(1 for v in sast_data if v.get('severity') == 'HIGH')},
            "sca": {"vulnerabilities": len(sca_data), "critical": sum(1 for v in sca_data if v.get('severity') == 'CRITICAL'), "high": sum(1 for v in sca_data if v.get('severity') == 'HIGH')},
            "dast": {"vulnerabilities": len(dast_data), "critical": sum(1 for v in dast_data if v.get('severity') == 'CRITICAL'), "high": sum(1 for v in dast_data if v.get('severity') == 'HIGH')},
            "container": {"vulnerabilities": len(container_data), "critical": sum(1 for v in container_data if v.get('severity') == 'CRITICAL'), "high": sum(1 for v in container_data if v.get('severity') == 'HIGH')}
        },
        "compliance_status": "PASS",
        "recommendations": []
    }

    # Générer le HTML du dashboard
    html_content = generate_html_dashboard(dashboard)
    return html_content

def generate_html_dashboard(dashboard):
    """Génère le HTML du dashboard"""
    return f"""
<html>
<head>
    <title>DevSecOps Security Dashboard</title>
</head>
<body>
    <h1>DevSecOps Security Dashboard</h1>
    <p>Generated at: {dashboard['timestamp']}</p>
    <h2>Summary</h2>
    <ul>
        <li>SAST: {dashboard['summary']['sast']['vulnerabilities']} vulnerabilities (Critical: {dashboard['summary']['sast']['critical']}, High: {dashboard['summary']['sast']['high']})</li>
        <li>SCA: {dashboard['summary']['sca']['vulnerabilities']} vulnerabilities (Critical: {dashboard['summary']['sca']['critical']}, High: {dashboard['summary']['sca']['high']})</li>
        <li>DAST: {dashboard['summary']['dast']['vulnerabilities']} vulnerabilities (Critical: {dashboard['summary']['dast']['critical']}, High: {dashboard['summary']['dast']['high']})</li>
        <li>Container: {dashboard['summary']['container']['vulnerabilities']} vulnerabilities (Critical: {dashboard['summary']['container']['critical']}, High: {dashboard['summary']['container']['high']})</li>
    </ul>
</body>
</html>
"""

def load_json_file(file_path):
    """Charge un fichier JSON, retourne une liste vide si le fichier n'existe pas"""
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    return []

def main():
    parser = argparse.ArgumentParser(description="Consolidate DevSecOps security reports into an HTML dashboard")
    parser.add_argument("--sast", default="sast_report.json")
    parser.add_argument("--sca", default="sca_report.json")
    parser.add_argument("--dast", default="dast_report.json")
    parser.add_argument("--container", default="container_report.json")
    parser.add_argument("--output", default="test-dashboard.html")
    args = parser.parse_args()

    sast_data = load_json_file(args.sast)
    sca_data = load_json_file(args.sca)
    dast_data = load_json_file(args.dast)
    container_data = load_json_file(args.container)

    html_dashboard = generate_security_dashboard(sast_data, sca_data, dast_data, container_data)

    with open(args.output, 'w') as f:
        f.write(html_dashboard)

    print(f"✅ Dashboard généré: {args.output}")

if __name__ == "__main__":
    main()
