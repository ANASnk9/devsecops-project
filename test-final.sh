#!/bin/bash
echo "🎯 TEST FINAL AVEC JENKINS ACTIF"
echo "================================"

echo "1. Vérification Jenkins..."
sudo systemctl status jenkins --no-pager -l

echo ""
echo "2. Modification du code..."
echo "# Test Jenkins Actif - $(date)" > JENKINS_TEST.md

echo "3. Push vers GitHub..."
git add .
git commit -m "Test avec Jenkins actif"
git push origin main

echo ""
echo "✅ Test lancé !"
echo "👀 Vérifiez maintenant :"
echo "   - Ngrok: requêtes POST vers /github-webhook/"
echo "   - Jenkins: build automatique démarré"
