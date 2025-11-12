#!/bin/bash
echo "🎯 DÉMO INTÉGRATION COMPLÈTE"
echo "============================="

echo "📝 Création fichier de test..."
echo "# Test Live - $(date)" > LIVE_DEMO.md

echo "📤 Push vers GitHub..."
git add .
git commit -m "Démo live intégration DevSecOps"
git push origin main

echo ""
echo "✅ Déclenchement réussi !"
echo "👀 Observez :"
echo "   - Ngrok: requêtes webhook"
echo "   - Jenkins: build automatique"
echo "   - Pipeline: sécurité en action"
