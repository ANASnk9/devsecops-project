#!/bin/bash
echo "🧪 TEST DE CORRECTION"
echo "===================="

echo "1. Création fichier test..."
echo "# Test Correction Webhook - $(date)" > WEBHOOK_FIX_TEST.md

echo "2. Push vers GitHub..."
git add .
git commit -m "Test correction webhook 404"
git push origin main

echo ""
echo "3. VÉRIFICATION :"
echo "   - GitHub: Dernier delivery devrait être 200 OK"
echo "   - Ngrok: Requêtes POST sans erreur"
echo "   - Jenkins: Build automatique démarré"
echo ""
echo "⏳ Attendez et vérifiez GitHub Webhook deliveries..."
