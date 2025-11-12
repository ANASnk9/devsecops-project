#!/bin/bash
echo "🧪 TEST POLL SCM"
echo "================"

echo "1. Création fichier test..."
echo "# Test Poll SCM - $(date)" > POLL_SCM_TEST.md

echo "2. Push vers GitHub..."
git add .
git commit -m "Test Poll SCM Jenkins"
git push origin main

echo ""
echo "3. ⏳ ATTENTION :"
echo "   - Jenkins va détecter le changement dans les 2 MINUTES MAX"
echo "   - Le pipeline DevSecOps va démarrer AUTOMATIQUEMENT"
echo "   - Observez Jenkins pendant 2 minutes !"
echo ""
echo "🎯 RÉSULTAT ATTENDU :"
echo "   - Jenkins → Build History → Nouveau build en cours"
echo "   - Votre pipeline de 14 étapes s'exécute"
echo "   - Tous les outils de sécurité fonctionnent"
