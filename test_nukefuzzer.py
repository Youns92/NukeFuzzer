#!/usr/bin/env python3
"""
Script de test pour NukeFuzzer v2.0 Advanced
Teste toutes les fonctionnalités avancées
"""

import sys
import os
import time
import asyncio
import tempfile
import random
from typing import List, Dict, Any

# Ajout du répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test l'import de tous les modules"""
    print("=== Test des imports ===")
    
    try:
        from advanced_payloads import AdvancedXSSPayloads, get_advanced_xss_payloads
        print("✓ advanced_payloads importé")
        
        from config import load_advanced_config, config, create_default_config
        print("✓ config importé")
        
        from advanced_techniques import AdvancedTechniques, get_waf_bypass_variants
        print("✓ advanced_techniques importé")
        
        from session_manager import AdvancedHTTPClient, SessionManager, AdvancedXSSScanner
        print("✓ session_manager importé")
        
        return True
    except Exception as e:
        print(f"✗ Erreur d'import: {e}")
        return False

def test_payload_generator():
    """Test le générateur de payloads"""
    print("\n=== Test du générateur de payloads ===")
    
    try:
        from advanced_payloads import AdvancedXSSPayloads
        
        generator = AdvancedXSSPayloads()
        
        # Test des payloads basiques
        basic_payloads = generator.basic_payloads
        print(f"✓ {len(basic_payloads)} payloads basiques")
        
        # Test des payloads contextuels
        html_payloads = generator.context_payloads['html']
        print(f"✓ {len(html_payloads)} payloads HTML")
        
        # Test des payloads polyglot
        polyglot_payloads = generator.polyglot_payloads
        print(f"✓ {len(polyglot_payloads)} payloads polyglot")
        
        # Test de génération d'encodages
        test_payload = '<script>alert("XSS")</script>'
        encoded_payloads = generator.generate_encoded_payloads(test_payload)
        print(f"✓ {len(encoded_payloads)} payloads encodés générés")
        
        # Test d'obfuscation
        obfuscated_payloads = generator.generate_obfuscated_payloads(test_payload)
        print(f"✓ {len(obfuscated_payloads)} payloads obfusqués générés")
        
        # Test de génération complète
        all_payloads = generator.generate_all_payloads(50)
        print(f"✓ {len(all_payloads)} payloads totaux générés")
        
        return True
    except Exception as e:
        print(f"✗ Erreur générateur de payloads: {e}")
        return False

def test_configuration():
    """Test le système de configuration"""
    print("\n=== Test de la configuration ===")
    
    try:
        from config import load_advanced_config, create_default_config
        
        # Test de création de configuration par défaut
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        config_file.close()
        
        config = load_advanced_config()
        config.save_config(config_file.name)
        print("✓ Configuration sauvegardée")
        
        # Test de chargement
        config.load_config(config_file.name)
        print("✓ Configuration chargée")
        
        # Test de validation
        errors = config.validate_config()
        if not errors:
            print("✓ Configuration valide")
        else:
            print(f"⚠ Erreurs de configuration: {errors}")
        
        # Test d'accès aux valeurs
        max_workers = config.get('general.max_workers')
        print(f"✓ Max workers: {max_workers}")
        
        user_agent = config.get_user_agent()
        print(f"✓ User agent: {user_agent[:50]}...")
        
        # Nettoyage
        os.unlink(config_file.name)
        
        return True
    except Exception as e:
        print(f"✗ Erreur configuration: {e}")
        return False

def test_advanced_techniques():
    """Test les techniques avancées"""
    print("\n=== Test des techniques avancées ===")
    
    try:
        from advanced_techniques import AdvancedTechniques
        
        techniques = AdvancedTechniques()
        
        # Test d'évasion WAF
        test_payload = '<script>alert("XSS")</script>'
        waf_variants = techniques.waf_evasion.generate_waf_bypass_variants(test_payload, 5)
        print(f"✓ {len(waf_variants)} variantes d'évasion WAF générées")
        
        # Test de détection de contexte
        test_response = '<html><body><input value="USER_INPUT"><script>var x = "USER_INPUT";</script></body></html>'
        analysis = techniques.analyze_response_for_xss(test_response, "USER_INPUT")
        print(f"✓ Analyse de réponse: contexte {analysis['context']}, confiance {analysis['confidence']}%")
        
        # Test de génération de payloads contextuels
        context_payloads = techniques.generate_context_specific_payloads('html', 5)
        print(f"✓ {len(context_payloads)} payloads contextuels générés")
        
        # Test de génération de payloads polyglot
        polyglot_payloads = techniques.generate_polyglot_payloads(3)
        print(f"✓ {len(polyglot_payloads)} payloads polyglot générés")
        
        # Test de détection de faux positifs
        false_positive = techniques.is_likely_false_positive({
            'evidence': ['error page', 'debug info']
        })
        print(f"✓ Détection de faux positifs: {false_positive}")
        
        return True
    except Exception as e:
        print(f"✗ Erreur techniques avancées: {e}")
        return False

def test_session_manager():
    """Test le gestionnaire de sessions"""
    print("\n=== Test du gestionnaire de sessions ===")
    
    try:
        from session_manager import AdvancedHTTPClient, SessionManager, RateLimiter
        
        # Test du client HTTP
        client = AdvancedHTTPClient({
            'requests_per_second': 10,
            'timeout': 5,
            'rotate_user_agents': True
        })
        print("✓ Client HTTP créé")
        
        # Test du rate limiter
        limiter = RateLimiter(requests_per_second=5, burst_size=10)
        print("✓ Rate limiter créé")
        
        # Test du gestionnaire de sessions
        manager = SessionManager()
        session = manager.create_session('example.com')
        print("✓ Session créée")
        
        # Test d'injection de payload dans URL
        test_url = "https://example.com/search?q=test&category=all"
        test_payload = "<script>alert('XSS')</script>"
        injected_url = client.inject_payload_in_url(test_url, test_payload)
        print(f"✓ Injection URL: {injected_url[:80]}...")
        
        return True
    except Exception as e:
        print(f"✗ Erreur gestionnaire de sessions: {e}")
        return False

def test_integration():
    """Test d'intégration des modules"""
    print("\n=== Test d'intégration ===")
    
    try:
        from advanced_payloads import AdvancedXSSPayloads
        from advanced_techniques import AdvancedTechniques
        from session_manager import AdvancedXSSScanner
        
        # Création des composants
        payload_generator = AdvancedXSSPayloads()
        techniques = AdvancedTechniques()
        scanner = AdvancedXSSScanner({
            'max_workers': 3,
            'timeout': 5
        })
        
        print("✓ Composants créés")
        
        # Test de génération et analyse
        payloads = payload_generator.generate_all_payloads(10)
        print(f"✓ {len(payloads)} payloads générés")
        
        # Test d'analyse contextuelle
        for payload in payloads[:3]:
            context = techniques.detect_context("<html><body>TEST</body></html>", "TEST")
            context_payloads = techniques.generate_context_specific_payloads(context, 2)
            print(f"✓ Contexte {context}: {len(context_payloads)} payloads spécifiques")
        
        return True
    except Exception as e:
        print(f"✗ Erreur intégration: {e}")
        return False

def test_main_script():
    """Test le script principal"""
    print("\n=== Test du script principal ===")
    
    try:
        import NukeFuzzer
        print("✓ Script principal importé")
        
        # Test des fonctions utilitaires
        if hasattr(NukeFuzzer, 'generate_advanced_xss_payloads'):
            payloads = NukeFuzzer.generate_advanced_xss_payloads()
            print(f"✓ {len(payloads)} payloads générés depuis le script principal")
        
        if hasattr(NukeFuzzer, 'ADVANCED_MODULES'):
            if NukeFuzzer.ADVANCED_MODULES:
                print("✓ Modules avancés détectés")
            else:
                print("⚠ Modules avancés non détectés")
        
        return True
    except Exception as e:
        print(f"✗ Erreur script principal: {e}")
        return False

def performance_test():
    """Test de performance"""
    print("\n=== Test de performance ===")
    
    try:
        from advanced_payloads import AdvancedXSSPayloads
        from advanced_techniques import AdvancedTechniques
        
        # Test de génération de payloads
        start_time = time.time()
        generator = AdvancedXSSPayloads()
        payloads = generator.generate_all_payloads(100)
        generation_time = time.time() - start_time
        print(f"✓ Génération de {len(payloads)} payloads en {generation_time:.3f}s")
        
        # Test d'analyse
        start_time = time.time()
        techniques = AdvancedTechniques()
        for _ in range(10):
            analysis = techniques.analyze_response_for_xss(
                "<html><body>TEST</body></html>", "TEST"
            )
        analysis_time = time.time() - start_time
        print(f"✓ 10 analyses en {analysis_time:.3f}s")
        
        # Test d'évasion WAF
        start_time = time.time()
        for payload in payloads[:10]:
            variants = techniques.waf_evasion.generate_waf_bypass_variants(payload, 5)
        evasion_time = time.time() - start_time
        print(f"✓ Génération d'évasions WAF en {evasion_time:.3f}s")
        
        return True
    except Exception as e:
        print(f"✗ Erreur test de performance: {e}")
        return False

def demonstration():
    """Démonstration des capacités"""
    print("\n=== Démonstration des capacités ===")
    
    try:
        from advanced_payloads import AdvancedXSSPayloads
        from advanced_techniques import AdvancedTechniques
        
        generator = AdvancedXSSPayloads()
        techniques = AdvancedTechniques()
        
        # Génération de payloads avancés
        print("\n1. Payloads XSS avancés:")
        payloads = generator.generate_all_payloads(5)
        for i, payload in enumerate(payloads, 1):
            print(f"   {i}. {payload}")
        
        # Techniques d'évasion WAF
        print("\n2. Techniques d'évasion WAF:")
        base_payload = '<script>alert("XSS")</script>'
        waf_variants = techniques.waf_evasion.generate_waf_bypass_variants(base_payload, 3)
        for i, variant in enumerate(waf_variants, 1):
            print(f"   {i}. {variant}")
        
        # Payloads contextuels
        print("\n3. Payloads contextuels:")
        contexts = ['html', 'javascript', 'attribute']
        for context in contexts:
            context_payloads = techniques.generate_context_specific_payloads(context, 2)
            print(f"   {context.upper()}: {len(context_payloads)} payloads")
            for payload in context_payloads[:1]:
                print(f"      → {payload}")
        
        # Payloads polyglot
        print("\n4. Payloads polyglot:")
        polyglot_payloads = techniques.generate_polyglot_payloads(2)
        for i, payload in enumerate(polyglot_payloads, 1):
            print(f"   {i}. {payload[:80]}...")
        
        # Blind XSS
        print("\n5. Blind XSS:")
        blind_payloads = generator.generate_blind_xss_payloads("callback.example.com", 2)
        for i, payload in enumerate(blind_payloads, 1):
            print(f"   {i}. {payload[:80]}...")
        
        return True
    except Exception as e:
        print(f"✗ Erreur démonstration: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 NukeFuzzer v2.0 Advanced - Suite de tests")
    print("=" * 50)
    
    tests = [
        ("Imports", test_imports),
        ("Générateur de payloads", test_payload_generator),
        ("Configuration", test_configuration),
        ("Techniques avancées", test_advanced_techniques),
        ("Gestionnaire de sessions", test_session_manager),
        ("Intégration", test_integration),
        ("Script principal", test_main_script),
        ("Performance", performance_test),
        ("Démonstration", demonstration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSÉ")
            else:
                print(f"❌ {test_name}: ÉCHOUÉ")
        except Exception as e:
            print(f"❌ {test_name}: ERREUR - {e}")
    
    print("\n" + "=" * 50)
    print(f"Résultats: {passed}/{total} tests passés")
    
    if passed == total:
        print("🎉 Tous les tests sont passés! NukeFuzzer v2.0 est prêt.")
    else:
        print("⚠️  Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)