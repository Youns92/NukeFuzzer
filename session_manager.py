#!/usr/bin/env python3
"""
Module de gestion de sessions et requêtes HTTP avancées pour NukeFuzzer v2.0
"""

import requests
import asyncio
import random
import time
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
from concurrent.futures import ThreadPoolExecutor

@dataclass
class RequestResult:
    """Résultat d'une requête HTTP"""
    url: str
    method: str
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    response_time: float
    payload: str
    vulnerable: bool = False
    vulnerability_type: str = None
    confidence: float = 0.0
    evidence: List[str] = None

class AdvancedHTTPClient:
    """Client HTTP avancé avec gestion de sessions et évasion"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        
        # Configuration des retry
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers par défaut
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Rate limiting
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('requests_per_second', 10),
            burst_size=self.config.get('burst_size', 50)
        )
        
        # Proxies
        self.proxies = self.config.get('proxies', [])
        self.proxy_index = 0
        
        # Session cookies
        self.session_cookies = {}
        
        # Authentication
        self.auth_headers = {}
        
    def rotate_user_agent(self):
        """Rotation du User-Agent"""
        self.session.headers['User-Agent'] = random.choice(self.user_agents)
    
    def rotate_proxy(self):
        """Rotation du proxy"""
        if self.proxies:
            proxy = self.proxies[self.proxy_index % len(self.proxies)]
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.proxy_index += 1
    
    def add_custom_headers(self, headers: Dict[str, str]):
        """Ajoute des headers personnalisés"""
        self.session.headers.update(headers)
    
    def set_authentication(self, auth_type: str, credentials: Dict[str, str]):
        """Configure l'authentification"""
        if auth_type == 'basic':
            from requests.auth import HTTPBasicAuth
            self.session.auth = HTTPBasicAuth(credentials['username'], credentials['password'])
        elif auth_type == 'bearer':
            self.auth_headers['Authorization'] = f"Bearer {credentials['token']}"
        elif auth_type == 'api_key':
            self.auth_headers[credentials['header_name']] = credentials['api_key']
        elif auth_type == 'cookie':
            self.session_cookies.update(credentials)
    
    def make_request(self, method: str, url: str, **kwargs) -> RequestResult:
        """Effectue une requête HTTP avec gestion des erreurs"""
        start_time = time.time()
        
        # Rate limiting
        self.rate_limiter.wait()
        
        # Rotation User-Agent
        if self.config.get('rotate_user_agents', True):
            self.rotate_user_agent()
        
        # Rotation proxy
        if self.config.get('rotate_proxies', False):
            self.rotate_proxy()
        
        # Ajout des headers d'authentification
        if self.auth_headers:
            kwargs.setdefault('headers', {}).update(self.auth_headers)
        
        # Ajout des cookies de session
        if self.session_cookies:
            kwargs.setdefault('cookies', {}).update(self.session_cookies)
        
        # Paramètres par défaut
        kwargs.setdefault('timeout', self.config.get('timeout', 15))
        kwargs.setdefault('allow_redirects', self.config.get('follow_redirects', True))
        kwargs.setdefault('verify', self.config.get('verify_ssl', False))
        
        try:
            response = self.session.request(method, url, **kwargs)
            response_time = time.time() - start_time
            
            # Mise à jour des cookies de session
            self.session_cookies.update(response.cookies)
            
            return RequestResult(
                url=url,
                method=method,
                status_code=response.status_code,
                response_body=response.text,
                response_headers=dict(response.headers),
                response_time=response_time,
                payload=kwargs.get('data', '') or kwargs.get('params', '')
            )
        
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return RequestResult(
                url=url,
                method=method,
                status_code=0,
                response_body=str(e),
                response_headers={},
                response_time=response_time,
                payload=kwargs.get('data', '') or kwargs.get('params', '')
            )
    
    def test_xss_payload(self, url: str, payload: str, method: str = 'GET') -> RequestResult:
        """Test un payload XSS sur une URL"""
        if method.upper() == 'GET':
            # Injection dans les paramètres GET
            if '?' in url:
                test_url = self.inject_payload_in_url(url, payload)
                return self.make_request('GET', test_url)
            else:
                return self.make_request('GET', url, params={'xss': payload})
        
        elif method.upper() == 'POST':
            # Injection dans les données POST
            return self.make_request('POST', url, data={'xss': payload})
        
        elif method.upper() == 'PUT':
            # Injection dans les données PUT
            return self.make_request('PUT', url, data={'xss': payload})
        
        elif method.upper() == 'DELETE':
            # Injection dans les données DELETE
            return self.make_request('DELETE', url, data={'xss': payload})
        
        else:
            return self.make_request(method, url, data={'xss': payload})
    
    def inject_payload_in_url(self, url: str, payload: str) -> str:
        """Injecte un payload dans tous les paramètres d'une URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Injection dans tous les paramètres
            for key in params:
                params[key] = [payload]
            
            # S'il n'y a pas de paramètres, on en ajoute un
            if not params:
                params['xss'] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            new_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            return new_url
        except Exception:
            return url
    
    def test_multiple_parameters(self, url: str, payload: str) -> List[RequestResult]:
        """Test le payload sur plusieurs paramètres"""
        results = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Test de chaque paramètre individuellement
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                result = self.make_request('GET', test_url)
                result.payload = f"{param_name}={payload}"
                results.append(result)
            
            # Test de tous les paramètres à la fois
            if params:
                all_params = {key: payload for key in params}
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urllib.parse.urlencode(all_params), parsed.fragment
                ))
                
                result = self.make_request('GET', test_url)
                result.payload = f"all_params={payload}"
                results.append(result)
        
        except Exception:
            # Fallback: test basique
            result = self.test_xss_payload(url, payload)
            results.append(result)
        
        return results
    
    def test_headers_injection(self, url: str, payload: str) -> List[RequestResult]:
        """Test l'injection dans les headers HTTP"""
        results = []
        
        # Headers couramment testés
        test_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Client-IP',
            'User-Agent',
            'Referer',
            'X-Forwarded-Host',
            'X-Forwarded-Proto',
            'X-Requested-With',
            'Accept',
            'Accept-Language',
            'Accept-Encoding',
            'Cookie'
        ]
        
        for header in test_headers:
            custom_headers = {header: payload}
            
            result = self.make_request('GET', url, headers=custom_headers)
            result.payload = f"Header:{header}={payload}"
            results.append(result)
        
        return results
    
    def test_cookies_injection(self, url: str, payload: str) -> List[RequestResult]:
        """Test l'injection dans les cookies"""
        results = []
        
        # Cookies couramment testés
        test_cookies = [
            'session', 'sessionid', 'token', 'auth', 'user',
            'id', 'username', 'email', 'role', 'admin',
            'csrf_token', 'xss_test', 'payload'
        ]
        
        for cookie_name in test_cookies:
            custom_cookies = {cookie_name: payload}
            
            result = self.make_request('GET', url, cookies=custom_cookies)
            result.payload = f"Cookie:{cookie_name}={payload}"
            results.append(result)
        
        return results
    
    def test_json_injection(self, url: str, payload: str) -> List[RequestResult]:
        """Test l'injection dans les données JSON"""
        results = []
        
        # Structures JSON courantes
        json_structures = [
            {'xss': payload},
            {'data': payload},
            {'content': payload},
            {'message': payload},
            {'value': payload},
            {'input': payload},
            {'search': payload},
            {'query': payload},
            {'name': payload},
            {'email': payload},
            {'comment': payload},
            {'feedback': payload}
        ]
        
        for json_data in json_structures:
            headers = {'Content-Type': 'application/json'}
            
            result = self.make_request('POST', url, 
                                     json=json_data, 
                                     headers=headers)
            result.payload = f"JSON:{json.dumps(json_data)}"
            results.append(result)
        
        return results
    
    def comprehensive_xss_test(self, url: str, payload: str) -> List[RequestResult]:
        """Test XSS complet sur une URL"""
        results = []
        
        # Test GET parameters
        results.extend(self.test_multiple_parameters(url, payload))
        
        # Test POST data
        result = self.test_xss_payload(url, payload, 'POST')
        results.append(result)
        
        # Test PUT data
        result = self.test_xss_payload(url, payload, 'PUT')
        results.append(result)
        
        # Test headers injection
        results.extend(self.test_headers_injection(url, payload))
        
        # Test cookies injection
        results.extend(self.test_cookies_injection(url, payload))
        
        # Test JSON injection
        results.extend(self.test_json_injection(url, payload))
        
        return results


class RateLimiter:
    """Gestionnaire de limitation de taux"""
    
    def __init__(self, requests_per_second: int = 10, burst_size: int = 50):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def wait(self):
        """Attend si nécessaire pour respecter le rate limit"""
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Ajout de tokens basé sur le temps écoulé
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.requests_per_second
            )
            
            self.last_update = now
            
            if self.tokens < 1:
                # Calcul du temps d'attente nécessaire
                sleep_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class SessionManager:
    """Gestionnaire de sessions pour maintenir l'état"""
    
    def __init__(self):
        self.sessions = {}
        self.session_data = {}
    
    def create_session(self, domain: str) -> AdvancedHTTPClient:
        """Crée une nouvelle session pour un domaine"""
        if domain not in self.sessions:
            self.sessions[domain] = AdvancedHTTPClient()
            self.session_data[domain] = {
                'cookies': {},
                'headers': {},
                'auth': None,
                'created_at': time.time()
            }
        
        return self.sessions[domain]
    
    def get_session(self, domain: str) -> Optional[AdvancedHTTPClient]:
        """Récupère une session existante"""
        return self.sessions.get(domain)
    
    def update_session_data(self, domain: str, cookies: Dict[str, str] = None, 
                           headers: Dict[str, str] = None):
        """Met à jour les données de session"""
        if domain in self.session_data:
            if cookies:
                self.session_data[domain]['cookies'].update(cookies)
            if headers:
                self.session_data[domain]['headers'].update(headers)
    
    def authenticate_session(self, domain: str, auth_type: str, credentials: Dict[str, str]):
        """Authentifie une session"""
        session = self.get_session(domain)
        if session:
            session.set_authentication(auth_type, credentials)
            self.session_data[domain]['auth'] = {
                'type': auth_type,
                'credentials': credentials
            }
    
    def cleanup_old_sessions(self, max_age: int = 3600):
        """Nettoie les sessions anciennes"""
        now = time.time()
        domains_to_remove = []
        
        for domain, data in self.session_data.items():
            if now - data['created_at'] > max_age:
                domains_to_remove.append(domain)
        
        for domain in domains_to_remove:
            del self.sessions[domain]
            del self.session_data[domain]


class AdvancedXSSScanner:
    """Scanner XSS avancé avec gestion de sessions"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session_manager = SessionManager()
        self.results = []
        self.thread_pool = ThreadPoolExecutor(max_workers=self.config.get('max_workers', 20))
        
        # Import des modules avancés
        try:
            from advanced_payloads import AdvancedXSSPayloads
            from advanced_techniques import AdvancedTechniques
            self.payload_generator = AdvancedXSSPayloads()
            self.techniques = AdvancedTechniques()
        except ImportError:
            self.payload_generator = None
            self.techniques = None
    
    def scan_url(self, url: str, payloads: List[str] = None) -> List[RequestResult]:
        """Scan une URL avec des payloads XSS"""
        domain = urllib.parse.urlparse(url).netloc
        session = self.session_manager.create_session(domain)
        
        if payloads is None:
            if self.payload_generator:
                payloads = self.payload_generator.generate_all_payloads(50)
            else:
                payloads = [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '"><script>alert("XSS")</script>',
                    '\';alert("XSS");//'
                ]
        
        results = []
        
        for payload in payloads:
            try:
                # Test complet avec tous les vecteurs d'injection
                test_results = session.comprehensive_xss_test(url, payload)
                
                # Analyse des résultats
                for result in test_results:
                    if self.techniques:
                        analysis = self.techniques.analyze_response_for_xss(
                            result.response_body, payload
                        )
                        result.vulnerable = analysis['potential_xss']
                        result.vulnerability_type = analysis['xss_type']
                        result.confidence = analysis['confidence']
                        result.evidence = analysis['evidence']
                    else:
                        # Analyse basique
                        result.vulnerable = payload in result.response_body
                        result.confidence = 50 if result.vulnerable else 0
                
                results.extend(test_results)
            
            except Exception as e:
                print(f"Erreur lors du test de {url} avec {payload}: {e}")
                continue
        
        return results
    
    def scan_urls_parallel(self, urls: List[str], payloads: List[str] = None) -> List[RequestResult]:
        """Scan multiple URLs en parallèle"""
        futures = []
        
        for url in urls:
            future = self.thread_pool.submit(self.scan_url, url, payloads)
            futures.append(future)
        
        all_results = []
        for future in futures:
            try:
                results = future.result(timeout=300)  # 5 minutes timeout
                all_results.extend(results)
            except Exception as e:
                print(f"Erreur lors du scan parallèle: {e}")
                continue
        
        return all_results
    
    def generate_report(self, results: List[RequestResult]) -> Dict[str, Any]:
        """Génère un rapport des résultats"""
        vulnerable_results = [r for r in results if r.vulnerable]
        
        report = {
            'total_requests': len(results),
            'vulnerable_requests': len(vulnerable_results),
            'vulnerability_rate': len(vulnerable_results) / len(results) * 100 if results else 0,
            'vulnerabilities_by_type': {},
            'high_confidence_vulnerabilities': [],
            'medium_confidence_vulnerabilities': [],
            'low_confidence_vulnerabilities': []
        }
        
        for result in vulnerable_results:
            # Comptage par type
            vuln_type = result.vulnerability_type or 'unknown'
            if vuln_type not in report['vulnerabilities_by_type']:
                report['vulnerabilities_by_type'][vuln_type] = 0
            report['vulnerabilities_by_type'][vuln_type] += 1
            
            # Classification par confiance
            if result.confidence >= 80:
                report['high_confidence_vulnerabilities'].append(result)
            elif result.confidence >= 50:
                report['medium_confidence_vulnerabilities'].append(result)
            else:
                report['low_confidence_vulnerabilities'].append(result)
        
        return report


# Instance globale
session_manager = SessionManager()

# Fonctions utilitaires
def create_http_client(config: Dict[str, Any] = None) -> AdvancedHTTPClient:
    """Crée un client HTTP avancé"""
    return AdvancedHTTPClient(config)

def scan_xss_advanced(urls: List[str], payloads: List[str] = None, 
                     config: Dict[str, Any] = None) -> List[RequestResult]:
    """Fonction utilitaire pour scanner XSS avancé"""
    scanner = AdvancedXSSScanner(config)
    return scanner.scan_urls_parallel(urls, payloads)


if __name__ == "__main__":
    # Test du module
    print("=== Test du module de gestion de sessions ===")
    
    # Test du client HTTP
    client = create_http_client({
        'requests_per_second': 5,
        'timeout': 10,
        'rotate_user_agents': True
    })
    
    print("✓ Client HTTP créé")
    
    # Test du rate limiter
    limiter = RateLimiter(requests_per_second=2, burst_size=5)
    print("✓ Rate limiter créé")
    
    # Test du gestionnaire de sessions
    manager = SessionManager()
    session = manager.create_session('example.com')
    print("✓ Session créée")
    
    # Test du scanner
    scanner = AdvancedXSSScanner({
        'max_workers': 5,
        'timeout': 10
    })
    print("✓ Scanner XSS avancé créé")
    
    print("\nTous les tests réussis!")