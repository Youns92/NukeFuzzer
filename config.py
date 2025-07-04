#!/usr/bin/env python3
"""
Configuration avancée pour NukeFuzzer v2.0
"""

import os
import json

class AdvancedConfig:
    """Configuration avancée pour NukeFuzzer"""
    
    def __init__(self):
        self.config = {
            # Configuration générale
            "general": {
                "max_workers": 100,
                "timeout": 30,
                "retry_count": 3,
                "delay_range": [1, 5],
                "verbose": True,
                "save_all_results": True,
                "auto_cleanup": True
            },
            
            # Configuration de découverte
            "discovery": {
                "use_multiple_sources": True,
                "subdomain_sources": [
                    "subfinder",
                    "assetfinder", 
                    "amass",
                    "findomain",
                    "crt.sh"
                ],
                "endpoint_sources": [
                    "gau",
                    "waybackurls",
                    "katana",
                    "hakrawler",
                    "gospider",
                    "linkfinder"
                ],
                "max_subdomains": 1000,
                "max_endpoints": 10000,
                "depth": 3,
                "include_js_analysis": True,
                "include_api_discovery": True
            },
            
            # Configuration XSS
            "xss": {
                "use_advanced_payloads": True,
                "use_blind_xss": True,
                "use_dom_xss": True,
                "use_stored_xss": True,
                "context_aware_testing": True,
                "waf_bypass_techniques": [
                    "case_variation",
                    "encoding_variation",
                    "character_substitution",
                    "javascript_obfuscation",
                    "polyglot_payloads",
                    "event_handler_variation",
                    "protocol_variation",
                    "filter_evasion"
                ],
                "payload_count": 100,
                "test_all_parameters": True,
                "test_headers": True,
                "test_cookies": True,
                "test_post_data": True
            },
            
            # Configuration WAF bypass
            "waf_bypass": {
                "rotate_user_agents": True,
                "use_proxy_rotation": False,
                "proxy_list": [],
                "use_custom_headers": True,
                "custom_headers": {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1", 
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1"
                },
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_second": 10,
                    "burst_size": 50,
                    "backoff_factor": 1.5
                }
            },
            
            # User agents pour rotation
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
            ],
            
            # Configuration des outils
            "tools": {
                "subfinder": {
                    "threads": 100,
                    "timeout": 30,
                    "sources": "all",
                    "recursive": True
                },
                "httpx": {
                    "threads": 200,
                    "timeout": 15,
                    "retries": 3,
                    "status_codes": [200, 201, 202, 301, 302, 303, 307, 308, 400, 401, 403, 405, 500, 502, 503],
                    "follow_redirects": True,
                    "random_agent": True
                },
                "gau": {
                    "threads": 50,
                    "timeout": 10,
                    "providers": "wayback,commoncrawl,otx,urlscan",
                    "blacklist": "ttf,woff,woff2,eot,css,png,jpg,jpeg,gif,svg,ico,pdf,doc,docx,xls,xlsx,ppt,pptx"
                },
                "katana": {
                    "depth": 3,
                    "js_crawling": True,
                    "headless": True,
                    "timeout": 10,
                    "concurrency": 20
                },
                "dalfox": {
                    "workers": 100,
                    "timeout": 15,
                    "delay": 1000,
                    "waf_evasion": True,
                    "blind_testing": True,
                    "dom_testing": True,
                    "follow_redirects": True,
                    "mining_dom": True,
                    "mining_dict": True,
                    "sequence": 5
                }
            },
            
            # Configuration du reporting
            "reporting": {
                "generate_json": True,
                "generate_html": True,
                "generate_csv": True,
                "include_screenshots": False,
                "include_poc": True,
                "severity_classification": True,
                "false_positive_filtering": True
            },
            
            # Blind XSS configuration
            "blind_xss": {
                "enabled": True,
                "callback_domain": "burpcollaborator.net",
                "polling_interval": 10,
                "max_wait_time": 300,
                "payload_variations": 20
            },
            
            # Filtres et exclusions
            "filters": {
                "exclude_extensions": [
                    "css", "js", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2", 
                    "ttf", "eot", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", 
                    "rar", "7z", "tar", "gz", "mp4", "avi", "mov", "wmv", "mp3", "wav", "flac"
                ],
                "exclude_patterns": [
                    r".*logout.*",
                    r".*signout.*",
                    r".*exit.*",
                    r".*delete.*",
                    r".*remove.*"
                ],
                "include_patterns": [
                    r".*search.*",
                    r".*comment.*",
                    r".*feedback.*",
                    r".*contact.*",
                    r".*redirect.*",
                    r".*url.*",
                    r".*callback.*",
                    r".*jsonp.*",
                    r".*api.*",
                    r".*ajax.*"
                ]
            },
            
            # Configuration de performance
            "performance": {
                "max_concurrent_requests": 50,
                "connection_pool_size": 100,
                "keep_alive": True,
                "compression": True,
                "timeout_scaling": True,
                "memory_limit": "2GB",
                "disk_usage_limit": "5GB"
            }
        }
    
    def load_config(self, config_file=None):
        """Charge la configuration depuis un fichier JSON"""
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    self.merge_config(file_config)
                    return True
            except Exception as e:
                print(f"Erreur lors du chargement de la configuration: {e}")
                return False
        return False
    
    def save_config(self, config_file="nukefuzzer_config.json"):
        """Sauvegarde la configuration actuelle"""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def merge_config(self, new_config):
        """Fusionne une nouvelle configuration avec l'existante"""
        def merge_dict(target, source):
            for key, value in source.items():
                if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                    merge_dict(target[key], value)
                else:
                    target[key] = value
        
        merge_dict(self.config, new_config)
    
    def get(self, key_path, default=None):
        """Récupère une valeur de configuration avec notation pointée"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path, value):
        """Définit une valeur de configuration avec notation pointée"""
        keys = key_path.split('.')
        target = self.config
        
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        
        target[keys[-1]] = value
    
    def get_tool_config(self, tool_name):
        """Récupère la configuration d'un outil spécifique"""
        return self.get(f"tools.{tool_name}", {})
    
    def is_enabled(self, feature_path):
        """Vérifie si une fonctionnalité est activée"""
        return self.get(feature_path, False)
    
    def get_user_agent(self):
        """Récupère un User-Agent aléatoire"""
        import random
        return random.choice(self.config["user_agents"])
    
    def get_waf_bypass_techniques(self):
        """Récupère les techniques de bypass WAF activées"""
        return self.get("xss.waf_bypass_techniques", [])
    
    def get_payload_count(self):
        """Récupère le nombre de payloads à utiliser"""
        return self.get("xss.payload_count", 50)
    
    def should_rotate_user_agents(self):
        """Vérifie si la rotation des User-Agents est activée"""
        return self.get("waf_bypass.rotate_user_agents", True)
    
    def get_rate_limit_config(self):
        """Récupère la configuration du rate limiting"""
        return self.get("waf_bypass.rate_limiting", {})
    
    def get_custom_headers(self):
        """Récupère les headers personnalisés"""
        return self.get("waf_bypass.custom_headers", {})
    
    def validate_config(self):
        """Valide la configuration actuelle"""
        errors = []
        
        # Vérification des valeurs numériques
        numeric_checks = [
            ("general.max_workers", 1, 1000),
            ("general.timeout", 1, 300),
            ("general.retry_count", 0, 10),
            ("discovery.max_subdomains", 1, 10000),
            ("discovery.max_endpoints", 1, 100000),
            ("xss.payload_count", 1, 1000)
        ]
        
        for path, min_val, max_val in numeric_checks:
            value = self.get(path)
            if value is not None and not (min_val <= value <= max_val):
                errors.append(f"{path}: valeur {value} hors limites [{min_val}, {max_val}]")
        
        # Vérification des listes
        list_checks = [
            "discovery.subdomain_sources",
            "discovery.endpoint_sources", 
            "xss.waf_bypass_techniques",
            "user_agents"
        ]
        
        for path in list_checks:
            value = self.get(path)
            if value is not None and not isinstance(value, list):
                errors.append(f"{path}: doit être une liste")
        
        return errors
    
    def create_default_config_file(self, filename="nukefuzzer_config.json"):
        """Crée un fichier de configuration par défaut"""
        return self.save_config(filename)
    
    def print_config(self):
        """Affiche la configuration actuelle"""
        print(json.dumps(self.config, indent=2))


# Instance globale de configuration
config = AdvancedConfig()

# Fonction utilitaire pour charger une configuration personnalisée
def load_advanced_config(config_file=None):
    """Charge une configuration avancée"""
    global config
    if config_file:
        config.load_config(config_file)
    return config

# Fonction pour créer une configuration par défaut
def create_default_config():
    """Crée un fichier de configuration par défaut"""
    config.create_default_config_file()
    print("Configuration par défaut créée: nukefuzzer_config.json")


if __name__ == "__main__":
    # Test de la configuration
    print("=== Test de la configuration avancée ===")
    
    # Affichage de quelques valeurs
    print(f"Max workers: {config.get('general.max_workers')}")
    print(f"Timeout: {config.get('general.timeout')}")
    print(f"XSS payload count: {config.get('xss.payload_count')}")
    print(f"User agents count: {len(config.get('user_agents', []))}")
    
    # Test de validation
    errors = config.validate_config()
    if errors:
        print(f"\nErreurs de configuration: {errors}")
    else:
        print("\nConfiguration valide!")
    
    # Création d'un fichier de configuration par défaut
    create_default_config()