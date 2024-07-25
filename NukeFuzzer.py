import subprocess
import os
import asyncio


RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
ASCII_ART = BLUE + """
  _   _       _        ______                      
 | \ | |     | |      |  ____|                     
 |  \| |_   _| | _____| |__ _   _ ___________ _ __ 
 | . ` | | | | |/ / _ \  __| | | |_  /_  / _ \ '__|
 | |\  | |_| |   <  __/ |  | |_| |/ / / /  __/ |   
 |_| \_|\__,_|_|\_\___|_|   \__,_/___/___\___|_|   v1.0
                                     made by Itachii 
""" + RESET
print(ASCII_ART)


async def run_command(command):
    process = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = await process.communicate()
    return_code = process.returncode
    if return_code != 0:
        print(f"Error: {stderr.decode()}")
        return None
    return stdout.decode().strip()


def print_potential_xss(file_path):
    print(MAGENTA + "\nPotentiels XSS trouvés:" + RESET)
    try:
        with open(file_path, 'r') as file:
            for line in file:
                print("XSS potentiel : " + CYAN + line.strip() + RESET)
    except FileNotFoundError:
        print(RED + "Aucune XSS trouvée" + RESET)   


async def main(domain):
    if not domain:
        print("Domaine non spécifié.")
        return
    
    base_report_dir = "report"
    report_dir = os.path.join(base_report_dir, f"report_{domain}")
    os.makedirs(report_dir, exist_ok=True)
    
    subdomains_file = os.path.join(report_dir, "subdomains.txt")
    httpx_output_file = os.path.join(report_dir, "httpx.txt")
    endpoints_file = os.path.join(report_dir, "Endpoints.txt")
    endpoints_filtered_file = os.path.join(report_dir, "Endpoints_F.txt")
    xss_file = os.path.join(report_dir, "XSS.txt")
    xss_ref_file = os.path.join(report_dir, "XSS_Ref.txt")
    xss_filtered = os.path.join(report_dir, "XSS_Final.txt")
    vulnerable_xss_file = os.path.join(report_dir, "Vulnerable_XSS.txt")
    
    print("[*] Collecte des sous-domaines...")
    if await run_command(f"subfinder -d {domain} -o {subdomains_file}") is None:
        return
    
    print("[*] Filtrage des sous-domaines actifs...")
    if await run_command(f"httpx -l {subdomains_file} -threads 100 -mc 200,301,302 -silent -nc -o {httpx_output_file}") is None:
        return

    print("[*] Collecte des points de terminaison...")
    if await run_command(f'cat {httpx_output_file} | gau --threads 30 >> {endpoints_file}') is None:
        return
    if await run_command(f'waybackurls {domain} >> {endpoints_file}') is None:
        return
    if await run_command(f"cat {httpx_output_file} | katana -jc >> {endpoints_file}") is None:
        return

    print("[*] Suppression des doublons avec uro...")
    if await run_command(f"cat {endpoints_file} | uro >> {endpoints_filtered_file}") is None:
        return

    print("[*] Filtrage des points de terminaison pour XSS...")
    if await run_command(f"cat {endpoints_filtered_file} | gf xss >> {xss_file}") is None:
        return

    print("[*] Recherche de paramètres XSS réfléchis...")
    if await run_command(f"cat {xss_file} | Gxss -p khXSS -o {xss_ref_file}") is None:
        return
        
    print("[*] Suppression des doublons avec uro...")
    if await run_command(f"cat {xss_ref_file} | uro >> {xss_filtered}") is None:
        return

    print("[*] Analyse des vulnérabilités XSS...")
    if await run_command(f"dalfox file {xss_filtered} --worker 200 --waf-evasion -o {vulnerable_xss_file}") is None:
        return
    
    print_potential_xss(vulnerable_xss_file)
    
    # Définition des fichiers à conserver
    files_to_keep = {endpoints_filtered_file, httpx_output_file, vulnerable_xss_file, xss_filtered}

    # Suppression des fichiers non nécessaires
    for file in os.listdir(report_dir):
        file_path = os.path.join(report_dir, file)
        if file_path not in files_to_keep:
            os.remove(file_path)

    print("\n[*] Automation completed.")

if __name__ == "__main__":
    domain = input("Entrez le domaine à analyser (ex: toyota.com): ").strip()
    asyncio.run(main(domain))
