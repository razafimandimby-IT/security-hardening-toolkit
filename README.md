# 🛡️ Security Hardening Toolkit

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)
![Bash](https://img.shields.io/badge/GNU%20Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![CIS](https://img.shields.io/badge/CIS%20Benchmarks-0052CC?style=for-the-badge&logo=cisco&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Hardening-red?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge)

**Automatisation du hardening et de l'audit de sécurité pour serveurs Windows et Linux**

*Conforme aux benchmarks CIS (Center for Internet Security)*

</div>

---

## 📋 Table des matières

- [Apercu general](#apercu-general)
- [Fonctionnalites](#fonctionnalites)
- [Architecture](#architecture)
- [Prerequis](#prerequis)
- [Installation rapide](#installation-rapide)
- [Utilisation](#utilisation)
- [Structure du projet](#structure-du-projet)
- [Niveaux de securite](#niveaux-de-securite)
- [Rapports](#rapports)
- [Bonnes pratiques](#bonnes-pratiques)
- [License](#license)
- [Auteur](#auteur)

---

## 📖 Apercu general

**Security Hardening Toolkit** est une suite complete d'outils pour automatiser le durcissement (hardening) et l'audit de conformite de serveurs Windows et Linux. Concu pour les administrateurs systeme et les equipes SecOps, ce toolkit permet de :

- **Auditer** la conformite de vos serveurs par rapport aux benchmarks CIS
- **Hardener** automatiquement les configurations systeme
- **Remedier** les ecarts de securite identifies
- **Generer** des rapports HTML professionnels avec scores et recommandations
- **Standardiser** la securite sur l'ensemble de votre parc informatique

---

## ✨ Fonctionnalites

| Fonctionnalite | Description |
|---|---|
| **Audit automatise** | Verifie des centaines de points de configuration critiques |
| **Conformite CIS** | Aligne vos serveurs sur les recommandations du Center for Internet Security |
| **Multi-OS** | Support complet pour Windows Server (2016/2019/2022) et Linux (Ubuntu/Debian/RHEL) |
| **Rapports HTML** | Genere des rapports professionnels avec scores visuels et graphiques |
| **Mode Dry-Run** | Simule les changements sans appliquer (--Dry-Run / --dry-run) |
| **Remediation auto** | Corrige automatiquement les ecarts de securite detectes |
| **Configuration centralisee** | Fichier JSON/YAML pour personnaliser les niveaux de securite |
| **Logging avance** | Journalisation complete de toutes les actions avec horodatage |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY HARDENING TOOLKIT                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌────────────────────────────┐    ┌────────────────────────────┐         │
│   │       WINDOWS MODULE       │    │        LINUX MODULE        │         │
│   │                            │    │                            │         │
│   │  ┌─────────────────────┐   │    │  ┌─────────────────────┐   │         │
│   │  │ Invoke-Windows      │   │    │  │ harden-linux.sh     │   │         │
│   │  │ Hardening.ps1       │   │    │  │                     │   │         │
│   │  └──────────┬──────────┘   │    │  └──────────┬──────────┘   │         │
│   │             │              │    │             │              │         │
│   │  ┌──────────▼──────────┐   │    │  ┌──────────▼──────────┐   │         │
│   │  │ Test-Windows         │   │    │  │ check-compliance    │   │         │
│   │  │ Compliance.ps1       │   │    │  │ .sh                 │   │         │
│   │  └──────────┬──────────┘   │    │  └──────────┬──────────┘   │         │
│   │             │              │    │             │              │         │
│   │  ┌──────────▼──────────┐   │    │  ┌──────────▼──────────┐   │         │
│   │  │ Remediate-Windows   │   │    │  │ remediate.sh        │   │         │
│   │  │ Issues.ps1          │   │    │  │                     │   │         │
│   │  └─────────────────────┘   │    │  └─────────────────────┘   │         │
│   └────────────────────────────┘    └────────────────────────────┘         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     REPORTING MODULE                                │   │
│   │  ┌──────────────────────┐  ┌──────────────────┐  ┌──────────────┐  │   │
│   │  │ New-HardeningReport  │  │New-HardeningReport│  │ report.html  │  │   │
│   │  │ .ps1                 │  │.sh                │  │ (template)   │  │   │
│   │  └──────────────────────┘  └──────────────────┘  └──────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     CONFIGURATION MODULE                             │   │
│   │  ┌──────────────────────┐  ┌────────────────────────────────────┐   │   │
│   │  │ hardening-config.json│  │ compliance-policy.yaml             │   │   │
│   │  └──────────────────────┘  └────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequis

### Windows

- **OS**: Windows Server 2016/2019/2022 ou Windows 10/11 Pro/Enterprise
- **PowerShell**: Version 5.1 ou superieure (PowerShell 7 recommande)
- **Droits**: Administrateur local (elevation requise)
- **Modules**: RSAT (Remote Server Administration Tools) pour certaines fonctionnalites

### Linux

- **OS**: Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+
- **Shell**: Bash 4.0+
- **Droits**: Acces root ou sudo
- **Packages**: `auditd`, `fail2ban`, `ufw` (installation automatique si manquants)

### Reporting

- **PowerShell**: Pour le rapport Windows (ou PowerShell 7)
- **Bash**: Pour le rapport Linux
- **Python 3**: Optionnel, pour les graphiques avances
- **Navigateur**: Pour visualiser les rapports HTML

---

## 🚀 Installation rapide

```bash
# Cloner le depot
git clone https://github.com/razafimandimby-IT/security-hardening-toolkit.git
cd security-hardening-toolkit

# Rendre les scripts Linux executables
chmod +x linux/*.sh
chmod +x reporting/New-HardeningReport.sh
```

---

## 🎯 Utilisation

### Windows - Hardening complet

```powershell
# Mode simulation (aucun changement applique)
.\windows\Invoke-WindowsHardening.ps1 -DryRun

# Hardening complet avec configuration personnalisee
.\windows\Invoke-WindowsHardening.ps1 -Level Advanced -ConfigPath .\config\hardening-config.json

# Hardening avec profil Standard et exclusion de services specifiques
.\windows\Invoke-WindowsHardening.ps1 -Level Standard -ExcludeService "WSearch,Xbox*"
```

### Windows - Audit de conformite

```powershell
# Audit complet avec rapport HTML
.\windows\Test-WindowsCompliance.ps1 -OutputHtml .\rapport-audit.html

# Audit rapide (categories specifiques)
.\windows\Test-WindowsCompliance.ps1 -Categories "AccountPolicies,Firewall,Defender"

# Audit avec configuration personnalisee
.\windows\Test-WindowsCompliance.ps1 -ConfigPath .\config\compliance-policy.yaml -OutputHtml .\report.html
```

### Windows - Remediation

```powershell
# Remedier les ecarts trouves par l'audit
.\windows\Remediate-WindowsIssues.ps1 -ReportPath .\rapport-audit.json

# Remediation ciblee
.\windows\Remediate-WindowsIssues.ps1 -ReportPath .\rapport-audit.json -Categories "PasswordPolicy,AuditPolicy"
```

### Linux - Hardening

```bash
# Mode simulation
sudo ./linux/harden-linux.sh --dry-run

# Hardening complet niveau avance
sudo ./linux/harden-linux.sh --level advanced --config ./config/hardening-config.json

# Hardening avec SSH personnalise
sudo ./linux/harden-linux.sh --level standard --ssh-port 2222
```

### Linux - Audit de conformite

```bash
# Audit complet
sudo ./linux/check-compliance.sh

# Audit avec sortie JSON pour traitement
sudo ./linux/check-compliance.sh --output json --file rapport.json

# Audit avec generation de rapport
sudo ./linux/check-compliance.sh --output html --file rapport.html
```

### Linux - Remediation

```bash
# Remediation automatique
sudo ./linux/remediate.sh --report ./rapport.json

# Remediation avec categories specifiques
sudo ./linux/remediate.sh --report ./rapport.json --categories "ssh, kernel, filesystem"
```

### Generation de rapports

```powershell
# Windows
.\reporting\New-HardeningReport.ps1 -DataPath .\resultats.json -OutputPath .\SecurityReport.html
```

```bash
# Linux
sudo ./reporting/New-HardeningReport.sh --input ./resultats.json --output ./SecurityReport.html
```

---

## 📁 Structure du projet

```
security-hardening-toolkit/
├── README.md                          # Documentation principale
├── LICENSE                            # Licence MIT
├── docs/
│   ├── ARCHITECTURE.md                # Documentation de l'architecture
│   └── CIS-BENCHMARKS.md              # Guide des benchmarks CIS
├── windows/
│   ├── Invoke-WindowsHardening.ps1    # Script de hardening Windows
│   ├── Test-WindowsCompliance.ps1     # Script d'audit Windows
│   └── Remediate-WindowsIssues.ps1    # Script de remediation Windows
├── linux/
│   ├── harden-linux.sh                # Script de hardening Linux
│   ├── check-compliance.sh            # Script d'audit Linux
│   ├── remediate.sh                   # Script de remediation Linux
│   ├── sshd_config.secure             # Template SSH durci
│   ├── 99-hardening.conf              # Configuration sysctl
│   └── audit/
│       └── 99-audit-hardening.rules   # Regles auditd
├── reporting/
│   ├── New-HardeningReport.ps1        # Generation rapport Windows
│   ├── New-HardeningReport.sh         # Generation rapport Linux
│   └── templates/
│       └── report.html                # Template HTML du rapport
└── config/
    ├── hardening-config.json          # Configuration JSON
    └── compliance-policy.yaml         # Politique de conformite YAML
```

---

## 📊 Niveaux de securite

| Niveau | Description | Cas d'usage |
|---|---|---|
| **Basic** | Configuration securisee minimale, compatibilite maximale | Postes de travail, environnements de developpement |
| **Standard** | Durcissement equilibre securite/productivite | Serveurs de production standard |
| **Advanced** | Durcissement maximal, restrictions fortes | Environnements haute-securite, DMZ, PCI-DSS |

Chaque niveau peut etre personnalise via le fichier `config/hardening-config.json`.

---

## 📈 Rapports

Les rapports HTML generes incluent :

- **Score global de conformite** (0-100%) avec jauge visuelle
- **Repartition par categorie** (Politiques de mots de passe, Pare-feu, Services, etc.)
- **Statut detaille** (PASS / FAIL / WARNING) pour chaque verification
- **Recommandations** avec commandes de remediation
- **Graphiques** de repartition des resultats
- **Horodatage** et informations systeme

Exemple de sortie :
```
═══════════════════════════════════════════════════════════
  SECURITY HARDENING TOOLKIT - RAPPORT DE CONFORMITE
═══════════════════════════════════════════════════════════
  Date : 2026-07-11 10:30:00
  Systeme : Windows Server 2022
  Niveau : Advanced
═══════════════════════════════════════════════════════════
  Score global : 87/100 (87% - Bon)
═══════════════════════════════════════════════════════════

  Categorie                Pass  Fail  Score
  ───────────────────────────────────────────
  Account Policies          12    0    100%
  Security Options          18    2     90%
  Audit Policy               8    1     89%
  Windows Defender           6    0    100%
  Firewall                   9    1     90%
  Services                  14    1     93%
  ───────────────────────────────────────────
  TOTAL                     67    5     93%
═══════════════════════════════════════════════════════════
```

---

## 🔒 Bonnes pratiques

1. **Toujours utiliser le mode Dry-Run** avant d'appliquer des changements en production
2. **Tester dans un environnement de qualification** avant le deploiement
3. **Sauvegarder la configuration** existante avant tout hardening
4. **Adapter les niveaux** en fonction de l'environnement (dev, prod, DMZ)
5. **Planifier des audits reguliers** (recommandation : mensuel)
6. **Documenter les exclusions** justifiees dans le fichier de configuration
7. **Combiner avec une solution de monitoring** pour detecter les derives

---

## ⚠️ Avertissement

Ce toolkit modifie des parametres de securite critiques du systeme. Une mauvaise configuration peut rendre un serveur inaccessible ou perturber des applications. **Utilisez-le avec prudence et toujours apres validation en environnement de test.**

---

## 📄 License

Ce projet est distribue sous licence **MIT**. Voir le fichier `LICENSE` pour plus d'informations.

---

## 👨‍💻 Auteur

**Louis Denis RAZAFIMANDIMBY**

- 🌐 GitHub : [@razafimandimby-IT](https://github.com/razafimandimby-IT)
- 🔗 LinkedIn : [Louis Denis RAZAFIMANDIMBY](https://linkedin.com/in/louis-denis-razafimandimby)
- 🛡️ Expert en cybersecurite et administration systeme

*Securite par la conception, automatisation par la pratique.*

---

<div align="center">

**Security Hardening Toolkit** - *Hardening automatise, conformite CIS, rapports professionnels*

</div>
