# 🏗️ Architecture du Security Hardening Toolkit

## Vue d'ensemble

Le Security Hardening Toolkit suit une architecture modulaire en couches permettant l'audit, le hardening et le reporting sur les systemes Windows et Linux.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERFACE UTILISATEUR                        │
│          CLI (Powershell / Bash) - Fichiers de configuration        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────┐          ┌──────────────────────┐          │
│  │    MODULE WINDOWS   │          │     MODULE LINUX     │          │
│  │                     │          │                      │          │
│  │  ┌───────────────┐  │          │  ┌────────────────┐  │          │
│  │  │ Hardening     │  │          │  │ harden-linux   │  │          │
│  │  │ Invoke-Windows│  │          │  │ .sh            │  │          │
│  │  │ Hardening.ps1 │  │          │  └────────┬───────┘  │          │
│  │  └───────┬───────┘  │          │           │          │          │
│  │          │           │          │  ┌────────▼───────┐  │          │
│  │  ┌───────▼───────┐  │          │  │ check-         │  │          │
│  │  │ Test-Windows  │  │          │  │ compliance.sh  │  │          │
│  │  │ Compliance.ps1│  │          │  └────────┬───────┘  │          │
│  │  └───────┬───────┘  │          │           │          │          │
│  │          │           │          │  ┌────────▼───────┐  │          │
│  │  ┌───────▼───────┐  │          │  │ remediate.sh   │  │          │
│  │  │ Remediate-    │  │          │  └────────────────┘  │          │
│  │  │ WindowsIssues │  │          │                      │          │
│  │  │ .ps1          │  │          │  ┌────────────────┐  │          │
│  │  └───────────────┘  │          │  │ sshd_config    │  │          │
│  │                      │          │  │ .secure        │  │          │
│  └─────────────────────┘          │  ├────────────────┤  │          │
│                                    │  │ 99-hardening   │  │          │
│  ┌─────────────────────┐           │  │ .conf          │  │          │
│  │    MODULE REPORTING │           │  ├────────────────┤  │          │
│  │                     │           │  │ audit/         │  │          │
│  │  New-Hardening      │           │  │ 99-audit-      │  │          │
│  │  Report.ps1 / .sh   │           │  │ hardening.rules│  │          │
│  │  templates/         │           │  └────────────────┘  │          │
│  │  report.html        │           └──────────────────────┘          │
│  └─────────────────────┘                                            │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   MODULE CONFIGURATION                       │   │
│  │                                                              │   │
│  │   hardening-config.json     compliance-policy.yaml           │   │
│  │                                                              │   │
│  │   - Niveaux : Basic / Standard / Advanced                   │   │
│  │   - Exclusions                                              │   │
│  │   - Politiques de conformite                                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Flux de travail

### 1. Modele standard

```
Audit (compliance)  ──>  Analyse des ecarts  ──>  Remediation  ──>  Verification
       │                        │                        │                │
       ▼                        ▼                        ▼                ▼
check-                  identifier les              appliquer les    re-auditer
compliance              non-conformites             corrections     pour valider
```

### 2. Modele complet

```
                    ┌──────────────────────────────────┐
                    │      HARDENING COMPLET           │
                    │   (Script de durcissement)       │
                    └────────────┬─────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────────────┐
                    │      AUDIT DE CONFORMITE         │
                    │   (Script de verification)       │
                    └────────────┬─────────────────────┘
                                 │
                    ┌────────────▼─────────────────────┐
                    │     RAPPORT (HTML / JSON)        │
                    │   (Generation automatique)       │
                    └────────────┬─────────────────────┘
                                 │
                    ┌────────────▼─────────────────────┐
                    │          REMEDIATION             │
                    │   (Correction des ecarts)        │
                    └────────────┬─────────────────────┘
                                 │
                    ┌────────────▼─────────────────────┐
                    │     RE-AUDIT DE VERIFICATION     │
                    │   (Validation des corrections)   │
                    └──────────────────────────────────┘
```

---

## Flux de donnees

```
┌──────────────┐    Audit    ┌──────────────┐    Rapport    ┌──────────────┐
│   Systeme    │────────────►│   Resultats   │─────────────►│   HTML/JSON   │
│   cible      │             │   JSON        │              │   Report      │
└──────────────┘             └──────┬───────┘              └──────────────┘
                                    │
                                    │ Remediation
                                    ▼
                            ┌──────────────┐
                            │   Corrections │
                            │   appliquees  │
                            └──────────────┘
```

---

## Composants cles

### Module Windows (PowerShell)
- Utilise les cmdlets natifs Windows pour les configurations
- Exploite Secedit pour les politiques de securite
- Interagit avec le registre, le service Windows Defender, le pare-feu
- Supporte les versions PowerShell 5.1 et 7

### Module Linux (Bash)
- Scripts shell POSIX compatibles avec les distributions majeures
- Utilise sysctl, auditd, fail2ban, sshd, iptables/nftables
- Detection automatique de la distribution
- Gestion des paquets apt/yum/dnf

### Module Reporting (Cross-Platform)
- Template HTML responsive avec CSS integre
- Graphiques CSS (sans dependance JavaScript)
- Sortie JSON pour integration avec d'autres outils
- Support des rapports combines Windows + Linux

### Module Configuration (Centralise)
- Fichier JSON pour les parametres de hardening
- Fichier YAML pour les politiques de conformite
- Niveaux predefinis (Basic, Standard, Advanced)
- Systeme d'exclusions par hote ou par role
