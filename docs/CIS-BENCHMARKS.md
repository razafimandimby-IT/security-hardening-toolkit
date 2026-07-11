# 📋 Guide des Benchmarks CIS

## Qu'est-ce que le CIS ?

Le **Center for Internet Security (CIS)** est une organisation a but non lucratif dediee a la securite des systemes d'information. Fondee en 2000, elle est reconnue mondialement pour ses **CIS Benchmarks** et ses **CIS Controls**.

### CIS Benchmarks

Les **CIS Benchmarks** sont des documents de reference contenant des recommandations de configuration securisee pour plus de 100 technologies, incluant :

- Systemes d'exploitation (Windows Server, Linux, macOS)
- Fournisseurs de cloud (AWS, Azure, GCP)
- Logiciels (Kubernetes, Docker, IIS, Apache)
- Dispositifs reseau (Cisco, Palo Alto)
- Bases de donnees (SQL Server, PostgreSQL, MongoDB)

Chaque benchmark est elabore par un consensus d'experts internationaux et mis a jour regulierement.

---

## Pourquoi les benchmarks CIS sont importants

| Benefice | Description |
|---|---|
| **Conformite reglementaire** | Repond aux exigences de nombreux cadres (PCI-DSS, HIPAA, NIST, RGPD) |
| **Reduction de la surface d'attaque** | Elimine les configurations par defaut vulnerables |
| **Standardisation** | Garantit une posture de securite homogene |
| **Meilleures pratiques** | Basees sur l'experience collective de milliers d'organisations |
| **Audit facilite** | Criteres clairs et mesurables pour les evaluations |

---

## Niveaux de profils CIS

| Profil | Description |
|---|---|
| **Niveau 1 (L1)** | Recommandations de base, facilement applicables, impact minimal sur les operations |
| **Niveau 2 (L2)** | Securite renforcee, peut impacter les fonctionnalites, pour environnements haute-securite |

Ce toolkit applique les recommandations des niveaux 1 et 2 selon le contexte.

---

## Correspondance avec le toolkit

### Windows - Sections couvertes

| Section CIS | Script correspondant | Statut |
|---|---|---|
| 1 - Account Policies | `Invoke-WindowsHardening.ps1` | ✅ |
| 2 - Local Policies | `Invoke-WindowsHardening.ps1` | ✅ |
| 3 - Event Log | `Invoke-WindowsHardening.ps1` | ✅ |
| 4 - Restricted Groups | `Invoke-WindowsHardening.ps1` | ✅ |
| 5 - System Services | `Invoke-WindowsHardening.ps1` | ✅ |
| 9 - Windows Defender Firewall | `Invoke-WindowsHardening.ps1` | ✅ |
| 18 - Administrative Templates | `Invoke-WindowsHardening.ps1` | ✅ |

### Linux - Sections couvertes

| Section CIS | Script correspondant | Statut |
|---|---|---|
| 1 - Initial Setup | `harden-linux.sh` | ✅ |
| 2 - Services | `harden-linux.sh` | ✅ |
| 3 - Network Configuration | `harden-linux.sh` | ✅ |
| 4 - Logging and Auditing | `check-compliance.sh` / `audit/rules` | ✅ |
| 5 - Access, Authentication | `harden-linux.sh` | ✅ |
| 6 - System Maintenance | `harden-linux.sh` | ✅ |

---

## References

- [Site officiel du CIS](https://www.cisecurity.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [Télécharger les benchmarks](https://www.cisecurity.org/cis-benchmarks/)
