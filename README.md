# linux-audit.sh

Script de collecte d'informations système et performances pour audits d'administration Linux.

## Description

`linux-audit.sh` est un script bash qui se connecte en SSH à un serveur Linux distant pour collecter des informations techniques et des données de performances. Il génère un rapport avec pré-analyse et alertes colorées pour faciliter les audits d'administration système.

## Prérequis

### Côté client (machine exécutant le script)
- bash (version 3.x ou supérieure)
- ssh et scp (client OpenSSH)
- gzip

### Côté serveur (machine auditée)
- bash
- Accès SSH configuré (clé ou mot de passe)
- Outils standard Linux (coreutils)
- sysstat (optionnel, pour les données SAR)

## Installation

1. Télécharger le script:
```bash
wget https://example.com/linux-audit.sh
# ou
git clone https://github.com/user/linux-audit.git
```

2. Rendre le script exécutable:
```bash
chmod +x linux-audit.sh
```

3. (Optionnel) Copier dans un répertoire du PATH:
```bash
sudo cp linux-audit.sh /usr/local/bin/
```

### Installation de la manpage

Pour pouvoir utiliser `man linux-audit.sh`, copiez la manpage dans le répertoire système approprié:

```bash
# Pour une installation système (nécessite les droits root):
sudo cp linux-audit.sh.1 /usr/local/share/man/man1/
sudo mandb    # Mettre à jour la base de données man

# Pour une installation utilisateur (sans droits root):
mkdir -p ~/.local/share/man/man1
cp linux-audit.sh.1 ~/.local/share/man/man1/
export MANPATH="$HOME/.local/share/man:$MANPATH"
# Ajouter la ligne export dans ~/.bashrc pour la rendre permanente

# Vérification:
man linux-audit.sh
```

## Utilisation

```
Usage: linux-audit.sh [OPTIONS] <hostname_ou_ip>

Options:
  -u, --user USER     Utilisateur SSH (défaut: root)
  -p, --port PORT     Port SSH (défaut: 22)
  -i, --identity KEY  Fichier de clé SSH
  -o, --output FILE   Génère un rapport HTML (fichier .html)
  -h, --help          Affiche l'aide
```

### Exemples

```bash
# Connexion basique en root
./linux-audit.sh serveur.example.com

# Connexion avec un utilisateur spécifique
./linux-audit.sh -u admin serveur.example.com

# Connexion avec clé SSH et port personnalisé
./linux-audit.sh -u admin -i ~/.ssh/id_rsa -p 2222 192.168.1.100

# Sauvegarder le rapport dans un fichier texte
./linux-audit.sh serveur.example.com > rapport-serveur.txt
./linux-audit.sh serveur.example.com | tee rapport-serveur.txt

# Générer un rapport HTML
./linux-audit.sh -o rapport.html serveur.example.com
```

## Informations collectées

Le script collecte les informations suivantes:

### Informations système
- Hostname, distribution, version kernel
- Architecture, uptime, date système

### CPU
- Modèle, nombre de sockets/cœurs/threads
- Utilisation CPU en temps réel
- I/O Wait

### Mémoire
- RAM totale, utilisée, libre
- Buffers et cache
- Calcul compatible kernels anciens (RHEL6)

### Swap
- Espace total, utilisé, libre

### Load Average
- Load 1, 5, 15 minutes
- Ratio load/nombre de CPUs

### Disques
- Espace utilisé par système de fichiers (df)
- Statistiques I/O depuis /proc/diskstats

### Réseau
- Interfaces et adresses IP
- Statistiques RX/TX par interface

### Processus
- Top 5 processus par utilisation CPU
- Top 5 processus par utilisation mémoire

### Données SAR (si sysstat installé)
- Export complet des données historiques
- Fichier compressé YYYYMMDD-Hostname-sar.gz

## Seuils d'alerte

Le script analyse les métriques et génère des alertes selon ces seuils:

| Métrique | Warning | Critique |
|----------|---------|----------|
| RAM utilisée | > 75% | > 85% |
| Swap utilisé | > 30% | > 50% |
| CPU utilisation | > 70% | > 85% |
| Load/CPU ratio | > 1.0 | > 1.5 |
| I/O Wait | > 15% | > 25% |
| Disque plein | > 80% | > 90% |

Les alertes sont affichées en couleur dans le terminal:
- **Jaune** : Warning
- **Rouge** : Critique

## Fichier SAR

Si sysstat est installé sur le serveur distant, le script exporte les données SAR historiques dans un fichier compressé:

- Format du nom: `YYYYMMDD-Hostname-sar.gz`
- Exemple: `20250125-webserver01-sar.gz`

Pour lire le fichier:
```bash
zcat 20250125-webserver01-sar.gz | less
zcat 20250125-webserver01-sar.gz | grep -A 20 "CPU"
gunzip -c 20250125-webserver01-sar.gz > sar-data.txt
```

Si sysstat n'est pas installé, un message d'avertissement est affiché et le script continue la collecte des autres informations.

## Compatibilité

Le script a été conçu pour être compatible avec:

### Distributions
- Red Hat Enterprise Linux (RHEL) 6, 7, 8, 9
- CentOS 6, 7, 8
- Oracle Linux 6, 7, 8
- Debian 8, 9, 10, 11, 12
- Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04

### Bash
- Version 3.x et supérieure (compatible RHEL6)
- Évite les syntaxes bash 4+ (declare -A, ${var,,}, etc.)

### Chemins SAR supportés
- `/var/log/sa/` (RHEL/CentOS)
- `/var/log/sysstat/` (Debian/Ubuntu)

## Codes de sortie

| Code | Description |
|------|-------------|
| 0 | Succès |
| 1 | Erreur de connexion SSH ou argument manquant |

## Personnalisation

Les seuils d'alerte peuvent être modifiés en éditant les variables au début du script:

```bash
THRESH_RAM_WARN=75
THRESH_RAM_CRIT=85
THRESH_SWAP_WARN=30
THRESH_SWAP_CRIT=50
THRESH_CPU_WARN=70
THRESH_CPU_CRIT=85
THRESH_LOAD_WARN=1.0
THRESH_LOAD_CRIT=1.5
THRESH_IOWAIT_WARN=15
THRESH_IOWAIT_CRIT=25
THRESH_DISK_WARN=80
THRESH_DISK_CRIT=90
```

## Sécurité

- Le script utilise `BatchMode=yes` pour SSH (pas de prompt interactif)
- `StrictHostKeyChecking=no` est utilisé (attention en environnement sensible, modifier si nécessaire)
- Aucune donnée sensible n'est stockée localement hormis le fichier SAR
- Recommandation: utiliser des clés SSH plutôt que des mots de passe

## Dépannage

### Problème: "Impossible de se connecter au serveur"
- Vérifier que le serveur est accessible: `ping hostname`
- Vérifier les credentials SSH: `ssh user@hostname`
- Vérifier le port SSH: `ssh -p 2222 user@hostname`
- Vérifier les permissions de la clé SSH: `chmod 600 ~/.ssh/id_rsa`

### Problème: "sysstat n'est pas installé"
- C'est un avertissement, pas une erreur
- Les autres informations sont collectées normalement
- Pour installer sysstat:
  - RHEL/CentOS: `yum install sysstat`
  - Debian/Ubuntu: `apt-get install sysstat`

### Problème: Certaines informations manquent
- Certaines commandes peuvent ne pas être disponibles selon la distribution
- Le script utilise des fallbacks quand possible
- Vérifier les permissions de l'utilisateur SSH

## Auteur

Script généré par Claude (Anthropic)
Date: Janvier 2025

## Licence

Ce script est fourni "tel quel" sans garantie d'aucune sorte.
Libre d'utilisation et de modification.

## Voir aussi

- `man linux-audit.sh` - Page de manuel détaillée
- `sar(1)` - System Activity Reporter
- `vmstat(8)` - Report virtual memory statistics
- `iostat(1)` - Report I/O statistics
- `top(1)` - Display Linux processes
