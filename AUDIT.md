# Audit de code — `linux-audit.sh`

**Révision auditée :** `c185a62` (v1.0.0, 2046 lignes), après le commit de correctifs `d5539c7`.
Les numéros de ligne renvoient à cette révision.

> **État actuel : tous les constats ouverts sont corrigés** (commits `9073cd8` → `6f95253`,
> dans l'ordre du plan de remédiation de la section 3). Voir la section 0 pour le détail et la
> validation. Les sections 1 et 2 décrivent l'état *avant* ces correctifs.

Méthode : lecture intégrale du script, puis reproduction locale des points douteux (les points
marqués *reproduit* ont été rejoués en bash). Ce document remplace l'audit précédent, qui
portait sur la version d'avant `d5539c7` : ses numéros de ligne ne correspondaient plus au
code et il listait comme ouverts des points déjà corrigés.

Modèle de menace retenu : **le serveur audité peut être compromis**. Toute chaîne renvoyée par
SSH (`hostname`, `ps`, `df`, `ip`, SAR…) peut donc être contrôlée par un attaquant, et le
rapport HTML est ouvert ensuite dans le navigateur de l'auditeur.

---

## 0. Correctifs appliqués

| Étape | Commit | Constats corrigés |
|-------|--------|-------------------|
| 1. Robustesse des valeurs vides | `9073cd8` | H11, H12, H13, M14 |
| 2. Quoting et glob | `91c7f26` | H3, M1, N6 |
| 3. Fausses alertes | `139ebdd` | N2, H4, M7, N1, et aussi H2, H7, M2, M8 (lscpu), M9, L7 |
| 4. Charge et performances | `eeb8847` | N3, N5, N11, et aussi M4, M8 (global), M10, L2, L3, L4, L5, N8, N9, N13, N14 |
| 5. Sécurité de l'opérateur | `1084245` | H6, H9, H10, M11, N4, L9, et aussi M5 |
| 6. Exploitabilité | `1e5a891` | N7, L6, M13 |
| 7. Points restants | `6f95253` | M3, L1, L8, N12, et N10 (seuils regroupés dans la section 1 du script dès les étapes 3 et 4) |

Bug supplémentaire trouvé en cours de route et corrigé dans `6f95253` : le badge du ratio load
générait les classes `badge-crit`/`badge-warn`, absentes du CSS (badge affiché sans style).

**Validation** (sshd local, clé et mot de passe, données SAR générées par `sadc`) :
- coupure SSH en cours d'audit : arrêt en code 3 sans rapport, avec la section où la coupure a été détectée ;
- clé dont le chemin contient une espace, `-u '-oProxyCommand=…'` refusé, cellule `[k1]` non expansée ;
- compte non-root avec shell de login `tcsh`, et mot de passe `Pw\csh 2` via prompt, via `SSHPASS` et en argument ;
- clé d'hôte modifiée : connexion refusée avec le message de ssh ; hôte inconnu : clé enregistrée ;
- analyse SAR validée sur sysstat 12 (`DEV` en dernière colonne avec `-p`) et sur le format
  sysstat 9 (AM/PM, `LINUX RESTART`, hostname `DEVbox` dans la bannière) ;
- fallback `/proc/diskstats` comparé à iostat sous charge d'écriture : mêmes débits, await et %util ;
- codes de sortie 0/1/2/3, rapport non inscriptible détecté, rapport et export en mode `0600` ;
- durée d'un audit : 16,7 s → 8,4 s, une seule authentification ;
- `shellcheck -S warning` : 147 → 1 avertissement hors SC2155 (le `printf '%80s'` voulu de `print_line`) ;
- rendu du rapport HTML vérifié dans Chromium headless.

---

## 1. Suivi de l'audit précédent

| Réf. | Sujet | État | Où / commentaire |
|------|-------|------|------------------|
| C1 | XSS via hostname dans `html_init` | ✅ Corrigé | L223-224 |
| C2 | XSS via cellules de `html_table_row` | ✅ Corrigé | L474 (mais voir M1, toujours ouvert) |
| H1 | Colonnes iostat codées en dur | ✅ Corrigé | L1160-1173 (mais voir **N1**, régression) |
| H2 | Graphique CPU sur le mauvais fichier SAR | ❌ Ouvert | L538-540 |
| H3 | `-i $SSH_KEY` non quoté | ❌ Ouvert | L148, L173 |
| H4 | `NB_CPUS` reste à 1 selon les variantes de lscpu | ❌ Ouvert | L767-770 |
| H5 | Fichiers temporaires distants prévisibles | ✅ Corrigé | L1228-1230 (`mktemp` + `trap`) |
| H6 | `percent` non validé dans `style=` | ❌ Ouvert | L863/L865 : `cpu_usage` distant brut |
| H7 | Heures SAR brutes dans le SVG | ❌ Ouvert | L636-637, L665-666 |
| H8 | Hostname non assaini dans les noms de fichiers | ✅ Corrigé | L2008-2011 |
| H9 | `StrictHostKeyChecking=no` silencieux | ❌ Ouvert | L47 |
| H10 | Mot de passe dans l'argv | ⚠️ Partiel | `sshpass -e` OK (L156), mais `-P 'secret'` reste documenté (L86, README, man) |
| H11 | Échec SSH en cours de run → rapport fabriqué, exit 0 | ❌ Ouvert | L156-158 |
| H12 | Division par zéro mémoire | ❌ Ouvert | L908, L912, L943-945 |
| H13 | Fausse alerte CRITIQUE si `/proc/loadavg` est vide | ❌ Ouvert (*reproduit*) | L1060 → `ratio=inf` → `float_ge` vrai |
| M1 | `for cell in $cells` : glob local | ❌ Ouvert (*reproduit*) | L473 : `[k1]` devient `1` et `k` si ces fichiers existent dans le cwd |
| M2 | `await` diskstats = temps occupé / secteurs | ❌ Ouvert | L1240-1251 |
| M3 | Barre mémoire : double soustraction buffers/cache | ❌ Ouvert | L939 |
| M4 | `/proc/net/dev` : `iface:octets` collés | ❌ Ouvert | L1443-1444, L1492-1493 |
| M5 | `-P <hostname>` avale le hostname | ❌ Ouvert | L1939 |
| M6 | Placeholder iowait mort | ✅ Corrigé | L822-828 (vmstat, colonne `wa` dynamique) |
| M7 | Lignes `LINUX RESTART` dans le graphique CPU | ❌ Ouvert | L546 |
| M8 | `LANG=C` au lieu de `LC_ALL=C` | ⚠️ Partiel | iostat corrigé ; `lscpu` toujours en `LANG=C` (L761) |
| M9 | `iostat -y` absent sur sysstat 9 (RHEL6) | ❌ Ouvert | L1156 → toujours le fallback diskstats |
| M10 | L'en-tête `sar -d` peut matcher la bannière | ❌ Ouvert | L1692 |
| M11 | Rapports créés avec l'umask par défaut | ❌ Ouvert | L520, L1786 |
| M12 | Boucle infinie sur un flag sans valeur | ✅ Corrigé | L1923-1933 |
| M13 | `-s` ne détecte pas un export SAR vide (gzip = 20 o) | ❌ Ouvert | L1788 |
| M14 | `remote_cmd_exists` confond coupure SSH et absence | ❌ Ouvert | L165 |
| L1 | iowait compté comme CPU occupé | ❌ Ouvert | L792-796 |
| L2 | Tri lexical des dates `DD/MM/YYYY` | ❌ Ouvert | L1727 |
| L3 | `sort -rn` dépend de la locale de l'opérateur | ❌ Ouvert | L1723-1724 |
| L4 | « Pas de données » affiché comme « pas d'anomalie » | ❌ Ouvert | L1729-1743 |
| L5 | `ip`/`ifconfig` hors du PATH non-root (RHEL) | ❌ Ouvert | L1413-1419 |
| L6 | « Rapport HTML généré » affiché même en cas d'échec | ❌ Ouvert | L520-521 |
| L7 | Filtre df non ancré | ❌ Ouvert | L1101 (voir aussi **N2**) |
| L8 | `\|` dans une alerte casse le stockage | ❌ Ouvert | L126-140 |
| L9 | `echo "$text"` dans `html_escape` | ❌ Ouvert | L218 |

**Bilan : 8 corrigés, 2 partiels, 28 encore ouverts.**

---

## 2. Nouveaux constats

### Élevés

#### N1 : `await` moyenné sans pondération, régression de `d5539c7` (L1191, L1346)
Avec sysstat récent (colonnes `r_await` et `w_await`), le correctif calcule
`await = (r_await + w_await) / 2`. Sur un disque qui ne fait que des écritures (`r/s=0`,
`r_await=0`, `w_await=40 ms`), l'await affiché est **20 ms au lieu de 40** : la latence réelle est
divisée par deux et l'alerte à 50 ms ne se déclenche qu'à 100 ms réels. Il faut pondérer :
`(r/s·r_await + w/s·w_await) / (r/s + w/s)`, en récupérant aussi les colonnes `r/s` et `w/s`.

#### N2 : fausses alertes CRITIQUES sur les snaps Ubuntu (L1101)
Le filtre df exclut `tmpfs|cdrom|devtmpfs`, mais pas `squashfs`, `iso9660`, `overlay` ni
`/dev/loop*`. Sur toute Ubuntu avec des snaps, chaque `/dev/loopN squashfs … 100% /snap/…`
déclenche une alerte **CRITIQUE disque** (*reproduit*). Sur un hôte Docker, les `overlay`
dupliquent aussi la racine. Correctif : filtrer sur la colonne type (`awk '$2 !~ /^(tmpfs|devtmpfs|squashfs|iso9660|overlay)$/'`)
plutôt que par `grep` sur toute la ligne, ce qui règle aussi L7.

#### N3 : l'analyse SAR charge le serveur de production audité (L1680-1720)
La boucle distante lance, **pour chaque ligne** de `sar -d`, 4 `$(echo | awk)` et 2 `cut` (environ
12 fork/exec par ligne), et exécute `sar -d` 3 fois par fichier. Sur un mois d'historique à 10 min
avec 20 devices (dm-* compris), cela fait environ 28 × 144 × 20 ≈ 80 000 lignes, soit **près d'un million de
processus créés sur le serveur audité**, souvent déjà en difficulté puisqu'on l'audite. Un seul
`awk` par fichier (détection d'en-tête + seuils + sortie) fait le même travail en une passe.

### Moyens

#### N4 : `read -s` sans `-r` altère le mot de passe (L1946)
*Reproduit* : `ab\cd ` est lu comme `abcd`. Les `\` disparaissent et les espaces de début
et de fin sont retirés (IFS). L'authentification échoue alors sans message utile, puisque stderr
de sshpass est jeté. Correctif : `IFS= read -rs SSH_PASSWORD`.

#### N5 : environ 40 connexions SSH distinctes par audit (L143-160)
Chaque `ssh_exec` et chaque `remote_cmd_exists` ouvre une nouvelle connexion (42 sites d'appel,
environ 35-40 connexions à l'exécution). Conséquences : lenteur, bruit dans `auth.log` et
`secure`, et risque de blocage par `MaxStartups` ou fail2ban. En mode mot de passe, cela fait 40
authentifications par mot de passe. Correctif : multiplexage
`-o ControlMaster=auto -o ControlPath=<mktemp -d>/%C -o ControlPersist=60`, avec
`ssh -O exit` dans un `trap EXIT`.

#### N6 : pas de `--` avant la destination SSH (L156, L158, L179, L185)
`-u '-oProxyCommand=…'` produit l'argument `-oProxyCommand=…@host`, que ssh interprète comme
une option. Aucune frontière de privilège n'est franchie (c'est l'opérateur qui lance le
script), mais le problème devient réel dès que le script est appelé par un wrapper ou un
inventaire alimenté par des données externes. Ajouter `--` et refuser un utilisateur ou un
hôte commençant par `-`.

#### N7 : code de sortie toujours 0 (L2043)
Même avec des alertes CRITIQUES, et même quand toutes les collectes ont échoué (H11), le script
sort en 0. Il est donc inutilisable tel quel en supervision, en cron ou en CI. Proposition :
sortir en 2 s'il y a des alertes critiques, en 1 pour des warnings et en 0 sinon (convention
Nagios).

### Faibles

- **N8 (L1703)** : `sar -d` sans `-p`, donc les anomalies SAR affichent `dev8-0` et `dev253-1` au
  lieu de `sda` et `dm-1` (ou du nom LVM), ce qui les rend difficiles à rapprocher du tableau iostat.
- **N9 (L1563)** : le « Top 5 par I/O Disque » repose sur des compteurs **cumulés depuis le
  démarrage du processus**, pas sur un débit. Un démon ancien et peu actif passe devant un
  processus qui sature le disque en ce moment. Il faut soit deux mesures espacées, soit un
  libellé « cumulé ».
- **N10 (L1204-1212, L1359-1364, L1713-1715)** : les seuils I/O (90/70 %, 50 ms en temps réel ;
  80 %, 30 ms pour SAR) sont codés en dur, en double, et absents de la section 1 des seuils.
  Le CLAUDE.md annonce `await > 20 ms` alors que le code utilise 30 ms.
- **N11 (L1436, L1484 ; L873, L1766)** : l'appel SSH `ip -4 addr show` est fait deux fois à
  l'identique, et `detect_sar_path` aussi (1 à 2 connexions de plus chacun).
- **N12** : code mort : `SCRIPT_DIR` (L49), `disk_html_rows` (L1108), `iot1[]` (L1240).
- **N13** : duplication console/HTML. Chaque section re-parse ses données deux fois (df
  L1110/L1305, iostat L1181/L1337, diskstats L1266/L1373, netdev L1441/L1489, ps
  L1531/L1585…). C'est la cause directe des correctifs qu'il a fallu appliquer en double dans
  `d5539c7`. Il faudrait parser une seule fois en lignes normalisées, puis produire les deux
  sorties.
- **N14** : les commandes distantes passent par le shell de login de l'utilisateur. Avec
  `tcsh` ou `fish`, les `$(…)`, `$((…))` et `[ ]` échouent en silence. Il faut les envelopper
  dans `sh -c` ou les envoyer via `ssh … sh -s <<'EOF'`.

---

## 3. Plan de remédiation recommandé

Par ordre de rapport gain/effort :

1. **Robustesse des valeurs vides** (H11, H12, H13, M14) : un helper `is_int` / `is_num`
   appliqué avant toute arithmétique ou comparaison, et `ssh_exec` qui propage `$?`. Si le
   code retour vaut 255 (transport), on arrête l'audit au lieu de produire un rapport fabriqué.
2. **Quoting et glob** (H3, M1, N6) : options SSH dans un tableau (bash 3 le permet), `--`
   avant la destination, et `set -f` (ou `IFS='|' read -ra`) dans `html_table_row`.
3. **Fausses alertes** (N2, H4, H13, M7, N1) : filtre df sur le type, `NB_CPUS` depuis
   `nproc` ou `getconf _NPROCESSORS_ONLN` en repli, exclusion des lignes `RESTART`, await pondéré.
4. **Charge et performances** (N3, N5, N11) : un seul `awk` pour l'analyse SAR et le multiplexage
   SSH. La durée d'exécution et l'empreinte sur le serveur audité en seraient fortement réduites.
5. **Sécurité de l'opérateur** (H6, H7, H9, M11, N4) : valider les nombres avant `style=`,
   échapper les heures SVG, `umask 077`, `StrictHostKeyChecking=accept-new` au lieu de `no`,
   et `IFS= read -rs`.
6. **Exploitabilité** (N7, L6, M13) : code de sortie qui reflète les alertes, et vérification
   réelle de l'écriture du rapport et du contenu de l'export SAR (`zcat | head -c1`).
