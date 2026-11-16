# 01 — Installer le serveur

Ce guide installe la pile serveur de Vigie sur un VPS : frontal TLS (Caddy), collecteur et console Vigie, Wazuh
(manager, indexeur, dashboard) et AdGuard Home (DNS privé filtrant). L'installation proprement dite tient en trois
commandes ; tout est expliqué en détail dans [`infra/README.md`](../../infra/README.md), que ce guide ne recopie
pas : il vous oriente, ordonne les étapes et dit quoi vérifier.

Durée : une heure environ, dont une partie d'attente (téléchargement des images, démarrage de Wazuh).
Suite : [02 — compiler l'APK](02-compiler-apk.md) (vous pouvez le faire pendant que le serveur démarre).

> **Statut de vérification.** La pile a été installée, rejouée, sauvegardée puis restaurée en **mode TLS interne**
> sur une machine de 16 Go sans accès Internet sortant pour les conteneurs. Les points suivants n'ont **jamais été
> testés** : Let's Encrypt réel, téléchargement des listes de blocage, résolution amont par Quad9, mode ClientID
> (joker DNS-01), WireGuard, consommation mémoire avec les listes chargées, processeur ARM. La section 9 dit
> comment vérifier chacun après l'installation.

## 1. Choisir le VPS

| | Minimum | Conseillé |
|---|---|---|
| Mémoire | **8 Go** (Wazuh n'est pas pris en charge en dessous) | 8 Go et 2 Go de swap |
| Processeur | 2 vCPU | 4 vCPU |
| Disque | 30 Go SSD | 50 Go SSD (environ 90 jours d'archives pour un téléphone) |
| Système | Debian 12 ou Ubuntu 24.04 (noyau 5.10 ou plus) | |
| Réseau | adresse IPv4 publique fixe ; ports **80/tcp, 443/tcp et 853/tcp** joignables depuis Internet | IPv6 en plus |
| Architecture | x86_64 (seule testée) | |

À vérifier chez l'hébergeur avant de payer : que le port 853 entrant n'est pas filtré (c'est le DNS sur TLS du
téléphone) et que le pare-feu du fournisseur, s'il y en a un, vous laisse ouvrir 80, 443 et 853.

Le swap n'est pas créé par l'installation : si votre image n'en a pas, créez-en un de 2 Go (documentation de votre
distribution).

## 2. Nom de domaine et enregistrements DNS

Il vous faut un domaine (ou un sous-domaine d'un domaine à vous ; un nom gratuit DuckDNS ou deSEC convient aussi).
Dans la suite, `vigie.exemple.fr` est ce domaine de base. Créez chez votre fournisseur DNS, **avant** l'installation,
cinq enregistrements de type A pointant vers l'IPv4 du VPS :

```
console.vigie.exemple.fr    A   <IP du VPS>
ingest.vigie.exemple.fr     A   <IP du VPS>
siem.vigie.exemple.fr       A   <IP du VPS>
adguard.vigie.exemple.fr    A   <IP du VPS>
dns.vigie.exemple.fr        A   <IP du VPS>
```

- N'ajoutez les enregistrements AAAA (IPv6) que si vous avez **vérifié** que le VPS est joignable en IPv6 ; un AAAA
  qui ne mène nulle part fait échouer la validation du certificat. Commencez par les A seuls (recommandation de ce
  guide, non testée).
- Le joker `*.dns.vigie.exemple.fr` n'est utile que pour le mode ClientID (hors périmètre de ce guide, voir
  `infra/README.md` §6.3).
- Un TTL court (300 s) facilite un changement de serveur.

Let's Encrypt valide chaque nom par le port 80 : les noms doivent déjà pointer vers le VPS **au moment** de
l'installation. Vérifiez la propagation depuis le VPS (`getent hosts` existe partout) et depuis votre PC :

```bash
getent hosts console.vigie.exemple.fr ingest.vigie.exemple.fr siem.vigie.exemple.fr adguard.vigie.exemple.fr dns.vigie.exemple.fr
```

```powershell
foreach ($h in 'console','ingest','siem','adguard','dns') { Resolve-DnsName "$h.vigie.exemple.fr" -Type A }
```

Les cinq noms doivent renvoyer l'adresse du VPS. Si l'un manque, attendez : lancer l'installation avant la
propagation provoque des échecs de validation répétés auprès de Let's Encrypt, qui limite les tentatives.

## 3. Préparer le VPS

Connectez-vous en SSH, avec un compte qui a `sudo`. Installez Docker Engine **26 ou plus** et le greffon
`docker compose` v2 depuis le dépôt officiel (<https://docs.docker.com/engine/install/>) : les paquets `docker.io`
des distributions sont souvent trop anciens, et `install.sh` refuse de continuer avec un Docker antérieur à la version 26. Puis les outils
utilisés par les scripts :

```bash
sudo apt update && sudo apt install -y git openssl curl ufw
docker --version && docker compose version     # Docker >= 26, Compose v2
```

Récupérez le dépôt (remplacez l'adresse par celle de votre dépôt) :

```bash
git clone <adresse du dépôt> vigie && cd vigie/infra
```

Tout ce qui suit se lance depuis `vigie/infra`.

## 4. Installer

```bash
sudo ./install.sh --domain vigie.exemple.fr --email vous@exemple.fr --tls acme
```

- `--tls acme` : certificats Let's Encrypt (VPS public). `--tls internal` (AC interne de Caddy, pour des essais en
  réseau local) existe mais impose d'installer l'AC de Caddy sur chaque client : `infra/README.md` §3.
- `--profile strict` règle le filtrage DNS en strict dès l'installation. **Ne le faites pas maintenant** : le profil
  DNS par défaut (`equilibre`) est celui qui garde le téléphone utilisable ; voir le guide 05 pour changer plus tard.
- Sans options, `install.sh` pose les questions. L'option `--help` liste tout.

Ce que fait le script (résumé ; détail dans `infra/README.md` §3) : vérifie Docker, la mémoire et le disque ; règle
`vm.max_map_count` pour l'indexeur ; **génère tous les secrets** dans `infra/.env` et `infra/secrets/` ; construit
l'image du collecteur (quelques minutes) ; démarre l'indexeur, le collecteur, Wazuh, Caddy (qui obtient les
certificats) puis AdGuard Home ; crée le compte console `admin` ; importe les tableaux de bord Wazuh ; affiche un
récapitulatif.

Attendez la fin sans l'interrompre. Le premier lancement télécharge plusieurs images Wazuh et construit le
collecteur : comptez plusieurs minutes. Le dashboard Wazuh peut mettre plusieurs minutes de plus à être prêt ; le
script le dit (« pas encore prêt ») sans que ce soit une erreur.

Le script est **rejouable** : après toute modification de `infra/.env` ou du dépôt, relancez
`sudo ./install.sh --yes`. Il conserve les secrets existants **et ce que vous avez réglé dans les interfaces** : mot de passe
de la console changé avec `set-password`, réglages d'AdGuard Home, utilisateurs créés dans le dashboard Wazuh. Pour
repartir de zéro sur un point précis, il a des options explicites : `--reset-console-password` (repose le mot de passe de
`.env`), `--reset-adguard` (régénère toute la configuration d'AdGuard ; l'ancienne est gardée), `--renew-wazuh-certs` et
`--renew-wazuh-ca` (certificats internes de Wazuh, guide 05 §8). Le script annonce à la fin les notifications (désactivées par
défaut, guide 05 §3) et l'échéance des certificats internes de Wazuh.

Récupérez les mots de passe générés :

```bash
sudo cat secrets/identifiants.txt
```

Ils servent à : la console Vigie (`admin`), la première barrière des interfaces d'administration (Caddy,
compte `admin`), le dashboard Wazuh (`admin`) et AdGuard Home (`admin`). **Copiez ce fichier dans votre gestionnaire
de mots de passe**, il n'est pas versionné et n'existe qu'ici (et dans vos sauvegardes, section 7).

Si le script s'arrête en erreur : il affiche la ligne en cause ; regardez aussi `sudo docker compose ps` et
`sudo docker compose logs <service>`. Les pannes courantes (pas de certificat, indexeur en lecture seule…) sont dans
`infra/README.md` §8.4.

## 5. Pare-feu

```bash
sudo ./firewall/ufw.sh              # SSH (limité), 80, 443 et 853
```

Si votre SSH n'écoute pas sur le port 22 : `SSH_PORT=2222 sudo ./firewall/ufw.sh`. **Une erreur de port vous
enferme dehors** : ouvrez une seconde session SSH avant de lancer le script et ne la fermez pas tant que la
première ne se reconnecte pas.

Deux précisions importantes, issues de `infra/README.md` §4 :

- **Docker contourne ufw** pour les ports qu'il publie. Les seuls ports publiés sont 80, 443 et 853 (garanti par
  `docker-compose.yml`, pas par ufw) ; ufw protège le reste de l'hôte, SSH compris.
- Si le fournisseur a son propre pare-feu, ouvrez-y 80/tcp, 443/tcp, 853/tcp (et 22/tcp, ou votre port SSH).

Rien d'autre ne doit être joignable : ni 53, ni 9200, ni 55000, ni 1514/1515. Vous le vérifiez depuis votre PC (la
commande doit échouer ou expirer pour chacun de ces ports) :

```bash
nc -vz -w 3 <IP du VPS> 9200
```

```powershell
Test-NetConnection <IP du VPS> -Port 9200
```

## 6. Premiers accès

| Interface | Adresse | Identifiants |
|---|---|---|
| Console Vigie | `https://console.vigie.exemple.fr` | `admin` et le mot de passe de la console (`identifiants.txt`) |
| Wazuh (dashboard) | `https://siem.vigie.exemple.fr` | **deux connexions** : d'abord Caddy (`admin` + mot de passe « accès administration »), puis Wazuh (`admin` + mot de passe Wazuh) |
| AdGuard Home | `https://adguard.vigie.exemple.fr` | deux connexions de même : Caddy, puis AdGuard (`admin`) |

- Console Vigie : sans appareil enrôlé, elle affiche « Cet appareil n'a encore jamais envoyé de données » ou une liste
  d'appareils vide : c'est normal. Les pages sont décrites dans le [guide 05](05-exploitation.md).
- Wazuh : deux tableaux de bord sont déjà importés, « Vigie — sécurité du téléphone » et « Vigie — pistage et DNS »
  (dans le menu du dashboard, rubrique des tableaux de bord ; l'intitulé exact peut varier selon la version).
  Ils seront vides tant qu'aucun appareil n'envoie.
- AdGuard Home : à chaque `install.sh`, la configuration **gérée par Vigie** (compte `admin`, TLS et DoT, amonts Quad9 et
  Mullvad, DNSSEC, listes du profil, journal lu par Wazuh) est réappliquée, et le reste est **conservé** : règles
  personnalisées de l'interface, listes ajoutées, listes d'autorisation, clients, réécritures DNS, durée du journal.
  AdGuard est arrêté quelques secondes pendant la fusion : le DNS du téléphone est brièvement indisponible (voir
  `infra/README.md` §6.2 pour la règle complète). Vous pouvez aussi mettre des règles dans
  `infra/data/adguard/userfilters/regles-perso.txt` (guide 05).
- Si la console accepte mal votre mot de passe plusieurs fois de suite, elle limite les essais (10 échecs par
  adresse et par compte, puis un par minute).
- **Changer le mot de passe de la console** : la source de vérité est la base du collecteur.
  `sudo docker compose exec collector vigie-collector user set-password admin` (depuis `infra/`, saisie sans écho,
  12 caractères au minimum) change le mot de passe et ferme les sessions ouvertes ; `install.sh` ne l'écrasera plus.
  Le mot de passe de `.env` et de `secrets/identifiants.txt` n'est alors plus à jour : notez le nouveau.
  `sudo ./install.sh --reset-console-password` repose celui de `.env`. Les autres mots de passe (indexeur, API Wazuh, AdGuard,
  accès Caddy) se changent dans `.env` puis `sudo ./install.sh --yes` ; `--rotate-passwords` les régénère tous (guide 05 §8).

## 7. Sauvegardes

```bash
sudo ./backup.sh                          # backups/vigie-AAAAMMJJ-HHMMSS.tar.gz
gpg -c backups/vigie-AAAAMMJJ-HHMMSS.tar.gz   # chiffrer avant de sortir l'archive du serveur
```

L'archive contient **tous les secrets** (`.env`, `secrets/`) et la base du collecteur avec l'**autorité qui signe les
certificats des téléphones** : sans elle, il faut réenrôler tous les appareils. Elle ne contient pas l'index Wazuh
(volumineux ; les événements restent dans la base du collecteur) sauf avec `--with-siem` (qui arrête Wazuh pendant la
copie). Le collecteur est arrêté quelques secondes ; le téléphone garde ses événements en tampon et les renvoie.

- Copiez l'archive **chiffrée** hors du serveur, par exemple depuis votre PC :
  `scp vous@vps:~/vigie/infra/backups/vigie-….tar.gz.gpg .`
- Les anciennes sauvegardes ne sont pas supprimées automatiquement : nettoyez `infra/backups/` de temps en temps.
- La restauration (`sudo ./restore.sh backups/vigie-….tar.gz`) a été vérifiée après destruction de tous les volumes
  sur la **même** machine ; elle n'a jamais été essayée sur un serveur neuf. La procédure prévue pour un nouveau
  serveur est dans l'en-tête de `restore.sh` (installer Docker, cloner, copier l'archive, lancer le script, mettre à
  jour les enregistrements DNS).
- La clé de signature de l'APK (guide 02) **n'est pas** dans cette sauvegarde : elle se sauvegarde à part.
- Planifier la sauvegarde (cron) est possible mais n'est pas fourni ; si vous le faites, vérifiez le premier passage.

## 8. Enrôler le téléphone

Le serveur produit un fichier `.vigie` par appareil, qui contient l'adresse d'ingestion, l'identifiant, le jeton, le
**certificat client et sa clé privée**, et le nom d'hôte du DNS privé :

```bash
sudo ./enroll.sh s25                 # produit ./s25.vigie (droits 600)
sudo ./enroll.sh --list              # appareils : identifiant, dernier contact, expiration du certificat (« à renouveler » sous 30 jours)
sudo ./enroll.sh --renew s25         # nouveau fichier pour le MÊME appareil (guide 05 §8) : s25-renouvellement.vigie
sudo ./enroll.sh --revoke s25        # (nom ou dev_…) révoque un appareil : jeton et certificat refusés aussitôt
```

Faites cette étape au moment du [guide 03](03-telephone.md), pas avant (le fichier doit rester le moins longtemps
possible hors de l'application). Il se transfère par câble depuis votre PC : récupérez-le d'abord du serveur
(`scp vous@vps:~/vigie/infra/s25.vigie .`), puis le script `push-enrollment` le copie sur le téléphone. **Ensuite,
supprimez toutes les copies** (VPS, PC, téléphone) : `shred -u s25.vigie` sur le serveur ; sur Windows,
`Remove-Item .\s25.vigie` (la corbeille et le stockage SSD ne garantissent pas l'effacement : c'est la raison pour
laquelle le fichier a des droits 600 et ne doit jamais circuler par un canal non chiffré).

Le certificat de l'appareil est valable **2 ans** : `--list` en affiche l'échéance ; le renouvellement garde le même
identifiant d'appareil et le même historique (guide 05 §8).

## 9. Vérifier l'installation

Chaque ligne indique ce qui est attendu. Faites-les toutes une fois : elles remplacent les essais que l'environnement
de développement ne pouvait pas faire.

**Services**

```bash
sudo docker compose ps
```

Tous les services doivent être `healthy` (le dashboard Wazuh peut mettre plusieurs minutes).

**Certificats Let's Encrypt (jamais testé ici)**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://console.vigie.exemple.fr/healthz       # 200
echo | openssl s_client -connect dns.vigie.exemple.fr:853 -servername dns.vigie.exemple.fr 2>/dev/null | openssl x509 -noout -issuer -dates
```

La première commande doit afficher `200` sans erreur de certificat ; la seconde, un émetteur Let's Encrypt et des
dates valides (le DNS sur TLS utilise le certificat de `dns.…` obtenu par Caddy). En cas d'échec :
`sudo docker compose logs caddy` (DNS pas encore propagé, port 80 fermé).

**DNS filtrant et listes de blocage (jamais testé ici)** — depuis le dossier `infra` du VPS ou de votre PC (Python 3
suffit) :

```bash
python3 tools/dot-query.py dns.vigie.exemple.fr example.org                 # une vraie adresse
python3 tools/dot-query.py dns.vigie.exemple.fr app-measurement.com         # 0.0.0.0 : bloqué
python3 tools/dot-query.py dns.vigie.exemple.fr connectivitycheck.gstatic.com  # une vraie adresse : exception
```

Le deuxième domaine est dans la liste locale de Vigie, donc il est bloqué même si le téléchargement des listes
HaGeZi a échoué. Pour contrôler ce téléchargement, ouvrez AdGuard Home (rubrique des listes de blocage DNS, l'intitulé
exact peut varier) : les listes HaGeZi doivent afficher un nombre de règles non nul et une date de mise à jour ;
sinon, `sudo docker compose logs adguardhome`. La résolution amont (Quad9) est validée par le premier exemple.

**Mémoire (jamais testé avec les listes chargées)**

```bash
free -h
sudo docker stats --no-stream
```

Les limites des conteneurs totalisent environ 7 Go ; si le serveur swappe beaucoup ou si un conteneur est tué
(`sudo docker compose ps` montre un redémarrage), ajoutez du swap ou lisez `infra/README.md` §9.

**Ingestion : le certificat client est bien exigé**

```bash
curl -sS https://ingest.vigie.exemple.fr/api/v1/ping
```

Doit échouer à la poignée de main TLS (erreur curl, pas de code HTTP) : sans certificat enrôlé, rien n'entre.

**Règles Wazuh**

```bash
./wazuh/tests/run-tests.sh
```

Doit se terminer avec 0 échec (code de sortie 0). C'est la preuve que les règles sont chargées dans le manager.

**Port 853 depuis un réseau mobile** : certains réseaux filtrent le DNS sur TLS. Le test décisif se fait avec le
téléphone, au [guide 03](03-telephone.md) (palier 1, « DNS privé seul »).

**Premier renouvellement de certificat** : le certificat de `dns.…` est renouvelé par Caddy (environ tous les 60 jours,
politique Let's Encrypt habituelle) et AdGuard le recharge sans redémarrer ; cela a été vérifié en mode TLS interne.
Après le premier renouvellement réel, relancez la commande `openssl s_client` ci-dessus et vérifiez que la date
d'expiration a changé.

## 10. Ensuite

- [Compiler l'APK](02-compiler-apk.md) puis [configurer le téléphone](03-telephone.md).
- Exploitation courante, mises à jour, rétention : [guide 05](05-exploitation.md).
- Options non couvertes ici : WireGuard (`infra/README.md` §10.1, non testé), tuiles de carte auto-hébergées
  (§10.2, la carte de la console charge par défaut les tuiles d'OpenStreetMap, donc OpenStreetMap voit les zones que
  vous consultez ; voir le guide 05).
