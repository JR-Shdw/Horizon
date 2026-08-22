# Installer Resurgamus Horizon avec l'aide d'un assistant IA

> Ce guide permet à un assistant IA d'accompagner une personne
> non-technique pendant une installation locale de Resurgamus Horizon.
>
> Ouvrez votre assistant IA, dites-lui *"Je
> veux installer Resurgamus Horizon sur mon ordinateur. Lis ce fichier
> et guide-moi pas à pas."*, puis collez ce fichier dans le chat.
> Relisez chaque commande avant de l'exécuter : l'assistant peut mal
> interpréter une sortie ou votre environnement.
>
> Si une étape échoue, fournissez l'erreur exacte et le numéro de
> l'étape après avoir masqué tokens, mots de passe, hostnames et autres
> valeurs sensibles.

Le reste de ce document est écrit principalement pour l'assistant.

---

## Instructions pour l'assistant IA

Tu vas accompagner un utilisateur non-technique à travers
l'installation de Resurgamus Horizon (un vault de secrets self-hosted)
sur son ordinateur personnel pour un **usage local** (pas production,
pas exposé Internet).

### Principes opérationnels

1. **Une étape à la fois.** Montre une commande, attends la sortie de
   l'utilisateur, puis passe à la suivante. Ne colle pas un mur de
   commandes.
2. **Vérifie l'OS d'abord.** Demande à l'utilisateur sur quel système
   il est (distro Linux, macOS, Windows) avant de recommander une
   commande. Le chemin d'install Docker diffère significativement.
3. **Cite les commandes exactes.** Copie-les caractère par caractère
   depuis ce document. Ne paraphrase pas. N'ajoute pas de flags non
   demandés.
4. **Vérifie chaque étape avant la suivante.** Chaque étape a un
   pattern de "sortie attendue". Si ça ne match pas, replie sur le
   tableau de troubleshooting.
5. **Explique précisément les échecs.** Ne minimise pas une erreur et
   n'annonce pas de succès avant que la vérification documentée passe.
6. **Ne demande JAMAIS à l'utilisateur de partager son master password
   avec toi.** C'est l'unique chose qu'il choisit que personne d'autre
   ne devrait jamais voir.
7. **Reste dans le périmètre.** Ce document concerne l'**installation
   locale uniquement**. Si l'utilisateur demande à exposer le vault
   sur Internet, redirige vers `docs/DEPLOYMENT.md` et arrête - ce
   scénario est hors-scope pour ce guide.
8. **Aucune commande non approuvée par l'utilisateur.** Surtout rien
   de destructif (pas de `rm -rf`, pas de `docker system prune`, pas
   de `docker compose -f tools/docker-compose.quickstart.yml down -v` sans confirmation explicite).

### Limites de sécurité

- Modifier code ou fichiers de config dans le repo cloné
- Faire tourner un container en mode `--privileged`
- Exposer des ports en dehors de `127.0.0.1` ("localhost") sans demande explicite de l'utilisateur
- Désactiver une feature de sécurité mentionnée dans ce document
- Stocker le master password ou le root token de l'utilisateur dans
  ton contexte, dans le chat, ou ailleurs - dirige vers un password
  manager
- Recommander des outils / scripts pas dans ce document ; si
  l'utilisateur est bloqué sur quelque chose non-couvert, dis-le et
  pointe vers `docs/QUICKSTART.md` ou `docs/DEPLOYMENT.md`

---

## Étape 0 - Établir le contexte

Demander à l'utilisateur :

```
1. Sur quel système d'exploitation êtes-vous ? (distro Linux / macOS / Windows)
2. Avez-vous déjà utilisé un terminal / ligne de commande ? (oui / un peu / jamais)
3. Avez-vous Docker installé ? (oui / non / pas sûr)
4. Combien d'espace disque libre avez-vous ? (besoin de 3 Go minimum)
5. Combien de RAM votre ordinateur a-t-il ? (besoin de 512 Mo libres minimum)
```

Si la RAM est sous 512 Mo ou le disque sous 3 Go, **arrête**. Dis
honnêtement les prérequis. Le gros du disque, ce sont les images
containers. Le tier `home` par défaut utilise un worker et constitue
le profil laptop supporté. N'invente pas de nombre intermédiaire :
le mode cluster commence au tier `smb` documenté, avec cinq workers.

---

## Étape 1 - Installer Docker (si pas déjà fait)

L'utilisateur a déjà Docker si `docker --version` retourne une version
>= 24.

### Linux (Debian / Ubuntu)

```bash
# Script d'install officiel - à examiner avant de piper dans sh !
# (Explique en termes simples ce que ça fait.)
curl -fsSL https://get.docker.com | sh

# Ajouter l'utilisateur au groupe docker pour ne pas avoir besoin de sudo
sudo usermod -aG docker $USER
# Il DOIT se déconnecter et se reconnecter (ou rebooter) pour que ça prenne effet
```

Vérifier après reconnexion :

```bash
docker --version              # attendu : Docker version 24.x ou plus
docker compose version        # attendu : Docker Compose version v2.x.x
```

### Linux (Arch / Manjaro)

```bash
sudo pacman -S docker docker-compose
sudo systemctl enable --now docker.service
sudo usermod -aG docker $USER
# Se déconnecter / reconnecter
```

### Linux (Fedora / RHEL / Rocky)

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Se déconnecter / reconnecter
```

### macOS

Recommander un de ceux-ci (équivalents pour notre usage) :

- **OrbStack** (léger, rapide, gratuit pour usage perso) - https://orbstack.dev/
- **Docker Desktop** - https://www.docker.com/products/docker-desktop/
- **Colima** (CLI uniquement) - `brew install colima docker docker-compose && colima start`

Après installation, vérifier :

```bash
docker --version
docker compose version
```

### Windows

Installer **Docker Desktop avec backend WSL2** - https://www.docker.com/products/docker-desktop/

L'utilisateur aura besoin de :

- Windows 10/11 avec WSL2 activé (`wsl --install` dans PowerShell admin si pas déjà)
- Virtualisation Hyper-V activée dans le BIOS

Après install, l'utilisateur ouvre **Ubuntu** (ou sa distro WSL2
préférée) et continue depuis là. **N'essaie pas de faire tourner
rhorizon depuis PowerShell ou cmd.exe** - utiliser le shell WSL2.

Dans WSL2, vérifier :

```bash
docker --version
docker compose version
```

---

## Étape 2 - Récupérer le code source

```bash
# Dans un répertoire sensé comme ~/projects
mkdir -p ~/projects && cd ~/projects

# Cloner le miroir public
git clone https://github.com/JR-Shdw/Horizon.git rhorizon
cd rhorizon
```

Si `git` n'est pas installé :

| OS | Installer |
|---|---|
| Debian/Ubuntu | `sudo apt install git` |
| Arch/Manjaro | `sudo pacman -S git` |
| Fedora | `sudo dnf install git` |
| macOS | `brew install git` (ou accepter le prompt Apple pour Xcode CLI) |
| Windows (WSL2) | `sudo apt install git` dans Ubuntu |

Vérifier :

```bash
git --version
ls
# attendu : api  CLAUDE.md  docker-compose.yml  docs  env.example  ...
```

---

## Étape 3 - Configurer (fichier .env)

```bash
cp env.example .env
```

Maintenant générer un password PostgreSQL solide et l'écrire dans `.env` :

```bash
sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 32)|" .env
rm .env.bak                # le sed macOS crée un backup ; le retirer
```

Montre à l'utilisateur ce qui a été modifié :

```bash
grep '^POSTGRES_PASSWORD=' .env
# attendu : POSTGRES_PASSWORD=<64 caractères hex>
```

Ce password est utilisé par Postgres en interne et n'est PAS le master
password de l'utilisateur. Il n'a pas besoin de le retenir.

---

## Étape 4 - Démarrer le stack

```bash
docker compose -f tools/docker-compose.quickstart.yml up -d
```

**Utilisez exactement ce fichier.** Le dépôt a aussi un `docker-compose.yml` à sa racine, mais celui-là est la stack
opérateur/VPN : il publie sur `10.0.0.1` et `10.0.1.1`, donc sur un laptop normal Docker refuse de
démarrer et affiche *« Couldn't listen on requested ports »*. Le fichier quickstart ne bind que
`127.0.0.1`, ce qui est ce que vous voulez ici.

Ça pull l'image Postgres (~150 Mo) et build les images API et frontend
localement. **Le premier build prend 5-15 minutes** selon la machine.
Les runs suivants sont instantanés.

Si le build est lent, dis à l'utilisateur que c'est normal. Il peut
suivre la progression avec `docker compose -f tools/docker-compose.quickstart.yml logs -f` dans un autre
terminal s'il le souhaite, mais ce n'est pas nécessaire.

Quand le prompt revient, vérifier :

```bash
docker compose -f tools/docker-compose.quickstart.yml ps
```

Sortie attendue : trois services au statut `running` ou `running (healthy)` :
- `rhorizon_postgres`
- `rhorizon_api`
- `rhorizon_frontend`

Attendre jusqu'à 60 secondes que les healthchecks se stabilisent. Puis :

```bash
curl http://localhost:8200/health
# attendu : {"status": "ok"}
```

Si pas de `curl`, ouvrir `http://localhost:8200/health` dans un
navigateur - même résultat.

---

## Étape 5 - Choisir un master password

**ARRÊTE-TOI ICI et lis ceci à l'utilisateur, mot pour mot :**

> La prochaine étape demande un master password. C'est le **secret
> le plus important** de tout votre vault. **Si vous le perdez, tous
> les secrets que vous mettrez dans le vault sont irrécupérables**
> (c'est précisément le but - il n'y a pas de lien "mot de passe
> oublié").
>
> Choisissez quelque chose :
>
> - **Long.** 16+ caractères minimum. Une passphrase comme "correct horse battery staple seven" convient.
> - **Unique.** Ne réutilisez pas un mot de passe d'ailleurs.
> - **Mémorable pour vous.** Une chaîne aléatoire impossible à retenir est pire qu'une passphrase longue.
>
> **Sauvegardez-le à DEUX endroits :**
>
> 1. Un password manager (KeePassXC, Bitwarden, 1Password, ...)
> 2. **Hors ligne** - écrit sur papier dans un coffre, ou imprimé et stocké chez vous
>
> Ne collez pas le password dans cette conversation IA. Ne vous
> l'envoyez pas par email. Ne le mettez pas dans un fichier texte sur
> votre bureau.
>
> Quand vous êtes prêt-e, dites-moi que vous êtes prêt-e et je vous
> montrerai la commande. **Tapez le password directement dans votre
> terminal - pas dans ce chat.**

Attends la confirmation de l'utilisateur qu'il/elle a préparé le password.

---

## Étape 6 - Unseal (première fois)

Demande à l'utilisateur de saisir le mot de passe maître directement dans son
terminal :

```bash
read -rsp "Master password: " PASSWORD && echo
printf '%s' "$PASSWORD" \
  | python3 -c 'import json,sys; print(json.dumps({"password": sys.stdin.read()}))' \
  | curl -X POST http://localhost:8200/api/v1/vault/unseal \
  -H "Content-Type: application/json" \
  --data-binary @-
unset PASSWORD
```

Le mot de passe est lu sans écho, encodé depuis l'entrée standard et ne figure
ni dans l'historique ni dans les arguments d'un processus. Il existe brièvement
dans la mémoire de bash, Python et curl, ce qui est nécessaire pour l'envoyer.

**Réponse attendue** (formatée) :

```json
{
  "status": "unsealed",
  "root_token": "rh_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

⚠️ **Dis à l'utilisateur** : cette valeur `rh_xxx` est son **root
token**. Il ne sera affiché qu'une seule fois. Il faut le sauvegarder
de la même façon que le master password (password manager + copie
offline).

Le root token est ce qu'il/elle utilisera pour s'authentifier à chaque
appel API depuis ses scripts et outils.

---

## Étape 7 - Vérifier que ça marche

```bash
curl http://localhost:8200/api/v1/vault/status
# attendu : {"sealed": false, "version": "0.9.0-beta", ...}
```

Si `sealed` est `true`, quelque chose a foiré. Refaire l'étape 6.

Ouvrir l'UI web :

- Linux : `xdg-open http://localhost:8200`
- macOS : `open http://localhost:8200`
- Windows (WSL2) : coller `http://localhost:8200` dans le navigateur

L'utilisateur devrait voir le dashboard "Horizon" avec un indicateur
**vert** disant que le vault est unsealed.

---

## Étape 8 - Stocker le premier secret de l'utilisateur

Dans l'UI web :

1. Cliquer sur **Eclipse** (Secrets) dans la sidebar
2. Coller son root token dans le prompt en haut, puis cliquer "Set token"
3. Cliquer "+ New secret"
4. Nom : `test-secret`, Valeur : `hello world`, cliquer Save
5. Le secret devrait apparaître dans la liste

Ou en ligne de commande :

```bash
TOKEN="rh_xxxxxxxxxxxxx"   # lui faire coller son root token ici
curl -X POST http://localhost:8200/api/v1/vault/secrets/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-secret", "value": "hello world"}'

# Le relire
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8200/api/v1/vault/secrets/test-secret
# attendu : {"name": "test-secret", "value": "hello world", ...}
```

---

## Étape 9 - Quoi faire ensuite (pour l'utilisateur)

Félicite l'utilisateur. Puis suggère ces étapes (dans cet ordre) :

1. **Lire [`docs/fr/QUICKSTART.md`](QUICKSTART.md)** - couvre la
   configuration 2FA (TOTP / YubiKey / WebAuthn), la génération de
   tokens scopés pour les scripts, le Shamir Secret Sharing, et le
   backup.
2. **Mettre en place la 2FA.** Hautement recommandé. Le chemin le
   plus simple est TOTP (avec une app smartphone comme Aegis, Google
   Authenticator, ou 1Password).
3. **Planifier un backup.** Un vault ne vaut que ce que vaut son
   backup. Un `pg_dump` quotidien + le volume audit suffit pour un
   usage perso ; voir [`docs/fr/DEPLOYMENT.md`](DEPLOYMENT.md#9-sauvegarde--restauration).
4. **Après chaque reboot, ré-unseal** avec la même commande de
   l'étape 6. C'est le design - le vault ne persiste jamais les clés
   sur disque.

---

## Troubleshooting - erreurs courantes

| L'utilisateur dit / voit | Cause | Fix |
|---|---|---|
| `command not found: docker` | Docker pas installé | Étape 1 |
| `permission denied while trying to connect to the Docker daemon socket` | User pas dans le groupe `docker`, ou pas déconnecté/reconnecté après l'étape 1 | Lancer `groups` - si `docker` n'est pas là, `sudo usermod -aG docker $USER` puis se déconnecter / reconnecter. Sur les systèmes sans support de groupes, utiliser `sudo` devant chaque commande `docker`. |
| `bind: address already in use` sur port 8200 | Un autre service utilise ce port | `ss -tlnp \| grep 8200` (Linux) ou `lsof -i :8200` (mac) pour trouver le conflit. L'arrêter, ou changer `VAULT_API_BIND` / le port mapping (avancé - voir `DEPLOYMENT.md`). |
| `docker compose -f tools/docker-compose.quickstart.yml up` reste bloqué sur "Building" | Internet lent / CPU lent | Patience. Le premier build prend vraiment 5-15 min sur du matos moyen. |
| `pull access denied for postgres` | Souci DNS ou réseau, peut-être derrière un proxy entreprise | Tester `docker pull postgres:18-trixie` directement. Si ça échoue, vérifier `~/.docker/config.json` pour les paramètres proxy, ou questionner l'utilisateur sur son réseau. |
| `unhealthy` sur `rhorizon_postgres` | Postgres a échoué à démarrer | `docker compose -f tools/docker-compose.quickstart.yml logs postgres` et lire les 30 dernières lignes. Le plus souvent : pas assez de RAM, ou `POSTGRES_PASSWORD` vide dans `.env`. |
| `connection refused` sur `curl http://localhost:8200/health` | API pas encore prête | Attendre 30 secondes et retry. Si toujours en échec, `docker compose -f tools/docker-compose.quickstart.yml logs api` |
| `{"sealed": true}` après unseal | Mauvais password ou 2FA mal configurée | Re-vérifier le password (sensible à la casse !). Si la 2FA est activée mais qu'aucun token n'est fourni, la requête unseal échoue. |
| L'UI web affiche "Cannot connect" | Container API pas en marche | `docker compose -f tools/docker-compose.quickstart.yml ps`, puis `docker compose -f tools/docker-compose.quickstart.yml logs api` |
| L'utilisateur veut tout recommencer | Master password foiré et pas de données auxquelles il/elle tient | `docker compose -f tools/docker-compose.quickstart.yml down -v` - **ATTENTION** : supprime la base. Confirmer avec l'utilisateur. Puis recommencer à l'étape 4. |
| Le build échoue avec `cargo: command not found` ou erreurs Rust | Souci de cache de build | `docker compose build --no-cache api` |
| Erreurs `disk full` | Plus d'espace disque | Vérifier `df -h`. Libérer ou ajouter du disque. Les images Docker seules ont besoin de ~3 Go. |

---

## Règles d'escalade

Renvoie l'utilisateur vers un humain (issue tracker, mailbox sécurité,
ou retour à la doc) si :

- Il/elle veut exposer le vault sur Internet -> **STOP**, pointer vers `docs/DEPLOYMENT.md`, refuser d'assister sur cette topologie
- Il/elle veut déployer sur Kubernetes -> pointer vers `docs/K8S.md`
- Il/elle veut intégrer avec Ansible / CI / agents -> pointer vers `docs/USE-CASES.md`
- Il/elle signale une vulnérabilité de sécurité -> pointer vers `SECURITY.md`
- Il/elle veut contribuer / fixer un bug -> pointer vers `CONTRIBUTING.md`
- Il/elle perd son master password -> dis-le honnêtement : **le vault est irrécupérable**. Les données sont chiffrées avec une clé dérivée de ce password et il n'y a pas de backdoor par design. Il/elle devra recommencer avec `docker compose -f tools/docker-compose.quickstart.yml down -v` et un nouveau password.

---

## Auto-vérification pour l'IA avant de finir

Avant de déclarer l'install réussie :

- [ ] Les trois containers affichent `running (healthy)` dans `docker compose -f tools/docker-compose.quickstart.yml ps`
- [ ] `curl http://localhost:8200/health` retourne `{"status": "ok"}`
- [ ] `curl http://localhost:8200/api/v1/vault/status` retourne `"sealed": false`
- [ ] L'utilisateur a sauvegardé son master password ET son root token à deux endroits (password manager + offline)
- [ ] L'utilisateur sait que rebooter requiert un re-unseal
- [ ] Tu n'as pas stocké le master password ni le root token où que ce soit

Si une vérification est incomplète, termine-la avant de dire au revoir.
