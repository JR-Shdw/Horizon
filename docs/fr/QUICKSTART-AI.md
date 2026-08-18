# Brancher un assistant IA sur des secrets sélectionnés

> Ce setup local sort les credentials du chat et des fichiers `.env`
> lisibles. Une policy MCP contrôle les secrets que l'assistant peut
> demander :
>
> - les secrets restent dans une petite base chiffrée sur ton
>   ordinateur ;
> - l'IA ne voit que ce que tu autorises ;
> - tu peux voir, après coup, chaque secret qu'elle a lu et quand ;
> - l'accès peut être révoqué sans supprimer un fichier local.
>
> Ce modèle ne protège ni un hôte compromis, ni un secret divulgué par
> un assistant que tu as explicitement autorisé à le lire. Relis le
> script de bootstrap et la policy avant utilisation.

---

## Avant de commencer (1 minute)

Il te faut **trois choses** sur ton ordinateur :

1. **Docker** (ou **Podman** avec son shim Docker) - c'est ce qui
   fait tourner le petit serveur qui tient tes secrets. Si tu as
   déjà Docker Desktop, c'est bon.
2. **Un terminal** - Terminal sur macOS, n'importe quel terminal
   sur Linux, l'app Ubuntu dans WSL2 sur Windows.
3. **Environ 1 Go d'espace disque libre** pour les images Docker.

Si tu n'as pas Docker :

| Ton OS | Installer Docker |
|---|---|
| macOS | Installe Docker Desktop : https://www.docker.com/products/docker-desktop/ - ouvre-le une fois, accepte les prompts. |
| Linux (Debian, Ubuntu, Fedora, Arch, ...) | Utilise le gestionnaire de paquets de ta distribution. Le plus rapide : `curl -fsSL https://get.docker.com \| sh` puis `sudo usermod -aG docker $USER` et déconnecte / reconnecte ta session. |
| Windows | Installe **WSL2** (cherche "WSL" dans Windows Update / PowerShell : `wsl --install`), puis installe Ubuntu depuis le Microsoft Store, puis suis la ligne Linux ci-dessus **dans le terminal Ubuntu**. |

Il te faut aussi un **assistant IA de bureau compatible MCP** (l'app
locale, pas le site web) si tu veux qu'il utilise tes secrets - par
exemple Claude Desktop, Cursor, Cline, Continue ou Codex. Tous
fonctionnent avec le même setup.

---

## Deux options : container ou natif

Deux installs supportées, même résultat. Choisis celle qui te va :

| Option | Ce qui tourne | Pour qui |
|---|---|---|
| **Container** (défaut, recommandé) | Un petit PostgreSQL + API + frontend dans des conteneurs **Docker**. | Quiconque a déjà Docker (Mac, Windows, Linux). Mise à jour via `docker compose pull`. |
| **Natif** | PostgreSQL + venv Python + uvicorn directement sur l'hôte - pas de Docker, pas de conteneurs. | Empreinte plus légère. WSL2 sans Docker Desktop. Linux laptops où tu préfères utiliser le PostgreSQL système. |

Dans le doute, prends le path container - c'est celui qu'on teste en CI.

### Path container (3 minutes - une commande)

Ouvre un terminal. Colle ça - **une seule ligne, pas de clone, pas de
setup** :

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh | bash
```

C'est tout.

Si tu préfères inspecter le script avant (toujours une bonne
habitude) :

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh -o quickstart.sh
less quickstart.sh        # un coup d'œil
bash quickstart.sh        # lancement
```

Si tu as déjà cloné le repo (développeurs) :

```bash
make laptop               # équivalent à : bash tools/quickstart-laptop.sh
```

### Path natif (5 minutes - Linux + WSL2 uniquement)

Même forme de commande, autre script. L'install native a besoin de
`sudo` pour installer PostgreSQL + libs système - le script demande
ton mot de passe une fois au début.

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop-native.sh | bash
```

Ou depuis un checkout :

```bash
make laptop-native        # équivalent à : bash tools/quickstart-laptop-native.sh
```

L'install native supporte : Debian, Ubuntu, Arch, Manjaro, Fedora,
Rocky, AlmaLinux, openSUSE - et n'importe laquelle de ces distros
sous WSL2. Sur macOS, l'install native n'est pas encore supportée -
prends le path container.

L'install native utilisateur suit le layout XDG normal :

| Usage | Chemin |
|---|---|
| App/checkout source (`curl \| bash`) | `~/.local/share/rhorizon/source` |
| Config, env, secrets locaux | `~/.config/rhorizon` |
| Etat, logs fallback, fichiers PID | `~/.local/state/rhorizon` |
| Sockets runtime | `$XDG_RUNTIME_DIR/rhorizon` ou `~/.local/state/rhorizon/run` |
| Logs d'audit JSONL | `~/.local/state/rhorizon/audit` |

Après l'install, gère l'API comme n'importe quel service :

```bash
# si ta distro / WSL2 supporte systemd (la plupart) :
systemctl --user status rhorizon-api
systemctl --user [start|stop|restart] rhorizon-api
journalctl --user -u rhorizon-api -f      # logs

# fallback (pas de systemd) :
cat ~/.local/state/rhorizon/api.pid       # PID du uvicorn qui tourne
tail -f ~/.local/state/rhorizon/api.log
kill $(cat ~/.local/state/rhorizon/api.pid)  # stop
```

Le script va :

1. Construire et démarrer un petit coffre-fort chiffré sur ton
   ordinateur. Le mode container utilise Docker ; le mode natif
   utilise PostgreSQL + uvicorn directement sur l'hôte.
2. Choisir un mot de passe principal solide pour toi et le
   sauvegarder sur disque
   (`~/rhorizon/secrets/master-password` pour le container,
   `~/.config/rhorizon/secrets/master-password` pour le natif).
3. Installer le petit programme passerelle qui permet à ton
   assistant IA de parler au coffre-fort.
4. Donner à ton assistant IA sa propre clé d'accès - distincte de la
   tienne, et en lecture seule par défaut.
5. Imprimer un petit bloc JSON à la fin. **Garde ce qu'il
   imprime**, tu vas le coller dans la config de ton assistant IA à
   l'étape suivante.

Relancer le script est sans danger : il saute les étapes déjà
faites.

---

## Dire à ton assistant IA d'utiliser le coffre-fort (1 minute)

Quand le script termine, il imprime un bloc qui ressemble à ça :

```json
{
  "mcpServers": {
    "rhorizon": {
      "command": "/home/toi/.local/share/rhorizon-mcp/.venv/bin/rhorizon-mcp-server",
      "env": {
        "RH_VAULT_URL": "http://127.0.0.1:8200",
        "RH_TOKEN_FILE": "/home/toi/.config/rhorizon/mcp.token",
        "RH_MCP_POLICY": "/home/toi/.config/rhorizon-mcp/policy.toml"
      }
    }
  }
}
```

Ouvre le fichier de configuration MCP de ton assistant IA et fusionne
l'entrée `"rhorizon"` dans sa section `"mcpServers"`. Chaque client
range ce fichier à un endroit différent. Pour **Claude Desktop** il
se trouve ici :

| Ton OS | Chemin |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| Windows (WSL) | `%APPDATA%\Claude\claude_desktop_config.json` (à ouvrir depuis l'Explorateur Windows ; l'app de bureau tourne sur Windows, pas dans WSL) |

**Cursor, Cline, Codex, Continue** et les autres ont chacun leur
propre fichier de config (par ex. `.mcp.json` dans un projet,
`~/.codex/config.toml`, les réglages de l'app) - le même bloc
`rhorizon` va dans leur section serveurs MCP. Voir les exemples de
connecteurs livrés sous `mcp/` (`claude.mcp.json`, `codex.config.toml`,
`opencode.json`).

Si le fichier n'existe pas, crée-le avec le bloc ci-dessus.

S'il existe déjà, fusionne l'entrée `"rhorizon"` dans ton objet
`"mcpServers"` existant - sans perdre ce qui s'y trouve déjà.

Quitte ton assistant IA complètement (pas juste la fenêtre - "Quitter"
via l'icône barre de menus / zone de notification), puis rouvre-le.
Dans une nouvelle conversation, demande :

> *"Qu'est-ce que tu peux faire avec rhorizon ?"*

Il devrait répondre qu'il a six outils disponibles, tous en lecture
seule, et que rien n'est encore autorisé (ce qui est le défaut
sécurisé).

---

## Frontière de sécurité après installation

Le setup crée les frontières de confiance locales suivantes :

| Où | Ce qu'il y a | Qui peut lire |
|---|---|---|
| Base du coffre-fort | Enregistrements de secrets chiffrés | La base seule ne suffit pas à les déchiffrer. |
| `~/rhorizon/secrets/master-password` (container) ou `~/.config/rhorizon/secrets/master-password` (natif) | Mot de passe principal en clair | Ton compte et root sur l'hôte. Le mode `0400` bloque les autres utilisateurs non privilégiés, pas root ni la compromission de ton compte. |
| `~/rhorizon/secrets/root-token` (container) ou `~/.config/rhorizon/secrets/root-token` (natif) | Token admin du coffre-fort | Ton compte et root sur l'hôte. |
| `~/.config/rhorizon/mcp.token` | Token vault en lecture seule de l'assistant | Le serveur MCP, ton compte et root. Il est distinct du token admin. |
| `~/.config/rhorizon-mcp/policy.toml` | La liste des secrets que ton assistant IA a le droit de lire | Actuellement **vide**. L'assistant ne peut rien lire tant que tu n'as pas ajouté à cette liste. |

Le quickstart laptop stocke le mot de passe principal près du stack
local pour simplifier l'usage. Active le chiffrement complet du disque
et verrouille ta session. Un disque non chiffré volé, un accès root ou
la compromission de ton compte peut exposer la base chiffrée et son
matériel de recovery. Garde le matériel de recovery hors hôte
séparément, selon [`DISASTER-RECOVERY.md`](../DISASTER-RECOVERY.md).

Deux propriétés restent garanties :

1. **Tu peux donner un secret à ton assistant IA sans lui donner
   *tous* les secrets.** Chaque secret stocké dans le coffre-fort
   reste inaccessible à l'IA tant que tu n'ajoutes pas explicitement
   son nom au fichier de policy. Ajouter les secrets d'un deuxième
   client l'an prochain n'ouvre pas l'accès aux secrets du
   premier.

2. **Les lectures sont auditées.** Chaque lecture par l'assistant
   enregistre l'acteur, la cible et le timestamp dans la chaîne d'audit
   tamper-evident. Vérifie la chaîne avant de l'utiliser comme preuve.

---

## Étape suivante

[`AI-PROMPTS.md`](AI-PROMPTS.md) contient des prompts relus pour les
opérations courantes :

- Ajouter un nouveau secret pour un client
- Donner à ton assistant IA l'accès à un secret précis pour une tâche
- Révoquer un accès dont tu n'as plus besoin
- Voir ce que l'IA a lu la semaine dernière
- Changer ton mot de passe principal

Chaque prompt garde les valeurs secrètes hors du chat et impose une
relecture avant d'approuver commandes ou changements de configuration.

---

## Si quelque chose cloche

| Symptôme | Première chose à tenter |
|---|---|
| `docker: command not found` | Installer Docker d'abord (voir haut de page). |
| `permission denied` sur Docker | Sur Linux, il faut être dans le groupe `docker` : `sudo usermod -aG docker $USER` puis déconnecter / reconnecter. |
| Le script a tourné mais ton assistant ne voit pas "rhorizon" | As-tu **complètement quitté** l'app et l'as relancée ? Fermer la fenêtre ne suffit pas - quitter via l'icône barre de menus / zone de notification. |
| Ton assistant dit "je vois rhorizon mais aucun outil" | Le fichier de policy est vide (défaut sécurisé). Ouvre `AI-PROMPTS.md` et copie le prompt "donner accès à un secret". |
| `port already in use` | Un autre programme utilise le port 8200. Relance avec un autre port : `RH_API_PORT=8210 bash tools/quickstart-laptop.sh`. |
| Autre chose | Donne à l'assistant l'erreur exacte et le numéro d'étape après avoir masqué secrets et identifiants locaux. La séquence de diagnostic est dans [`AI-INSTALL-GUIDE.md`](../AI-INSTALL-GUIDE.md). |

---

## Plateformes testées

| Plateforme | Statut |
|---|---|
| Linux (Debian, Ubuntu, Arch, Fedora) | Plateforme principale, testée en continu en CI. |
| macOS (Apple Silicon + Intel) | Supportée. Requiert Docker Desktop. Même script, mêmes chemins sous `~/`. Le chemin de config de ton assistant IA est spécifique à l'OS (voir le tableau Claude Desktop plus haut à titre d'exemple). |
| Windows (WSL2 + Ubuntu) | Supportée. Lance le script *dans* le terminal Ubuntu WSL2. Le coffre-fort écoute sur `127.0.0.1:8200` de WSL ; ton assistant IA tourne sur Windows et l'atteint via `localhost` (WSL2 forwarde) et via un wrapper `wsl.exe` pour le serveur MCP lui-même. Le script auto-détecte WSL et imprime le bon snippet JSON Windows (avec `wsl.exe -d <distro>, env ... rhorizon-mcp-server` au lieu d'un chemin Linux nu). Le chemin de config est celui de Windows - une app de bureau comme Claude Desktop est une app Windows, pas une app WSL. |

Si ta plateforme manque ou casse, ouvre une issue. Les chemins macOS
et Windows-WSL doivent rester fluides.

## Portée - un setup pour ordinateur personnel

Ça tourne sur ton laptop et ça écoute seulement sur `127.0.0.1` (ta
propre machine, rien d'autre n'y a accès). L'exposer sur Internet
public est un setup différent avec TLS, reverse proxy et 2FA,
documenté à part dans [`DEPLOYMENT.md`](DEPLOYMENT.md).

Ça garde aussi tes secrets chiffrés et accessibles à ton assistant IA
sur ce seul ordinateur. Si ton laptop meurt, restaure depuis une
sauvegarde (voir le prompt "sauvegarde" dans
[`AI-PROMPTS.md`](AI-PROMPTS.md)).

---

## Version anglaise

English version : [`../QUICKSTART-AI.md`](../QUICKSTART-AI.md).
