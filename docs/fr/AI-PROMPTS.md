# Prompts à donner à ton assistant IA

Chaque section ci-dessous est un prompt autonome. Remplace seulement
les placeholders `<...>` qui ne sont pas secrets. Relis les commandes
et changements de configuration avant de les approuver. Ne mets
jamais un secret, un token ou le mot de passe principal dans le prompt.

Ces prompts supposent que tu as déjà suivi
[`QUICKSTART-AI.md`](QUICKSTART-AI.md). Si ce n'est pas
fait, commence par là.

---

## La règle que suivent tous les prompts de cette page

**Ton assistant détient exactement un credential : sa propre clé.** Cette clé
est en lecture seule et valide dans une seule section du coffre-fort. Il ne
reçoit jamais de credential d'administration, et aucun prompt ci-dessous ne lui
indique où en trouver un.

Ce n'est pas de la politesse, c'est la seule chose qui fait tenir le reste. La
clé de l'assistant est bornée par une autorisation que le coffre-fort vérifie à
chaque requête : quoi qu'il en fasse, il ne peut pas sortir de sa section. Un
token admin n'est borné par rien : il lit toutes les sections, crée des clés et
verrouille le coffre-fort. Lui en donner un jette la frontière en une étape, et
l'assistant n'a même pas besoin de mal se comporter pour que ça compte : tout ce
qui peut lire ses fichiers hérite de la même portée.

Donc quand une opération demande plus d'autorité que la clé de l'assistant,
**c'est toi qui lances la commande et le credential reste dans ton shell.**
L'assistant écrit la commande, l'explique, et lit la sortie que tu lui colles.
Il n'ouvre pas de fichier de credentials, et tu ne colles pas de credentials
dans le chat.

## Deux façons dont ton assistant a reçu sa clé

| Ta situation | Comment la clé a été émise |
|---|---|
| **Install AI-secure** : ton assistant t'a guidé dans le quickstart | Le script a créé la section, émis une clé en lecture seule limitée à cette section, accordé l'entrée à cette clé, et affiché le token admin **une fois, pour toi**. L'assistant ne l'a jamais vu. |
| **Horizon existant** : le coffre-fort tournait déjà | Un administrateur émet une clé limitée, lui accorde l'entrée d'une section, et pointe la config de l'assistant dessus. On lui remet la clé, jamais de quoi l'élargir. |

Pour le second cas, voici la préparation côté opérateur. À lancer toi-même, avec
un token admin dans ton propre shell. C'est la forme que le quickstart automatise :

```sh
export RH_TOKEN='<ton-token-admin>'       # ton shell uniquement, jamais le chat
BASE=http://127.0.0.1:8200/api/v1/vault

# 1. Un groupe qui possédera la section de l'assistant.
GID=$(curl -fsS -X POST "$BASE/groups/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agents","permissions":{"secrets":"r"}}' | jq -r .id)

# 2. La section, possédée par ce groupe, appartenance appliquée.
#    enforce_membership est un cliquet : impossible de le relâcher ensuite.
curl -fsS -X POST "$BASE/namespaces/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"mcp\",\"owner_group_id\":\"$GID\",\"enforce_membership\":true}"

# 3. La clé de l'assistant : lecture seule, une section.
MINT=$(curl -fsS -X POST "$BASE/tokens/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agent","permissions":{"secrets":"r","namespaces":["mcp"]}}')

# 4. Accorder l'entrée à cette clé. Tant que ce n'est pas fait, rien ne lit
#    la section, y compris la clé elle-même.
curl -fsS -X POST "$BASE/groups/$GID/members" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"principal_type\":\"token\",\"principal_id\":\"$(echo "$MINT" | jq -r .id)\"}"

# 5. Ne donner à l'assistant que la valeur du token de $MINT, dans sa config.
unset RH_TOKEN
```

Retirer l'accès plus tard, c'est l'étape 4 à l'envers : retire le principal du
groupe et la requête suivante de l'assistant échoue. Rien à réémettre, et rien
à lui demander gentiment d'arrêter d'utiliser.

---

## 1. Ajouter un nouveau secret pour un client

À utiliser quand un client te donne un mot de passe / clé d'API /
URL de base de données et que tu veux le ranger dans le
coffre-fort pour que ton assistant IA puisse l'utiliser plus tard.

Écrire un secret demande plus d'autorité que n'en a la clé de ton assistant :
c'est donc une commande que tu lances. J'ai un token avec accès en écriture
exporté dans `RH_TOKEN` dans mon propre shell avant de commencer.

```
J'utilise rhorizon (un petit coffre-fort de secrets chiffré qui
tourne sur mon laptop). Je veux ranger un nouveau secret client. J'ai
déjà un token avec accès en écriture exporté dans RH_TOKEN dans mon
shell : ne le lis pas, ne l'affiche pas, ne me le demande pas, et ne
cherche aucun fichier de credentials.

Donne-moi les commandes terminal exactes pour :

  1. Stocker ce secret dans la SECTION que mon assistant peut
     atteindre, c'est-à-dire le namespace "mcp". Utilise un NOM
     structuré pour séparer les clients, pas un namespace imbriqué :
     nom "clients/<nom-court>" (sans espace) dans le namespace "mcp" :

       rhorizon set "clients/<nom-court>" --stdin --namespace mcp

     La valeur doit être demandée silencieusement dans mon terminal
     puis transmise en pipe. Ne me demande pas de la coller dans ce
     chat, de la mettre dans un argument ou de l'afficher.

  2. Vérifier que le secret a bien été enregistré en listant la
     section.

Après l'exécution, dis-moi le nom complet du nouveau secret
(format : "mcp/clients/<nom>"). J'en ai besoin pour l'étape
suivante (l'ajouter à la policy pour que ton assistant IA puisse le lire).

Montre les commandes avant de les exécuter. Je saisirai le secret
uniquement dans le prompt masqué du terminal.
```

**Ce que ça fait** : crée une entrée à l'intérieur de la seule section où la
clé de ton assistant peut entrer. La valeur est chiffrée au repos avec les clés
dérivées du mot de passe principal.

**Pourquoi le slash va dans le nom et pas dans le namespace.** Les namespaces
sont comparés exactement, jamais par préfixe : un secret rangé dans un namespace
nommé `mcp/clients` serait *hors* de l'autorisation sur `mcp`, et ton assistant
ne pourrait jamais le lire. Garder le namespace `mcp` et mettre la structure
dans le nom donne le même `mcp/clients/<nom>` lisible dans la policy, du bon
côté de la frontière.

---

## 2. Donner à ton assistant IA l'accès à un secret précis

À utiliser quand tu as un secret dans le coffre-fort et que tu
veux que ton assistant IA puisse le lire. **Sans
cette étape, le secret est invisible pour l'IA** - c'est le défaut
sécurisé.

```
J'utilise rhorizon. Je veux donner à mon assistant IA un accès en
lecture à ce secret :

  <colle-le-nom-complet-ici>
  (ex. "mcp/clients/dupont-mot-de-passe-bdd")

Le fichier de policy MCP est ~/.config/rhorizon-mcp/policy.toml.

Stp :

  1. Ouvre ce fichier.
  2. Ajoute le nom du secret ci-dessus au tableau
     [secrets].whitelist. Sans rien retirer de ce qui y est déjà.
  3. Montre-moi le nouveau contenu du fichier avant de sauver.
  4. Après confirmation de ma part, sauve.

Ensuite rappelle-moi de QUITTER COMPLÈTEMENT mon assistant IA
(Claude Desktop, Cursor, Cline...) et de le rouvrir, sinon la
nouvelle policy ne sera pas chargée.
```

**Ce que ça fait** : ajoute une ligne au fichier de policy. Ton
assistant IA peut maintenant appeler `vault_get_secret` pour ce nom de secret
précis, et seulement celui-là. Les autres secrets restent
invisibles.

---

## 3. Révoquer l'accès de ton assistant IA à un secret

À utiliser quand tu ne veux plus que ton assistant IA puisse lire un secret.
Ne supprime pas le secret - retire seulement la permission de
ton assistant IA. Le secret reste dans le coffre-fort.

```
J'utilise rhorizon. Je veux révoquer l'accès de mon assistant IA
à :

  <colle-le-nom-complet-ici>

Stp :

  1. Ouvre ~/.config/rhorizon-mcp/policy.toml.
  2. Retire ce secret de [secrets].whitelist (et si sa section
     est dans [namespaces].allow, demande-moi si je veux la
     retirer aussi - l'allow par section est plus large).
  3. Montre-moi le nouveau contenu.
  4. Après confirmation, sauve.

Ensuite dis-moi de quitter et rouvrir complètement mon
assistant IA pour que le changement prenne effet.
```

**Ce que ça fait** : retire le secret de la whitelist. Au prochain essai de
lecture par ton assistant IA, le serveur MCP renvoie `policy_denied`. Le secret
lui-même est intact.

**C'est la couche souple, pas la frontière.** Le fichier de policy vit sous ton
compte : un assistant capable de lancer des commandes peut remettre l'entrée. Il
arrête les erreurs, pas les intentions. Pour retirer l'accès d'une façon que
l'assistant ne peut pas défaire, sors le secret de sa section, ou retire sa clé
du groupe qui possède la section : le coffre-fort refuse alors dès la requête
suivante, quoi que dise le fichier de policy.

---

## 4. Voir ce que l'IA a lu récemment

À utiliser pour le reporting client, ou avant/après une session,
ou simplement pour voir ce que ton IA a fait.

Lire le journal d'audit demande `audit:r`, que la clé de ton assistant n'a pas.
Soit tu lances ça avec ton propre token exporté dans `RH_TOKEN`, soit tu lui
émets une clé d'audit dédiée en lecture seule, comme sa clé de secrets.

```
J'utilise rhorizon. Le coffre-fort est sur http://127.0.0.1:8200. Un
token avec accès en lecture à l'audit est exporté dans RH_TOKEN dans
mon shell : ne le lis pas, ne l'affiche pas, ne me le demande pas, et
ne cherche aucun fichier de credentials.

Donne-moi une seule commande curl qui liste les 50 dernières
entrées d'audit où l'acteur est "mcp-agent" (la clé d'accès
utilisée par mon assistant IA). Formate le résultat en tableau
lisible avec les colonnes : timestamp, action, target. Groupe par
jour s'il y a des entrées de plusieurs jours.

N'inclue pas la colonne signature de chaîne - je veux juste voir
ce qui a été lu et quand.
```

**Ce que ça fait** : récupère les 50 dernières entrées du journal
d'audit pour le token MCP et les affiche en tableau. Le journal
d'audit du coffre-fort est protégé par des checkpoints Merkle signés, donc
modifier ou supprimer une lecture déjà checkpointée casse la vérification
d'intégrité. La queue la plus récente reste en attente jusqu'à son prochain
checkpoint.

---

## 5. Mon IA ne voit pas rhorizon - debug

À utiliser quand tu as ouvert ton assistant IA et que les outils
`rhorizon` n'apparaissent pas, ou qu'ils apparaissent mais que
chaque appel échoue.

```
J'utilise rhorizon. Après avoir lancé tools/quickstart-laptop.sh
et redémarré mon assistant IA, [je ne vois pas rhorizon du tout /
je vois rhorizon mais chaque tool call échoue / l'assistant IA dit
que la policy refuse tout].

Stp guide-moi étape par étape dans cette séquence de debug, en
me demandant la sortie de chaque étape avant de passer à la
suivante :

  1. Le coffre-fort tourne-t-il ? (`docker ps | grep rhorizon_api`)
  2. L'API est-elle saine ? (`curl -s http://127.0.0.1:8200/health`)
  3. Le fichier token MCP est-il présent et lisible ?
     (`test -s ~/.config/rhorizon/mcp.token && echo present`).
     N'affiche pas le token et ne me demande pas de le coller.
  4. Le token authentifie-t-il toujours ?
     (`curl -s -H "Authorization: Bearer $(cat ~/.config/rhorizon/mcp.token)" \
        http://127.0.0.1:8200/api/v1/vault/tokens/whoami`)
  5. Le fichier de policy est-il présent et parsable ?
     (`cat ~/.config/rhorizon-mcp/policy.toml`)
  6. Le binaire MCP est-il toujours installé ?
     (`ls -la ~/.local/share/rhorizon-mcp/.venv/bin/rhorizon-mcp-server`)
  7. Le fichier de config de mon assistant IA pointe-t-il vers les
     bons chemins ? (ex. Claude Desktop : inspecte
     ~/Library/Application\ Support/Claude/claude_desktop_config.json
     sur macOS ; ou l'équivalent pour Cursor / Cline / Codex sur mon OS).
     Masque les tokens et valeurs d'environnement avant tout extrait.

Quand on a trouvé le problème, donne-moi la commande exacte
pour le réparer. Ne suggère rien de destructif (pas de docker
prune, pas de rm de ~/rhorizon/, pas de reset de policy) sans
me demander d'abord.
```

**Ce que ça fait** : vérifie le service, les credentials, la policy,
le binaire et la configuration client sans afficher le token.

---

## 6. Changer mon mot de passe principal

À utiliser si tu suspectes que ton mot de passe principal a été
vu par quelqu'un d'autre, ou comme hygiène de routine.

Celui-là, c'est entièrement à toi de le lancer. Rotater le mot de passe
principal demande à la fois le mot de passe actuel et un token admin, soit
exactement les deux choses que ton assistant ne doit jamais détenir. Il peut
expliquer l'opération et te donner les commandes ; tous les credentials restent
de ton côté de la conversation.

```
J'utilise rhorizon. Je veux changer mon mot de passe principal. Je
lancerai moi-même chaque commande.

Contexte :
  - le coffre-fort est sur http://127.0.0.1:8200 ;
  - je détiens le mot de passe principal actuel et un token admin. Ne
    me les demande pas, ne les lis dans aucun fichier, et ne prévois
    pas d'endroit où les coller dans les commandes que tu écris :
    suppose qu'ils sont déjà dans mon shell, dans
    RH_MASTER_PASSWORD et RH_TOKEN ;
  - je veux que les clés d'accès existantes (celle de mon
    assistant IA, etc.) continuent à marcher quelques jours pendant que je
    migre - PAS d'invalidation immédiate.

Stp donne-moi :

  1. Une explication courte (3-4 lignes) de ce qui va se passer.
  2. Une façon de choisir un nouveau mot de passe solide
     (suggère un outil, ne génère pas pour moi - ne mets jamais
     mon mot de passe principal dans ton contexte).
  3. La commande curl exacte pour rotater le mot de passe, en lisant
     les deux valeurs dans l'environnement, avec emergency=false vu
     le point 3 ci-dessus.
  4. Un rappel de mettre à jour l'endroit où je garde le mot de passe,
     et de ne rien relancer d'autre.
  5. Un rappel que si je perds ce mot de passe, le contenu du
     coffre-fort est irrécupérable - et que la seule protection
     est de sauvegarder le nouveau dans un gestionnaire de mot
     de passe que je contrôle.

Ne me demande pas de taper ou coller mon nouveau mot de passe
dans le chat. Je le garde de mon côté.
```

**Ce que ça fait** : exécute une rotation du mot de passe
principal contre le coffre-fort qui tourne. Les clés d'accès
existantes continuent à marcher pendant une fenêtre (~15 jours
par défaut), te donnant un tampon pour les mettre à jour sans
casser ton workflow. Après la fenêtre, il faudra les re-créer.

---

## 7. Sauvegarder le coffre-fort

À utiliser régulièrement et avant un changement majeur.

```
J'utilise rhorizon et je veux une sauvegarde hors hôte restaurable.

Ouvre docs/DISASTER-RECOVERY.md et suis la procédure documentée
de reprise PostgreSQL complète. Avant toute commande :

  1. Explique le chemin de restauration et comment je testerai le restore.
  2. Chiffre la sauvegarde DB avant qu'elle quitte cet hôte.
  3. Garde le mot de passe principal ou les shares de recovery
     séparés de la sauvegarde DB chiffrée. Ne mets jamais les deux
     dans la même archive tar.
  4. Traite les tokens MCP comme des credentials à recréer après
     restauration ; sauvegarde séparément la policy non secrète.
  5. N'invente pas une commande d'archive brute du volume Docker et
     ne lance aucune restauration destructive sans confirmation.

Montre chaque commande et attends mon accord.
```

**Ce que ça fait** : utilise le chemin de DR testé sans placer la base
chiffrée et son matériel de recovery dans la même archive.

---

## 8. Installation guidée

À utiliser si tu as sauté `QUICKSTART-AI.md` et que tu veux
que l'IA te guide intégralement.

```
Je veux configurer rhorizon (un petit coffre-fort de secrets
chiffré) sur mon laptop, pour que mon assistant IA (Claude
Desktop / Cursor / Cline) puisse lire des secrets sélectionnés
de façon contrôlée et auditée.

Je tourne sur [macOS / distro Linux / Windows avec WSL2].

Stp ouvre
https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/AI-INSTALL-GUIDE.md
et guide-moi dans l'installation, une étape à la fois. Après que
le coffre-fort est up, guide-moi aussi pour lancer
tools/quickstart-laptop.sh, qui configure la passerelle MCP vers
mon assistant IA.

Principes opératoires :
  - une étape à la fois, attends ma sortie avant de passer à la
    suivante ;
  - ne colle pas des murs de commandes ;
  - ne demande pas mon mot de passe principal - dirige-moi vers
    un gestionnaire de mots de passe ;
  - à chaque étape, dis-moi ce qui va se passer et pourquoi.
```

**Ce que ça fait** : demande à l'assistant de suivre le guide
d'installation contraint et de vérifier chaque étape.

---

## Version anglaise

English version : [`../AI-PROMPTS.md`](../AI-PROMPTS.md).
