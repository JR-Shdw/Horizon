# Prompts à donner à ton assistant IA

Chaque section ci-dessous est un prompt autonome. Remplace seulement
les placeholders `<...>` qui ne sont pas secrets. Relis les commandes
et changements de configuration avant de les approuver. Ne mets
jamais un secret, un token ou le mot de passe principal dans le prompt.

Ces prompts supposent que tu as déjà suivi
[`QUICKSTART-AI.md`](QUICKSTART-AI.md). Si ce n'est pas
fait, commence par là.

---

## 1. Ajouter un nouveau secret pour un client

À utiliser quand un client te donne un mot de passe / clé d'API /
URL de base de données et que tu veux le ranger dans le
coffre-fort pour que ton assistant IA puisse l'utiliser plus tard.

```
J'utilise rhorizon (un petit coffre-fort de secrets chiffré qui
tourne sur mon laptop). Mon coffre-fort est sur
http://127.0.0.1:8200 et mon token admin est dans le fichier
~/rhorizon/secrets/root-token.

Donne-moi les commandes terminal exactes pour :

  1. Stocker ce secret dans le coffre-fort, dans la section
     "mcp/clients". Le nom du secret doit être
     "<nom-court-explicite>" (sans espace). La valeur du secret
     doit être demandée silencieusement dans mon terminal puis
     transmise à `rhorizon set --stdin`. Ne me demande pas de la
     coller dans ce chat, de la mettre dans un argument ou de l'afficher.

  2. Vérifier que le secret a bien été enregistré en listant la
     section.

Après l'exécution, dis-moi le nom complet du nouveau secret
(format : "mcp/clients/<nom>"). J'en ai besoin pour l'étape
suivante (l'ajouter à la policy pour que ton assistant IA puisse le lire).

Montre les commandes avant de les exécuter. Je saisirai le secret
uniquement dans le prompt masqué du terminal.
```

**Ce que ça fait** : crée une nouvelle entrée dans la section
`mcp/clients`. La valeur est chiffrée au repos avec les clés
dérivées du mot de passe principal. L'hôte local et les processus
autorisés par le coffre-fort ou la policy MCP restent dans la
frontière de confiance.

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

**Ce que ça fait** : retire le secret de la whitelist. Au prochain
essai de lecture par ton assistant IA, le serveur MCP renvoie
`policy_denied`. Le secret lui-même est intact et toujours
lisible avec le token admin (root).

---

## 4. Voir ce que l'IA a lu récemment

À utiliser pour le reporting client, ou avant/après une session,
ou simplement pour voir ce que ton IA a fait.

```
J'utilise rhorizon. Le coffre-fort est sur http://127.0.0.1:8200,
mon token admin est dans ~/rhorizon/secrets/root-token.

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
d'audit du coffre-fort est **chaîné** - chaque entrée signe la
précédente - donc une modification devient détectable. Si quelqu'un (y
compris toi) modifiait la base pour cacher une lecture, la chaîne
casse.

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

```
J'utilise rhorizon. Je veux changer mon mot de passe principal.

Contexte :
  - le coffre-fort est sur http://127.0.0.1:8200 ;
  - mon mot de passe principal actuel est dans
    ~/rhorizon/secrets/master-password ;
  - mon token admin est dans ~/rhorizon/secrets/root-token ;
  - je veux que les clés d'accès existantes (celle de mon
    assistant IA, etc.) continuent à marcher quelques jours pendant que je
    migre - PAS d'invalidation immédiate.

Stp donne-moi :

  1. Une explication courte (3-4 lignes) de ce qui va se passer.
  2. Une façon de choisir un nouveau mot de passe solide
     (suggère un outil, ne génère pas pour moi - ne mets jamais
     mon mot de passe principal dans ton contexte).
  3. La commande curl exacte pour rotater le mot de passe (avec
     emergency=false vu le point 4 ci-dessus).
  4. La commande pour mettre à jour
     ~/rhorizon/secrets/master-password avec la nouvelle valeur,
     et re-`chmod 0400` dessus.
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
