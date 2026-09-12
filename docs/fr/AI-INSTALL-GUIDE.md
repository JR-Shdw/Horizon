# Installer Horizon avec un assistant IA

S'applique à Horizon 0.9.4-beta.

Cette page est la fiche d'instructions à fournir à un assistant IA. Elle couvre
une installation locale, pas un déploiement exposé sur Internet ou en HA.
Relisez chaque commande avant de l'autoriser. Un assistant peut mal comprendre
la machine ou proposer une commande hors de ce guide.

Ne collez jamais dans la conversation un mot de passe maître, un token root, un
token MCP, une clé privée, un fichier `.env`, un nom d'hôte ou une adresse
privée. Masquez ces valeurs avant de transmettre une erreur.

## Instructions pour l'assistant

Demandez quel système est utilisé et si la personne privilégie la simplicité
ou une séparation système entre le coffre et le processus IA. Expliquez la
différence avant de proposer une commande.

### Installation locale personnelle

Utilisez [`QUICKSTART-AI.md`](QUICKSTART-AI.md). C'est le parcours simple pour
macOS, Windows/WSL et Linux. Horizon reste sur localhost et le client MCP reçoit
un token limité par le coffre, mais les fichiers de récupération et l'assistant
partagent généralement le même compte utilisateur. Un logiciel exécuté sous ce
compte peut lire ces fichiers. Sous Linux, appartenir au groupe Docker équivaut
généralement à disposer des droits root.

Ne présentez pas ce parcours comme une protection contre un agent local compromis
ou hostile. Sa frontière de sécurité est l'autorisation du coffre, pas l'identité
du système d'exploitation.

### Installation avec identité séparée pour l'outil IA

Ce parcours est actuellement validé sous Linux. Horizon s'exécute avec le compte
de service non interactif `rhorizon`. Le mot de passe maître et le token
administrateur restent dans `/etc/rhorizon/secrets`, lisibles uniquement par
root. Le processus IA de l'utilisateur ne reçoit qu'un token limité au namespace
gouverné `mcp`.

Cette séparation protège l'autorité de récupération après l'installation. Elle
ne rend pas sûre l'approbation aveugle de commandes root : `sudo` autorise le
code exécuté. Utilisez une release relue dans un répertoire source appartenant
à root.

Exécutez une seule commande à la fois et attendez son résultat.

1. Choisissez la release publiée et clonez-la directement dans un chemin
   appartenant à root :

   ```bash
   sudo git clone --branch v0.9.4-beta --depth 1 https://github.com/JR-Shdw/Horizon.git /usr/local/src/rhorizon
   ```

   Si le répertoire existe déjà, arrêtez-vous. Ne le supprimez, ne l'écrasez et
   ne le mettez pas à jour sans accord explicite. Le contenu de la release et
   les moyens de vérification sont décrits dans
   [`verifying-releases.md`](../verifying-releases.md).

2. Vérifiez que le compte de connexion ne peut pas modifier le checkout :

   ```bash
   test ! -w /usr/local/src/rhorizon && echo "les sources ne sont pas modifiables par ce compte"
   ```

3. Lancez le script dédié. Remplacez `VOTRE_COMPTE` par le compte non-root qui
   exécute le client IA ; obtenez-le avec `id -un` au lieu de le deviner :

   ```bash
   sudo /usr/local/src/rhorizon/tools/quickstart-ai-system.sh --user VOTRE_COMPTE
   ```

   Le script doit s'arrêter si ce compte est root, peut modifier les sources,
   appartient au groupe `docker`, peut écrire dans la socket Docker ou dispose
   de sudo/doas sans mot de passe. Ne contournez pas ces contrôles.

4. La personne saisit deux fois le mot de passe maître dans le terminal. Ne le
   demandez jamais dans la conversation et ne proposez ni variable
   d'environnement ni argument de ligne de commande.

5. À la fin, donnez à la personne le bloc de configuration MCP affiché. Ne
   demandez pas à lire les fichiers de récupération. La séparation attendue est :

   | Élément | Propriétaire et emplacement |
   |---|---|
   | Mot de passe maître | root uniquement, `/etc/rhorizon/secrets/master-password` |
   | Token administrateur | root uniquement, `/etc/rhorizon/secrets/root-token` |
   | Token MCP | compte cible, `~/.config/rhorizon/mcp.token` |
   | Politique MCP locale | compte cible, `~/.config/rhorizon-mcp/policy.toml` |

La politique commence avec une liste de secrets vide. Le compte cible peut
modifier ce fichier local, mais cela ne peut pas étendre l'appartenance au
namespace contrôlée par le coffre.

## Vérification

Ne concluez pas à partir du seul état du service. Demandez à la personne
d'exécuter :

```bash
sudo systemctl status rhorizon.service --no-pager
sudo test -r /etc/rhorizon/secrets/root-token && echo "token de récupération root présent"
test ! -r /etc/rhorizon/secrets/root-token && echo "token de récupération masqué au compte de connexion"
test -r "$HOME/.config/rhorizon/mcp.token" && echo "token MCP limité présent"
```

Le service doit fonctionner sous `rhorizon`; la lecture sans privilège doit
échouer ; le contrôle du token MCP doit réussir. Le certificat TLS auto-signé
est copié pour le compte cible et le client MCP : aucune désactivation de la
vérification TLS n'est nécessaire.

## Cas d'arrêt

Arrêtez ce parcours et indiquez le document correspondant si le besoin change :

- exposition publique ou production : [`DEPLOYMENT.md`](../DEPLOYMENT.md) ;
- haute disponibilité : [`HA-CLUSTER.md`](../HA-CLUSTER.md) ;
- Kubernetes : [`K8S.md`](../K8S.md) ;
- signalement de sécurité : [`SECURITY.md`](SECURITY.md).

N'ajoutez jamais le compte au groupe Docker, ne désactivez pas la vérification
TLS, n'exposez pas une installation localhost sur toutes les interfaces, ne
réduisez pas les permissions des fichiers, ne placez pas un secret dans les
arguments, l'environnement ou la conversation, et ne continuez pas après
l'échec d'un contrôle de sécurité.

Version anglaise : [`../AI-INSTALL-GUIDE.md`](../AI-INSTALL-GUIDE.md).
