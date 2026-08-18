# Sécuriser tes workflows n8n avec rhorizon

n8n chiffre les credentials de workflow dans sa base avec une seule
`N8N_ENCRYPTION_KEY`, souvent fournie par `.env`. La divulgation de
cette clé et du store de credentials expose le catalogue.

Ce guide stocke `N8N_ENCRYPTION_KEY` et certains credentials de nœuds
dans rhorizon, les injecte dans n8n au boot et journalise chaque
lecture dans l'audit.

> Si tu n'as pas encore lancé rhorizon, commence par
> [`QUICKSTART-AI.md`](QUICKSTART-AI.md). C'est le même
> coffre-fort - le quickstart laptop suffit.

---

## Ce que ça protège

| Risque | Baseline `.env` | Avec rhorizon |
|---|---|---|
| Quelqu'un lit le volume / l'image / un dump de config n8n | Voit `N8N_ENCRYPTION_KEY` et le store de credentials décryptable en entier | Voit un store chiffré sans la clé. Inutile sans le coffre-fort qui tourne. |
| Un workflow fuite une clé Slack / OpenAI / Stripe (logs, message d'erreur, ...) | Cette même clé continue à marcher tant que tu ne te souviens pas de quel `.env` rotater | Une révocation dans le coffre-fort ; le workflow concerné s'arrête au prochain run |
| Tu as confié n8n à un prestataire / VA | Il voit tous les credentials parce que n8n les affiche dans l'UI | Tu ne whitelistes que ce dont il a besoin ; l'audit rhorizon montre ce qui a été tiré, quand, par qui |
| Tu veux un trail conformité "qui/quoi a touché la clé API Acme en mars" | Aucun | `rhorizon audit tail --target acme/api-key` |
| Rotation de la clé maître | Édit `.env` partout, restart n8n, espère que rien ne casse | Une rotation dans le coffre-fort ; fenêtre de migration douce de ~15 jours pour les tokens existants |

Le modèle se mappe proprement sur la checklist d'un auditeur
externe : chiffrement au repos, séparation des clés, latence de
révocation, attribution audit par secret.

---

## Deux patterns

| Pattern | Ce qu'il protège | Quand l'utiliser |
|---|---|---|
| **A - protéger `N8N_ENCRYPTION_KEY`** | Le store de credentials propre à n8n (celui que l'UI gère) | Toujours. Upgrade le moins coûteux. |
| **B - injection par-secret via `rh-inject`** | Secrets de workflow individuels exposés en `={{$env.MY_KEY}}` dans les nœuds n8n | Workflows qui demandent une rotation, un audit par-secret, ou une révocation indépendante de l'UI n8n |

Les patterns se composent : A est la fondation, B est opt-in
par secret. Tu peux ne lancer que A et garder B pour les secrets
qui ont besoin d'un audit serré.

---

## Pattern A - protéger N8N_ENCRYPTION_KEY

### Ce qui change

`N8N_ENCRYPTION_KEY` ne traîne plus dans `.env` à côté du
conteneur. Il vit dans rhorizon et est lu depuis un fichier tmpfs
monté dans le conteneur n8n au boot. n8n le lit comme avant - seul
le chemin a changé.

### Setup

**1. Génère la clé une fois et stocke-la dans rhorizon**

Si tu as déjà une `N8N_ENCRYPTION_KEY`, garde cette valeur exacte
(la rotater re-chiffrerait chaque credential existant). Utilise le
prompt de [`AI-PROMPTS.md`](AI-PROMPTS.md) section 1 ("Ajouter un nouveau
secret") avec :

- Section : `n8n`
- Nom du secret : `encryption-key`
- Valeur : ta `N8N_ENCRYPTION_KEY` existante

Si tu n'en as pas encore, génère-en une avant de stocker :

```bash
openssl rand -hex 32
```

**2. Mint un token pour l'hôte n8n**

```bash
# depuis le poste opérateur, avec le token admin chargé
rhorizon token create n8n-host \
  --scope secrets:r \
  --namespace n8n \
  --allowed-ips 10.89.0.0/16    # le subnet de ton bridge podman / docker
```

`allowed-ips` correspond au subnet du conteneur où n8n tourne.
Même si le token leak, il ne peut pas être utilisé d'ailleurs sur
le LAN.

**3. Tirer la clé dans le conteneur n8n au boot**

Utilise `rh-fetch` (un init container qui sort quand le fichier
est écrit ; n8n attend qu'il termine) :

```yaml
# docker-compose.yml - service n8n
services:

  rh-fetch-n8n:
    image: localhost/rhorizon-agent:latest
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      RH_SECRETS: encryption-key:/run/n8n-secrets/encryption-key
      RH_NAMESPACE: n8n
    secrets:
      - rh-bootstrap
    volumes:
      - n8n_secrets:/run/n8n-secrets
    restart: "no"

  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    depends_on:
      rh-fetch-n8n:
        condition: service_completed_successfully
    environment:
      N8N_ENCRYPTION_KEY_FILE: /run/n8n-secrets/encryption-key
    volumes:
      - n8n_secrets:/run/n8n-secrets:ro
      - n8n_data:/home/node/.n8n
    ports:
      - "127.0.0.1:5678:5678"

volumes:
  n8n_secrets:
    driver_opts:
      type: tmpfs
      device: tmpfs    # jamais écrit sur disque
  n8n_data:

secrets:
  rh-bootstrap:
    file: ./rh-bootstrap-token   # le token n8n-host, mode 0400
```

**4. Vérifier**

```bash
docker compose up -d
docker compose logs -f n8n
```

Le log doit mentionner "Encryption key loaded" sans warning sur
une clé par défaut. Le store de credentials dans l'UI n8n repose
maintenant sur une clé qui vit dans rhorizon - relance le
coffre-fort scellé et n8n refusera de décrypter le store à son
prochain restart.

---

## Pattern B - injection par-secret avec rh-inject

### Quand ça vaut le coup

Le pattern A protège la clé maître mais l'UI n8n affiche encore
les valeurs en clair une fois déverrouillé. Le pattern B garde les
secrets individuels à forte valeur **hors** du store de
credentials n8n entièrement - ils n'existent que comme variables
d'environnement dans le conteneur n8n, référencées depuis les
nœuds en `={{$env.STRIPE_KEY}}`.

À utiliser pour :

- Secrets qui rotent souvent (Stripe, OpenAI billing, Twilio).
- Secrets partagés avec un prestataire pour une mission donnée.
- Secrets que tu veux révoquer sans toucher à l'UI n8n.

### Setup

**1. Stocke le secret dans rhorizon**

Même prompt que tout à l'heure, section `n8n`. Par exemple,
`n8n/stripe-key`.

**2. Mint un token (ou réutilise `n8n-host`)**

Si tu as déjà le token `n8n-host` du Pattern A, tu peux le
réutiliser - la section et le scope correspondent.

**3. Build une petite image n8n custom**

```dockerfile
# n8n.Dockerfile
FROM localhost/rhorizon-agent:latest AS agent
FROM docker.n8n.io/n8nio/n8n:latest
USER root
COPY --from=agent /usr/local/bin/rh-inject /usr/local/bin/rh-inject
USER node
ENTRYPOINT ["/usr/local/bin/rh-inject", "--", "tini", "--"]
CMD ["n8n", "start"]
```

**4. Référence des URLs rhorizon dans l'env**

```yaml
# docker-compose.yml - service n8n (remplace le précédent)
services:
  n8n:
    image: localhost/n8n-rh:custom        # ton image construite ci-dessus
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      N8N_ENCRYPTION_KEY_FILE: /run/n8n-secrets/encryption-key
      STRIPE_KEY: rh://n8n/stripe-key
      OPENAI_API_KEY: rh://n8n/openai-key
      TWILIO_AUTH_TOKEN: rh://n8n/twilio-token
    volumes:
      - n8n_secrets:/run/n8n-secrets:ro
      - n8n_data:/home/node/.n8n
    secrets:
      - rh-bootstrap
```

`rh-inject` scanne l'env au démarrage en PID 1, trouve chaque
valeur qui commence par `rh://`, tire chacune depuis rhorizon,
remplace la valeur en mémoire, puis `execve()` n8n. Les
credentials du coffre-fort (`RH_TOKEN_FILE`,
`RH_ADDR`) sont retirés de l'env enfant avant exec - n8n
lui-même ne les voit jamais.

**5. Référence dans tes workflows**

Dans n'importe quel paramètre de nœud n8n qui supporte les
expressions :

```
={{ $env.STRIPE_KEY }}
```

Identique à ce que tu ferais avec une env var classique. n8n n'a
aucune idée que ça vient d'un coffre-fort.

### Compromis à connaître

- Les valeurs résolues vivent dans `/proc/<n8n-pid>/environ` après
  exec. N'importe qui qui tourne avec le même uid + `SYS_PTRACE`
  peut les lire. C'est inchangé par rapport à n'importe quel setup
  "secret en env var" ; rhorizon n'efface pas ça par magie. Pour
  les secrets à forte assurance préférer le Pattern A seul + les
  garder dans le store n8n, ou Pattern A + `rh-fetch` + `_FILE`
  pour les nœuds qui le supportent.

- `rh-inject` résout au boot. Rotater un secret demande un restart
  du conteneur n8n. Pour la rotation runtime, utiliser `rh-watch`
  (pattern sidecar polling) à la place - voir
  [`docs/docs/howto/agents.md`](../docs/howto/agents.md#rh-watch---sidecar-with-rotation)
  pour la config.

---

## Audit - ce que ton client / ton auditeur voit

Une fois n8n en route et un workflow exécuté au moins une fois,
chaque tirage est dans la chaîne :

```bash
# chaque fois que l'hôte n8n a tiré un secret
rhorizon audit tail --actor n8n-host

# ce que la clé OpenAI a touché, par qui, quand
rhorizon audit tail --target n8n/openai-key

# export fin de mois pour un client
rhorizon audit tail --since 2026-04-01 --until 2026-04-30 \
  --format json > avril-audit.json
```

La chaîne est signée HMAC - chaque ligne signe la précédente. Si
quelqu'un (y compris toi) modifie la base pour cacher un tirage,
la chaîne casse et `rhorizon audit verify` le signale. C'est la
propriété que les auditeurs cherchent.

---

## Checklist de durcissement pour un déploiement n8n + rhorizon

- [ ] `rhorizon` et `n8n` sont sur le même réseau privé. Le
      coffre-fort n'est **jamais** exposé publiquement. L'UI n8n
      est derrière un reverse proxy avec TLS + auth (Authelia /
      Authentik / Keycloak / nginx basic-auth au minimum).
- [ ] Token `n8n-host` avec `allowed-ips` qui matche le subnet
      bridge du conteneur uniquement.
- [ ] Scope `n8n-host` = `secrets:r` seulement - pas d'écriture,
      pas d'admin.
- [ ] Token `n8n-host` restreint à la section `n8n`. Mettre les
      creds d'autres clients dans `n8n/` est un footgun ; utiliser
      `clients/<nom>/` ou splitter les tokens.
- [ ] Fichier token de bootstrap (`rh-bootstrap`) sur l'hôte n8n
      en mode 0400 owned par root.
- [ ] Volume tmpfs pour `/run/n8n-secrets` - jamais sur disque.
- [ ] Rotation `N8N_ENCRYPTION_KEY` : éviter de la rotater après
      que le store de credentials est rempli (n8n ne peut pas
      re-chiffrer les entrées existantes automatiquement). Si tu
      dois, suis la procédure upstream n8n d'abord, puis mets à
      jour la valeur dans rhorizon.
- [ ] Rétention audit assez longue pour satisfaire ton client /
      ton régulateur. Défaut 365 jours.

---

## Quand ça n'est *pas* un fit

- **Déploiements n8n cloud / SaaS.** L'idée même du guide est le
  contrôle local de la clé de chiffrement. Si n8n l'entreprise
  tient la clé, ce guide ne s'applique pas.
- **Rotation de credentials à haute fréquence (toutes les
  quelques minutes).** Le pattern B demande un restart de
  conteneur pour rafraîchir. Utiliser les engines de secrets
  dynamiques du coffre-fort (PostgreSQL / MySQL / LDAP / Redis /
  Cassandra) pour les credentials qui ont vraiment besoin d'une rotation
  courte.
- **Webhook signing où n8n lui-même signe le trafic.** Cette clé
  est utilisée par requête, pas par boot ; le cycle restart du
  pattern B est trop grossier. Tirer cette clé via le nœud HTTP
  n8n directement depuis le coffre-fort à la demande.

---

## Version anglaise

English version : [`../N8N.md`](../N8N.md).
