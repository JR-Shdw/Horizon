# Vérifier les images rhorizon

Chaque push sur `main` construit, pousse, signe et atteste les images docker
de rhorizon. Quiconque dispose de `cosign.pub` (commité à la racine du dépôt et
servi sur https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub) peut
les vérifier de bout en bout avant de les tirer.

## Ce qui est signé

Pour chaque image (`rhorizon-api`, `rhorizon-frontend`, `rhorizon-agent`) :
- L'image elle-même - `cosign sign` produit un artefact OCI de signature
  (`sha256-XXXX.sig`) stocké à côté de l'image dans le registre Gitea.
- Une attestation de provenance SLSA v1.0 décrivant le build (commit, URL du
  builder, invocation, heure de démarrage).
- Une attestation SBOM CycloneDX (Software Bill of Materials).

Les trois sont liées au digest de contenu de l'image, pas à son tag.

## Prérequis

- `cosign` v2+ (nous utilisons actuellement v3.0.6 en CI)
- La clé publique :
  ```bash
  curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub > cosign.pub
  ```

## Vérifier la signature de l'image

```bash
IMAGE=ghcr.io/jr-shdw/rhorizon-api:latest

cosign verify --key cosign.pub "$IMAGE"
```

Sortie en cas de succès : un tableau JSON avec le payload de signature, les
annotations (`git-commit`, `build-time`, `builder`), et le digest qui a été
signé. Code de sortie non nul en cas d'échec.

## Vérifier la provenance SLSA

```bash
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$IMAGE" \
  | jq -r '.payload' | base64 -d | jq .predicate
```

Affiche les métadonnées de build : URL du dépôt source + commit, identité du
builder (`https://ci.example.com/woodpecker`), URL d'invocation du pipeline, et
heure de démarrage.

## Vérifier le SBOM

```bash
cosign verify-attestation --key cosign.pub --type cyclonedx "$IMAGE" \
  | jq -r '.payload' | base64 -d | jq -r '.predicate.components[].name' \
  | sort -u
```

Liste chaque composant (paquet Python, paquet système, crate Rust) embarqué
dans l'image.

## Tirer-puis-vérifier dans un script de déploiement

```bash
set -euo pipefail
IMAGE=ghcr.io/jr-shdw/rhorizon-api:latest
cosign verify --key /etc/rhorizon/cosign.pub "$IMAGE" >/dev/null
# Résoudre le digest que cosign vient de vérifier, puis tirer par digest pour
# que l'image qu'on exécute soit exactement les octets auxquels on a fait
# confiance.
DIGEST=$(docker image inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null \
        || docker pull "$IMAGE" >/dev/null && \
           docker image inspect --format='{{index .RepoDigests 0}}' "$IMAGE")
docker pull "${IMAGE%:*}@${DIGEST##*@}"
```

Refuser le pull quand la signature ne vérifie pas, c'est la barrière côté
consommateur. Le chemin de déploiement de cmdb (`scripts/deploy.sh` et
l'intégration pull de Portainer) implémente ce contrôle.

## Racines de confiance

| Artefact | Où | Ce que ça prouve |
|---|---|---|
| `cosign.pub` | racine du dépôt + URL raw Gitea | Ce qui est signé par nous ne peut l'être qu'avec la clé privée correspondante. |
| Clé privée + mot de passe | secrets Woodpecker `cosign_key`, `cosign_password` (node-2) | Indépendants du vault rhorizon - construire rhorizon n'exige **pas** que rhorizon soit descellé. |
| Digest d'image | registre OCI Gitea | Les tags mutables se résolvent en digests ; les signatures sont liées aux digests. |

La clé de signature vit délibérément en dehors de rhorizon, pour éviter le cas
de l'œuf et de la poule où un rhorizon scellé/cassé bloquerait la publication
de son propre correctif.
