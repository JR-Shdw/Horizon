# Vérifier les releases rhorizon

Chaque tag git correspondant à `v*` (par ex. `v1.0.0`) déclenche un pipeline de
release qui construit, hashe et signe avec cosign chaque artefact livrable,
puis les publie comme assets de release Gitea.

## Ce qui est publié par release

Pour le tag `vX.Y.Z` (https://github.com/JR-Shdw/Horizon/releases/tag/vX.Y.Z) :

| Asset | Description |
|---|---|
| `rhorizon_crypto-X.Y.Z-cp312-abi3-manylinux_*.whl` | Wheel de l'extension Rust (la seule chose non installable par pip depuis PyPI) |
| `rh-inject` / `rh-fetch` / `rh-watch` | Binaires d'agent musl statiques (payload d'init container) |
| `terraform-provider-rhorizon_X.Y.Z_linux_amd64` | Provider Terraform en Go (statique, reproductible via `-trimpath`/`-buildid=`) |
| `rhorizon-client-X.Y.Z.tgz` | Pack SDK npm (`@rhorizon/client`, version issue de package.json) |
| `rhorizon-X.Y.Z-source.tar.gz` | Archive git déterministe du commit taggé (inclut les sources vendorées d'`eso-provider`) |
| `<module>.sbom.cdx.json` | SBOM CycloneDX par module (`rhorizon_crypto`, `rhorizon-agent`, `terraform-provider-rhorizon`, `rhorizon-client`) - signé comme tout autre asset et hashé dans les sujets de provenance |
| `*.sig` | Signature cosign détachée (flux historique / clé explicite) |
| `*.bundle` | Bundle cosign autonome (signature + cert + payload) |
| `*.sha256` | Hash SHA-256 pour un recoupement supplémentaire |

Tous les assets sont signés avec la même clé que celle qui signe les images
Docker (`cosign.pub` à la racine du dépôt).

## Vérification

```bash
TAG=v1.0.0
BASE=https://github.com/JR-Shdw/Horizon/releases/download/$TAG

# Clé publique (commitée à la racine du dépôt, servie via le raw Gitea)
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub > cosign.pub

# Choisissez l'artefact à vérifier
ASSET=rhorizon_crypto-1.0.0-cp312-abi3-manylinux_2_34_x86_64.whl

curl -fsSL "$BASE/$ASSET"          -O
curl -fsSL "$BASE/$ASSET.bundle"   -O
curl -fsSL "$BASE/$ASSET.sha256"   -O

# 1. Contrôle du hash (étape de bon sens, peu coûteuse)
sha256sum -c "$ASSET.sha256"

# 2. Signature cosign (préférée - le bundle contient le payload de signature)
cosign verify-blob --key cosign.pub --bundle "$ASSET.bundle" "$ASSET"
```

`cosign verify-blob` sort avec un code non nul en cas de signature discordante,
de fichier manquant, de mauvaise clé, ou de toute altération. Le chemin du
bundle et celui du binaire sont tous deux requis.

## Flux `.sig` détaché (fichier de signature explicite)

Si vous préférez le `.sig` brut au bundle :

```bash
curl -fsSL "$BASE/$ASSET.sig" -O
cosign verify-blob --key cosign.pub --signature "$ASSET.sig" "$ASSET"
```

Même résultat ; le bundle n'est qu'une enveloppe autonome.

## Racines de confiance

La même chaîne que celle documentée dans
[`verifying-images.md`](verifying-images.md) :

| Artefact | Où | Ce que ça prouve |
|---|---|---|
| `cosign.pub` | racine du dépôt + URL raw Gitea | Ce qui est signé par nous ne peut l'être qu'avec la clé privée correspondante. |
| Clé privée + mot de passe | secrets Woodpecker `cosign_key`, `cosign_password` (node-2) | Indépendants du vault rhorizon - publier rhorizon n'exige **pas** que rhorizon soit descellé. |
| Liaison tag -> commit | dépôt Gitea (tags immuables) | Le tag `vX.Y.Z` se résout en un SHA de commit précis ; le corps de la release affiche le SHA + le pipeline Woodpecker qui l'a construit. |

## Reproduire une release en local

Le pipeline de release utilise `SOURCE_DATE_EPOCH = timestamp du commit git` et
`RUSTFLAGS=--remap-path-prefix=...=.` pour que les artefacts soient stables
octet à octet.

```bash
git checkout vX.Y.Z
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)

# wheel rhorizon_crypto
docker run --rm -v "$PWD/api/rust:/build" -w /build \
  -e SOURCE_DATE_EPOCH \
  -e RUSTFLAGS="--remap-path-prefix=/build=." \
  python:3.12-slim@sha256:46cb7c... \
  bash -c "apt-get update && apt-get install -y curl gcc libc6-dev && \
           curl https://sh.rustup.rs | sh -s -- -y && \
           PATH=/root/.cargo/bin:\$PATH pip install maturin && \
           PATH=/root/.cargo/bin:\$PATH maturin build --release --locked --strip"

sha256sum api/rust/target/wheels/*.whl
# Doit correspondre au .sha256 de la release.
```

Le gate CI `.woodpecker/reproducibility.yml` impose cette même propriété à
chaque push, donc un build de release n'est qu'un build reproductible avec de
la signature et de la publication en plus.

## Inspecter le SBOM d'un module

Chaque module client livre un SBOM CycloneDX signé. Vérifiez-le comme n'importe
quel autre asset, puis lisez sa liste de composants :

```bash
ASSET=rhorizon-client.sbom.cdx.json
cosign verify-blob --key cosign.pub --bundle "$ASSET.bundle" "$ASSET"

# Ce qu'il contient (nom@version par composant) :
jq -r '.components[] | "\(.name)@\(.version)"' "$ASSET"
```

Les SBOM sont générés par `trivy fs --include-dev-deps --format cyclonedx` sur
le lockfile commité de chaque module (`Cargo.lock`, `go.sum`,
`package-lock.json`), donc ils énumèrent la chaîne d'approvisionnement au
moment du build, pas seulement les dépendances d'exécution. Le cron quotidien
`scan.yml` fait tourner `trivy fs` sur les mêmes lockfiles pour les CVE
fraîches (les rapports s'agrègent dans le résumé de scan).
