TP12 : Software Supply Chain (Harbor, SBOM, Cosign, provenance, SLSA)

Ce dépôt contient l'API contact-api et le travail du TP12 : un registre privé Harbor, des SBOM (Syft, Grype), la signature d'images avec Cosign (clés puis keyless), une provenance générée par GitHub Actions, et une lecture du pipeline selon SLSA.

build -> SBOM -> scan -> push -> signature -> attestation -> vérification
1. Environnement
Élément	Valeur
VM Harbor / client Docker	Ubuntu Server (VirtualBox), IP privée 192.168.56.10
Harbor	v2.15.5, HTTP, avec Trivy (harbor.lab.local)
Image	contact-api (Node 24 Alpine, express)
Cosign	v3.1.4
Grype	0.122.1
Dépôt GitHub / registre public	Narjess805/contact-api / ghcr.io/narjess805/contact-api

Prérequis : entrée 192.168.56.10 harbor.lab.local dans /etc/hosts, et {"insecure-registries": ["harbor.lab.local"]} dans /etc/docker/daemon.json (lab isolé uniquement, un registre de production est servi en HTTPS).

2. Partie 1 et 2 : Harbor, RBAC, scan, rétention
Installation : sudo ./install.sh --with-trivy, 10 conteneurs healthy.
Projet privé devsecops, utilisateurs dev1 (Développeur) et audit1 (Invité), robot account limité à Pull et Push sur le projet.

Projet, membres et robot

RBAC : audit1 peut tirer l'image mais pas la pousser (unauthorized to access repository ... action: push, libellé de Harbor 2.15 pour le denied du sujet).

Push refusé pour audit1

Scan automatique et blocage : le scan au push et l'option « Empêcher les images vulnérables de s'exécuter » (gravité Critical) sont activés. L'image vuln-app est scannée par Trivy et son pull est refusé. Remarque : avec cette option active, les push d'une image elle-même vulnérable ont renvoyé 412 Precondition Failed ; l'option a été désactivée le temps de la démonstration de rétention.

Rapport Trivy et pull bloqué

Rétention et immutabilité : règle « conserver les 5 derniers artefacts poussés » (dry run uniquement) et immutabilité des tags v*. Les tags t1 à t7 pointaient vers un seul digest, donc 7 artefacts distincts (r1 à r7) ont été construits avec --label pour que la rétention ait un effet visible.

Dry run de la rétention

3. Partie 3 : SBOM avec Syft, scan avec Grype
bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/out" anchore/syft:latest \
  contact-api:latest -o spdx-json=/out/contact-api.spdx.json -o cyclonedx-json=/out/contact-api.cdx.json
docker run --rm -v "$PWD:/in" -v grype-cache:/.cache/grype anchore/grype:latest sbom:/in/contact-api.spdx.json
Question	Réponse
Nombre de paquets	259
Version d'express	4.22.3
Version d'OpenSSL	libssl3 / libcrypto3 3.5.9-r0 (OpenSSL s'appelle ainsi sur Alpine)
Vulnérabilités Grype	47 lignes, dont une Critical (zlib CVE-2026-4738) et plusieurs High sur OpenSSL, undici, brace-expansion

SBOM et Grype

Intérêt : avec le SBOM de chaque release, on répond à « suis-je concerné par la CVE X ? » sans reconstruire ni retélécharger les images.

4. Partie 4 : Cosign avec paire de clés
bash
cosign generate-key-pair                       # cosign.key (jamais commitée) + cosign.pub
DIGEST=sha256:01da43c9e8fd07360900759ca23702bba1b19877324ae690a87de48269bf7a97
cosign sign --key cosign.key --allow-http-registry --allow-insecure-registry \
  harbor.lab.local/devsecops/contact-api@$DIGEST
cosign attest --key cosign.key --type spdxjson --predicate contact-api.spdx.json \
  --allow-http-registry --allow-insecure-registry harbor.lab.local/devsecops/contact-api@$DIGEST
1.0.0 (signée) : cosign verify réussit.
1.0.1 (poussée sans signature, digest sha256:48d35c3d...) : no signatures found.
L'attestation SPDX est vérifiée par cosign verify-attestation ; c'est un statement in-toto.

Note : docker buildx imagetools essaie HTTPS, donc le digest a été obtenu via docker pull / docker inspect.

Vérifications Cosign

5. Partie 5 : keyless et provenance (GitHub Actions)

Le workflow release.yml se déclenche sur un tag v* et enchaîne : build et push vers GHCR, SBOM (anchore/sbom-action), signature cosign sign --yes en keyless (jeton OIDC, certificat éphémère Fulcio, journal Rekor), attestation actions/attest-build-provenance et SBOM joint à la release.

bash
cosign verify ghcr.io/narjess805/contact-api:v1.0.0 \
  --certificate-identity-regexp 'https://github.com/Narjess805/contact-api/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/narjess805/contact-api:v1.0.0 --owner Narjess805

Les deux vérifications réussissent (workflow .github/workflows/release.yml@refs/tags/v1.0.0).

Keyless et provenance

Que se passe-t-il si --certificate-identity-regexp désigne un autre dépôt ? La vérification échoue (expected SAN value to match regex ... got https://github.com/Narjess805/contact-api/.github/workflows/release.yml@refs/tags/v1.0.0). Le certificat Fulcio contient l'identité du workflow signataire. Sans ce contrôle, la signature de n'importe quel autre workflow GitHub serait acceptée : c'est l'identité attendue qui prouve l'origine, pas la seule présence d'une signature.

6. Partie 6 : SLSA, in-toto, attaque simulée
Tableau SLSA (Build track)
Niveau	Exigence principale	Atteint par
Build L1	Provenance existante	Pipeline Jenkins (build scripté, provenance documentée)
Build L2	Provenance signée, générée par une plateforme hébergée	Workflow GitHub Actions avec attest-build-provenance
Build L3	Plateforme durcie, provenance infalsifiable par le projet	Non atteint tel quel ; possible avec un workflow réutilisable (slsa-github-generator)

Situation : (a) build sur le poste du développeur : aucun niveau ; (b) Jenkins : L1 ; (c) GitHub Actions avec attestation : L2.

Rôle d'in-toto

in-toto sécurise toute la chaîne de fabrication. Le layout définit qui peut réaliser quelles étapes (checkout, build, scan, signature). Chaque étape produit un link, une preuve signée listant ses entrées et ses sorties. La vérification compare les links au layout : étape manquante, mauvaise identité ou artefact modifié entre deux étapes font échouer le contrôle. Les attestations Cosign et GitHub reprennent ce format : le payload décodé est un statement https://in-toto.io/Statement/v0.1 avec un subject (le digest) et un predicateType (SPDX ou provenance SLSA).

Attaque simulée

Une image modifiée est poussée sous le même tag contact-api:1.0.0 (l'immutabilité ne couvre que v*). Le tag pointe alors vers un nouveau digest (sha256:8c84fc8b...). docker pull réussit sans aucune alerte, mais cosign verify sur ce digest échoue (no signatures found). Le tag a ensuite été restauré vers le digest signé sha256:01da43c9....

Image remplacée détectée

verify-before-run.sh

verify-before-run.sh résout le digest, vérifie la signature et ne lance docker run que si elle est valide.

bash
./verify-before-run.sh harbor.lab.local/devsecops/contact-api:1.0.0
# REFUS : signature invalide ...   (code retour 1, image altérée)
./verify-before-run.sh harbor.lab.local/devsecops/contact-api@sha256:01da43c9e8fd07360900759ca23702bba1b19877324ae690a87de48269bf7a97
# Signature valide, lancement.   (API sur :4000)
7. Comparaison GHCR / Harbor
Critère	GHCR	Harbor
Hébergement	Cloud GitHub, rien à gérer	Auto-hébergé, à installer et maintenir
RBAC	Lié aux permissions GitHub (dépôt, organisation)	Projets, rôles fins, robot accounts
Scan	Via GitHub (Dependabot, actions externes)	Trivy intégré, scan au push, blocage au pull
Réplication	Non native	Réplication entre registres (pull/push)
Coût	Gratuit pour les paquets publics, quotas sinon	Gratuit, coût d'infrastructure et d'administration
Usage hors ligne	Impossible	Possible en réseau isolé
8. Sécurité
cosign.key n'est jamais commitée (.gitignore) ni rendue.
Les secrets de robot et jetons ne figurent dans aucune capture ni aucun fichier du dépôt ; le secret du robot Harbor et le token GitHub du lab doivent être régénérés ou révoqués après le TP.
Un registre HTTP et un stockage d'identifiants en clair ne sont acceptables que dans ce lab isolé.
9. Livrables
Fichier	Contenu
captures/tp12/harbor-project.png	Projet devsecops, membres, robot
captures/tp12/harbor-rbac-denied.png	Push refusé pour audit1
captures/tp12/harbor-scan.png	Rapport Trivy et pull bloqué
captures/tp12/harbor-retention.png	Dry run de la rétention
captures/tp12/sbom-grype.png	Extrait SBOM et Grype
captures/tp12/cosign-verify.png	Vérification réussie, puis échec sur image non signée
captures/tp12/keyless-provenance.png	cosign verify keyless et gh attestation verify
captures/tp12/attack-detected.png	Image remplacée détectée
.github/workflows/release.yml, verify-before-run.sh	Workflow et script
