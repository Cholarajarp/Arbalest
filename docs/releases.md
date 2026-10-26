# Container releases and verification

This repository defines a release pipeline; adding these files does **not** publish
an image or sign an existing image. Only a successful run of
[`.github/workflows/release.yml`](../.github/workflows/release.yml) performs the
publication, signing and verification described below. A locally built image is
not release-signed. No historical image is implicitly trusted.

## Maintainer release procedure

1. Review the source, `pyproject.toml` and `uv.lock`. Releases accept stable
   `MAJOR.MINOR.PATCH` versions only. Update the lock with the project's pinned
   uv version (`0.11.21`) when changing metadata or dependencies.
2. Run the local checks below and the normal CI suite. Commit the reviewed
   release source and create a tag matching the project version, for example
   `v1.0.0` for project version `1.0.0`.
3. Push that tag, or manually dispatch `release` **on that same tag** with its
   `tag` input set to `v1.0.0`. Using `gh`, the equivalent is
   `gh workflow run release.yml --ref v1.0.0 -f tag=v1.0.0`.
   Manual dispatch from a branch, a mismatched input or a mismatched lock/project
   version fails before tests or publication.
4. Wait for the entire workflow, not merely the image push, to succeed. Record
   the immutable `ghcr.io/<owner>/<repository>@sha256:...` reference and exact
   certificate identity from the **Verified release image** run summary.
5. Verify the digest independently before deploying it. Treat a failed signing,
   attestation or verification step as an incomplete release even if GHCR already
   contains image layers or tags. Revoke/remove incomplete release tags as needed;
   this workflow cannot atomically publish and sign a registry artifact.

GHCR uses the lowercased GitHub repository path. The workflow publishes the
package version tag (without `v`) and `sha-<full-source-commit>` tag; it does not
publish `latest`. Tags, including commit-named tags, are mutable registry pointers.
Rebuilds/reruns can produce a different digest; deploy and verify by digest.

The release workflow independently runs locked dependency installation, release
policy checks, Ruff, mypy, pytest, Bandit, dependency auditing and distribution
builds on Python 3.12 on both Linux and Windows. Each release-test platform also
sets up Node 22, runs `npm ci --no-audit --no-fund` against
`sdk/typescript/package-lock.json`, runs `npm test` (which compiles TypeScript before
running the SDK tests), and checks package contents with `npm pack --dry-run`.
The publishing job requires version validation and the entire test matrix,
including these SDK gates, to succeed. Normal CI has a separate `typescript-sdk`
job with the same Node/npm gates. This does not rely on a previous green branch
CI run. Distribution builds are validation only: the workflow publishes a container
to GHCR, not a PyPI release or GitHub Release.

### Repository controls and permissions

Enable Actions and allow `GITHUB_TOKEN` to publish the repository's GHCR package.
An existing package may need its Actions repository access explicitly configured.
No registry PAT, Cosign private key, Nebius key or other application credential is
required for releasing. Only the publishing job receives `packages: write` and
`id-token: write`; validation and tests have read-only repository access. Checkouts
do not persist Git credentials.

Protect release tags (including against deletion/recreation), the default branch
and changes to the release workflow through repository rulesets and review.
These repository settings are **not** configured by this change. A workflow
identity is not a replacement for reviewing the source commit or protecting tags.
Manual runs must select an existing matching version tag; they cannot publish
arbitrary branch heads through the supplied workflow.

## What the pipeline produces

- An OCI image index for `linux/amd64` and `linux/arm64` built with Buildx/QEMU.
- BuildKit SBOMs and maximum-mode build provenance attached to the index. These
  BuildKit attestations are not independently Cosign-signed; the index signature
  binds the index and the manifests it references. This is not a claim of a SLSA
  certification or reproducible builds.
- A keyless Cosign signature on the **immutable index digest**, using GitHub OIDC,
  Fulcio and Rekor (no stored signing key).
- Two keyless-signed SPDX JSON attestations on that same index digest, produced by
  scanning the published index explicitly for `linux/amd64` and `linux/arm64`
  with Syft 1.55.0. Each predicate describes one selected platform, not both.
  These are image filesystem/dependency inventories, not Arbalest scan reports
  or vulnerability-free certifications.
- In-workflow verification of the signature and SPDX attestation type against the
  exact repository/workflow/tag identity and the GitHub OIDC issuer.

All workflow actions use full commit references checked against their upstream
GitHub repositories when introduced. The Cosign installer pin resolves the
annotated `v3` tag to its commit; Cosign 2.5.2 is checksum-verified by that installer.
Syft's Linux amd64 archive is anchored by a literal SHA-256 checked before
extraction, not an unverified `curl | sh` installer. Python's multi-platform base
index is digest-pinned. Review and deliberately refresh these anchors for security
updates. Action pins do not pin every transitive infrastructure dependency (for
example the hosted runner, BuildKit's SBOM generator or QEMU image).

Publication contacts GHCR, dependency registries and upstream tool download
services. Signing contacts GitHub's OIDC service and public Sigstore services;
certificate identities and artifact digest information are recorded in the public
transparency log. Review that metadata disclosure for private repositories.
The pipeline does not send application credentials to these services.

## Verify before use

Install a trusted Cosign (the workflow uses 2.5.2) and authenticate to GHCR if the
package is private. Substitute the **actual successful run's** repository, tag and
immutable digest below; the values in angle brackets are not published artifacts.
Do not derive trust solely from a mutable tag or accept an arbitrary identity regex.

```sh
IMAGE='ghcr.io/<owner>/<repository>@sha256:<64-hex-index-digest>'
IDENTITY='https://github.com/<owner>/<repository>/.github/workflows/release.yml@refs/tags/v1.0.0'

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"

cosign verify-attestation --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE" > verified-attestations.jsonl
```

Both commands must succeed. `verify-attestation` checks signatures, subject digest,
issuer, identity and predicate type; inspect the returned envelopes' base64-encoded
`payload` statements for both platform inventories and their SPDX `predicate`
contents. An attestation's existence alone is not a package/security policy check.
Do not disable transparency-log or certificate verification to bypass a failure.

Inspect the index and its BuildKit attestations separately if required by your
build-provenance policy:

```sh
docker buildx imagetools inspect "$IMAGE"
docker buildx imagetools inspect "$IMAGE" --format '{{json .Provenance}}'
docker buildx imagetools inspect "$IMAGE" --format '{{json .SBOM}}'
```

Use the verified digest for pulls and runs, not a newly resolved tag. Keep the
successful run URL, expected source commit, digest and identity in deployment
records. Consumers needing a stricter source/provenance policy must also validate
those claims; signature validity alone does not approve the source code.

## Runtime image and credentials

The multi-stage `Dockerfile` installs the project and locked production dependencies
as a noneditable package. The final Python 3.12 slim image copies only that virtual
environment and the license from the build inputs; uv and development dependencies
are not copied from the builder. It runs as UID/GID `10001:10001` with a writable
`/workspace` and home directory. The application environment is root-owned rather
than writable by the runtime user. It is not a compiler/scanner-tool distribution:
Git, language toolchains, optional scanner CLIs and local-session provider CLIs are
not installed. Features that require those external executables need a separately
reviewed derived image or an appropriate remote backend.

`.dockerignore` denies the context by default and allows only package/build inputs
and Python source. `.env`, `.env.*`, private keys, VCS metadata, local state, tests,
examples and generated reports are not sent to the builder. The Dockerfile never
uses `COPY . .`, credentials as build arguments, or application secrets. Dotenv
loading is disabled in the runtime image; pass credentials through runtime
environment variables, never through `docker build --build-arg` or copied files.

For example, after verification, in a shell where the variables are already
provided securely (values are not written into shell history). This prints help
without calling Nebius; replace `--help` with the intended command and mounts:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --tmpfs /home/arbalest:rw,nosuid,nodev,uid=10001,gid=10001,size=64m \
  --env NEBIUS_API_KEY --env NEBIUS_PROJECT_ID \
  --env ARBALEST_SANDBOX_BACKEND=nebius \
  "$IMAGE" --help
```

`NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID` are runtime credentials, not release/build
credentials. Nebius sandbox operations require service access and can incur usage
charges; the configured project and account need the required permissions. Docker
runtime environment variables are visible to Docker administrators; use an
appropriate secrets delivery mechanism for your deployment. No credential values
belong in workflow inputs or release logs.

The default entrypoint is `arbalest`, with `--help` as its default argument. For
MCP use `--entrypoint arbalest-mcp` and `-i` for stdio. Mount only intended target
repositories and give UID 10001 explicit access; read-only mounts are appropriate
for scans, while remediation and scan archives may need narrowly scoped writable
storage. The read-only example above does not provide a writable target/archive.

**No Docker socket is mounted or declared by default.** Local Docker sandbox
operations will not work without separately configured daemon access. Do not solve
this by adding a default `/var/run/docker.sock` mount or privileged mode: daemon
access can grant host-equivalent control and defeats the container's nonroot
boundary. Prefer the explicitly selected remote Nebius sandbox when available.

## TypeScript SDK: local package only

`@arbalest/sdk` in `sdk/typescript` is currently a local ESM package for Node 22+
and requires a separately installed compatible Arbalest Python CLI. There is no
npm publication step, registry authentication, or claim that this package is
available from npm. SDK tests use a fixture CLI rather than live provider calls.

To validate and create a local tarball from the SDK directory:

```sh
npm ci --no-audit --no-fund
npm test
npm pack --dry-run
# Optional local artifact; this creates a .tgz but does not publish it:
npm pack
```

`npm test` runs the existing build and Node test runner; packing runs the existing
`prepack` build. `npm ci` requires registry access unless packages are already
cached. The CI/release gates use only the dry run, not `npm pack` or `npm publish`,
and do not upload an SDK tarball. npm publishing remains a separate, unapproved
future operation; do not add registry tokens to these validation jobs. The SDK is
not included in the minimal Python runtime container.

## Offline local checks

With the project's development environment installed:

```sh
uv run --frozen python scripts/verify-release.py --check-files
uv run --frozen python scripts/verify-release.py --tag v1.0.0
uv run --frozen ruff check scripts/verify-release.py
```

`verify-release.py` checks local metadata/version agreement and selected structural
workflow/container policies. It does not contact GitHub to authenticate action
commits, execute tests, verify image signatures, or prove all release policies.
The workflow uses `uv sync --locked` to check full lock freshness in addition to
this script's metadata checks. Full container builds, network auditing and live
Sigstore/GHCR verification happen only when those commands or the workflow are
actually run; the offline checks cannot establish that publication will succeed.
