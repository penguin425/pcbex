# GitHub Actions supply-chain policy

Every external `uses:` reference in repository workflows and composite actions,
including the public root action, is fixed to a full lowercase 40-character
commit SHA. The adjacent version comment records the reviewed upstream release
without making the mutable tag part of execution.

| Action | Reviewed release | Commit |
|---|---:|---|
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `github/codeql-action` | `v4.37.3` | `e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81` |
| `actions/attest` | `v4.2.1` | `508db95dd578ae2727ebd6217d5ba78e4fbda05d` |
| `anchore/sbom-action` | `v0.24.0` | `e22c389904149dbc22b58101806040fa8d37a610` |

The CodeQL release uses an annotated Git tag. Its row therefore records the
dereferenced commit, not the tag-object SHA.

`scripts/tests/test_action_pinning.py` recursively inspects workflows and
composite actions. It permits repository-local `./` actions, requires external
repository actions to use a full commit SHA plus a version comment, and rejects
mutable tags or branches, short SHAs, expressions, malformed references, and
Docker `uses:` references.

Dependabot checks the `github-actions` ecosystem weekly. For each update:

1. confirm the proposed SHA is the commit resolved by the named release in the
   official upstream repository;
2. for annotated tags, dereference the tag object and record the commit;
3. update every use of that action and this table in the same pull request;
4. run the pinning test and all affected workflows; and
5. merge only after CodeQL and the protected required checks pass.

Repository Actions policy has `sha_pinning_required` enabled. Running
`scripts/release-audit.py --check-protection` with a repository-administration
read credential checks the live Actions-permissions API alongside
protected-main policy and fails if Actions are disabled, the response shape is
invalid, or SHA pinning is no longer required.
