# Versioning and image tags

The repository uses Semantic Versioning and one version for both images because the template, metadata contract, monitoring controller, and provider reconcilers evolve together.

- **PATCH**: compatible fixes and dependency/documentation corrections.
- **MINOR**: backward-compatible features, provider options, checks or fields.
- **MAJOR**: incompatible configuration, metadata, environment or deployment changes.

## Release flow

1. Merge a green pull request to `main`.
2. Prepare release notes.
3. Create `git tag -a v1.2.3 -m "v1.2.3"` and push it.
4. GitHub Actions publishes both `linux/amd64` and `linux/arm64` images as `1.2.3`, `1.2`, `1`, and `latest`.

Pin `1.2.3` or an OCI digest in production. Floating tags ease evaluation but reduce deterministic rollback. Pull requests build without publishing; ordinary `main` pushes do not publish, so the SemVer tag is the release boundary. Before 1.0, breaking changes increment MINOR.
