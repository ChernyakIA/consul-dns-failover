# Security policy

Report vulnerabilities privately through GitHub Security Advisories.

- Never commit Consul tokens, DNS credentials, gossip keys, private keys, private-PKI bundles, or live desired state.
- Use least-privilege identities and separate monitoring and DNS-writer credentials.
- Pin release images or digests and review rendered manifests.
- Keep one writer per provider/zone set.
- Treat `remove` and `fallback` as production-impacting policy changes.

The Microsoft DNS backend requires strict SSH host-key verification through `WIN_SSH_KNOWN_HOSTS`. An explicit `WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK=true` escape hatch exists only for temporary migration and emits a warning; do not use it in production. Prefer SSH keys. If credentials were committed, rotate them first; deleting a later revision is insufficient without history cleanup.
