# Example configuration

`conf/` is git-ignored (it holds admin tokens and key material). This directory
is a committed, runnable example you can copy to bootstrap a local instance:

```bash
cp -r conf.example conf
docker compose up
```

It defines a single per-organization issuer instance, **`yivi`**, demonstrating
the file layout described in the top-level [README](../README.md#file-based-configuration):

- `issuer/yivi.json` — the issuer instance (served at `/yivi`)
- `dids/yivi-did.json` — a self-contained `did:jwk` signing key (generated on first run)
- `metadata/yivi.json` — issuer metadata; `credential_configurations_supported`
  defines three `dc+sd-jwt` credentials with localized (en/nl) `display` on the
  credential and each claim
- `vct/nl-yivi-*.json` — SD-JWT VC Type Metadata, one per credential

The values are local-development defaults (`http://localhost:3000/yivi`, a dummy
`adminToken`). For a real deployment, provide your own `conf/` (e.g. the
`openid4vc-poc-ops` config, where the base URL, DID host and admin token are
substituted per environment).

Credential config ids are namespaced per organization (`YiviEmailSdJwt`, …) so
they stay unique across issuer instances that share this agent.
