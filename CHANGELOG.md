# Changelog

## 0.1.1

- Rename node to **Claude Code (Credentials)** (`claudeCodeCreds`) so it can coexist with other Claude Code community nodes
- Require **n8n credentials** for auth (no auth from container env)
- Redact the API key from node outputs if it ever appears
- Fix workflow templates and GitHub Actions to reference the `@sureliving` package

## 0.1.0

- Initial fork published under `@sureliving/n8n-nodes-claudecode`
- Add `Anthropic API` credential type and inject key only into the spawned process env

## Upstream history

Upstream project history is tracked in:
- `https://github.com/johnlindquist/n8n-nodes-claudecode`
- `https://github.com/holt-web-ai/n8n-nodes-claudecode`
