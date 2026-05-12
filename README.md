# scan-shai-hulud

A fast, zero-dependency Bash scanner to detect whether your machine is affected by the **CVE-2026-45321 "Mini Shai-Hulud"** supply chain attack.

On May 11, 2026, over **170 npm packages** and **2 PyPI packages** across TanStack, Mistral AI, UiPath, OpenSearch, and Guardrails AI were simultaneously poisoned. The malicious payload steals AWS credentials, GitHub tokens, npm tokens, Vault secrets, and SSH keys — and includes a self-propagating worm that spreads through CI/CD pipelines.

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/qi-scape/scan-shai-hulud/main/scan-shai-hulud.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/qi-scape/scan-shai-hulud.git
cd scan-shai-hulud
chmod +x scan-shai-hulud.sh
./scan-shai-hulud.sh
```

## Usage

```bash
# Scan current directory + system-wide persistence checks
./scan-shai-hulud.sh

# Scan a specific project
./scan-shai-hulud.sh ~/my-project

# Deep scan across entire home directory
./scan-shai-hulud.sh --full
```

## What It Checks

The scanner runs 8 steps:

| Step | Description |
|------|-------------|
| **Persistence** | macOS LaunchAgent (file + `launchctl` loaded state), Linux systemd service, dead-man's switch script, `.claude/` and `.vscode/` payload drops, injected GitHub Actions workflows, `/tmp` droppers |
| **Malicious files** | `router_init.js`, `tanstack_runner.js`, `router_runtime.js`, `gh-token-monitor.sh`, `transformers.pyz` — verified against 3 known SHA-256 hashes |
| **C2 indicators** | Scans config files (`.npmrc`, `.bashrc`, `.zshrc`, `.env`) and project source for 6 C2 domains + campaign markers |
| **npm packages** | All `node_modules` trees, npm global root, lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`), npm cache — with precise per-package matching (42 specific @tanstack router packages, not the entire scope) |
| **PyPI packages** | `pip show` across all Python/conda environments + `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock` |
| **Git repos** | Malicious commit hash in history, `dependabout/*/setup-formatter` dead-drop branches, dead-drop commit author, injected `codeql_analysis.yml` |
| **Shell history & env** | Bash/Zsh/Fish history for payload execution traces, shell RC files for injections, environment variables for C2 domains |
| **Network & tokens** | Active connections to C2 via `lsof`, `/etc/hosts`, `~/.ssh/known_hosts`, npm token list |

## Affected Packages

**170 npm packages** across 15 scopes:

- **@tanstack** (42 packages) — router ecosystem only (`react-router`, `vue-router`, `solid-router`, `router-core`, etc.)
- **@uipath** (65 packages) — full automation tooling suite
- **@squawk** (20 packages) — aviation data packages
- **@tallyui** (10 packages) — POS/connector packages
- **@mistralai** (3 packages) — `mistralai`, `mistralai-azure`, `mistralai-gcp`
- **@opensearch-project** (1 package) — `opensearch`
- **@beproduct**, **@draftauth**, **@draftlab**, **@supersurkhet**, **@taskflow-corp**, **@tolka**, **@mesadev**, **@ml-toolkit-ts**, **@dirigible-ai**
- **Unscoped**: `agentwork-cli`, `cmux-agent-mcp`, `cross-stitch`, `git-branch-selector`, `git-git-git`, `ml-toolkit-ts`, `nextmove-mcp`, `safe-action`, `ts-dna`, `wot-api`

**2 PyPI packages**:

- `mistralai==2.4.6`
- `guardrails-ai==0.10.1`

## C2 Infrastructure

| Indicator | Value |
|-----------|-------|
| Primary exfil | `filev2.getsession.org` |
| Session seeds | `seed{1,2,3}.getsession.org` |
| Secondary C2 | `api.masscan.cloud`, `git-tanstack.com` |
| Payload staging | `litter.catbox.moe/h8nc9u.js`, `litter.catbox.moe/7rrc6l.mjs` |
| Malicious commit | `79ac49eedf774dd4b0cfa308722bc463cfe5885c` |

## If You Find Something

If the scanner reports **CRITICAL** findings:

1. **Rotate all credentials** reachable from the affected machine — AWS keys, GitHub tokens (`ghp_*`, `gho_*`, `ghs_*`), npm tokens, Vault tokens, SSH keys, Kubernetes service account tokens
2. **Remove malicious packages** — `npm cache clean --force && rm -rf node_modules && npm install`
3. **Remove persistence** — `launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
4. **Block C2 domains** at DNS/proxy level
5. **Audit GitHub Actions** runs since `2026-05-11T19:20Z`
6. **Check for unauthorized npm publishes** — `npm access ls-packages`

## References

- [CVE-2026-45321](https://www.cve.org/CVERecord?id=CVE-2026-45321) — CVSS 9.6 Critical
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx) — GitHub Advisory
- [TanStack Postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [Aikido: Mini Shai-Hulud Is Back](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised)
- [SafeDep: Mass Supply Chain Attack](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)
- [Snyk: TanStack Compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [The Hacker News Coverage](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)

## Requirements

- Bash 4+ (macOS ships with 3.x but the script is compatible)
- Standard UNIX utilities (`find`, `grep`, `shasum`)
- Optional: `mdfind` (macOS Spotlight, used for faster file search)
- Optional: `npm`, `pip` (for package/token checks)
- Optional: `git` (for repository checks)
- Optional: `lsof` (for network connection checks)

## License

MIT
