#!/usr/bin/env bash
# scan-shai-hulud.sh — Detect CVE-2026-45321 "Mini Shai-Hulud" supply chain compromise
# Covers 170 npm + 2 PyPI packages across TanStack, Mistral AI, UiPath, OpenSearch, Guardrails AI, etc.
#
# Usage:
#   ./scan-shai-hulud.sh              # scan current directory + system-wide checks
#   ./scan-shai-hulud.sh ~/projects   # scan specific directory
#   ./scan-shai-hulud.sh --full       # deep scan across home directory

set -eo pipefail

# ─── Colors & output helpers ────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

FINDINGS=0
WARNINGS=0

finding() { ((FINDINGS++)) || true; echo -e "  ${RED}[CRITICAL]${RESET} $*"; }
warning() { ((WARNINGS++)) || true; echo -e "  ${YELLOW}[WARNING]${RESET}  $*"; }
info()    { echo -e "  ${CYAN}[INFO]${RESET}     $*"; }
ok()      { echo -e "  ${GREEN}[OK]${RESET}       $*"; }
section() { echo; echo -e "${BOLD}═══ $* ═══${RESET}"; }

# ─── Self-awareness (so we don't flag our own IOC strings) ──────────────────
SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Parse args ─────────────────────────────────────────────────────────────
FULL_MODE=0
SCAN_DIR="$(pwd)"
HOME_DIR="${HOME:-/Users/$(whoami)}"

if [ "${1:-}" = "--full" ]; then
  FULL_MODE=1
  SCAN_DIR="$HOME_DIR"
elif [ -n "${1:-}" ]; then
  SCAN_DIR="$1"
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║   Mini Shai-Hulud Supply Chain Scanner (CVE-2026-45321)        ║"
echo "║   170 npm + 2 PyPI packages | TanStack, Mistral AI, UiPath,   ║"
echo "║   OpenSearch, Guardrails AI, Squawk, TallyUI + others         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  Scan target: ${SCAN_DIR}"
echo "  Mode:        $([ "$FULL_MODE" -eq 1 ] && echo "full (--full)" || echo "targeted")"
echo "  Started:     $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ─── IOC data ───────────────────────────────────────────────────────────────

KNOWN_HASHES="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01"

KNOWN_BAD_VERSIONS="@tanstack/react-router|1.169.5
@tanstack/react-router|1.169.8
@tanstack/vue-router|1.169.5
@tanstack/vue-router|1.169.8
@tanstack/solid-router|1.169.5
@tanstack/solid-router|1.169.8
@tanstack/router-core|1.169.5
@tanstack/router-core|1.169.8
@tanstack/react-start|1.167.68
@tanstack/react-start|1.167.71
@tanstack/router-plugin|1.167.38
@tanstack/router-plugin|1.167.41
@mistralai/mistralai|2.2.2
@mistralai/mistralai|2.2.3
@mistralai/mistralai|2.2.4
@mistralai/mistralai-azure|1.7.1
@mistralai/mistralai-azure|1.7.2
@mistralai/mistralai-azure|1.7.3
@mistralai/mistralai-gcp|1.7.1
@mistralai/mistralai-gcp|1.7.2
@mistralai/mistralai-gcp|1.7.3
@opensearch-project/opensearch|3.5.3
@opensearch-project/opensearch|3.6.2
@opensearch-project/opensearch|3.7.0
@opensearch-project/opensearch|3.8.0"

# Scopes where ALL packages were compromised (check any package in the scope)
COMPROMISED_SCOPES_ALL="@mistralai @uipath @squawk @tallyui @beproduct @draftauth @draftlab @supersurkhet @taskflow-corp @tolka @mesadev @ml-toolkit-ts @dirigible-ai"

# @tanstack: only the 42 router-ecosystem packages were compromised (NOT query/table/form/etc.)
TANSTACK_COMPROMISED="arktype-adapter eslint-plugin-router eslint-plugin-start history nitro-v2-vite-plugin react-router react-router-devtools react-router-ssr-query react-start react-start-client react-start-rsc react-start-server router-cli router-core router-devtools router-devtools-core router-generator router-plugin router-ssr-query-core router-utils router-vite-plugin solid-router solid-router-devtools solid-router-ssr-query solid-start solid-start-client solid-start-server start-client-core start-fn-stubs start-plugin-core start-server-core start-static-server-functions start-storage-context valibot-adapter virtual-file-routes vue-router vue-router-devtools vue-router-ssr-query vue-start vue-start-client vue-start-server zod-adapter"

# @opensearch-project: only opensearch was hit
OPENSEARCH_COMPROMISED="opensearch"

COMPROMISED_UNSCOPED="agentwork-cli cmux-agent-mcp cross-stitch git-branch-selector git-git-git ml-toolkit-ts nextmove-mcp safe-action ts-dna wot-api"

C2_REGEX='filev2\.getsession\.org|seed[123]\.getsession\.org|api\.masscan\.cloud|git-tanstack\.com|litter\.catbox\.moe/h8nc9u|litter\.catbox\.moe/7rrc6l|EveryBoiWeBuildIsAWormyBoi|A Mini Shai-Hulud has Appeared|svksjrhjkcejg'

POISON_MARKERS='79ac49eedf774dd4b0cfa308722bc463cfe5885c|voicproducoes|tanstack/setup|tanstack_runner|router_init\.js|bun run tanstack_runner'

MALICIOUS_COMMIT="79ac49eedf774dd4b0cfa308722bc463cfe5885c"

# ─── Exclusions for find (shared across steps) ─────────────────────────────
FIND_PRUNE=(-not -path "*/Library/*" -not -path "*/.Trash/*" -not -path "*/.npm/*"
  -not -path "*/.cache/*" -not -path "*/.nvm/*" -not -path "*/.docker/*"
  -not -path "*/.cargo/*" -not -path "*/.rustup/*" -not -path "*/Applications/*"
  -not -path "*/.electron*" -not -path "*/.gradle/*")

# ─── Helper functions ───────────────────────────────────────────────────────

hash_is_malicious() { echo "$KNOWN_HASHES" | grep -qF "$1"; }
version_is_malicious() { echo "$KNOWN_BAD_VERSIONS" | grep -qF "$1|$2"; }

check_npm_package() {
  local pkg_name="$1"
  local pkg_dir="$2"
  local pkg_json="${pkg_dir}/package.json"

  [ -f "$pkg_json" ] || return 0

  local version
  version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null \
    | head -1 | sed 's/.*"\([^"]*\)"/\1/')
  [ -z "$version" ] && return 0

  if version_is_malicious "$pkg_name" "$version"; then
    finding "CONFIRMED malicious: ${pkg_name}@${version}"
    return 0
  fi

  if grep -qE "$POISON_MARKERS" "$pkg_json" 2>/dev/null; then
    finding "Poisoned dependency marker in: ${pkg_name}@${version}"
    return 0
  fi

  warning "Affected-scope package installed: ${pkg_name}@${version} — verify version is clean"
}

is_compromised_package() {
  local pkg_name="$1"
  case "$pkg_name" in
    @tanstack/*)
      local short="${pkg_name#@tanstack/}"
      for t in $TANSTACK_COMPROMISED; do
        [ "$short" = "$t" ] && return 0
      done
      return 1
      ;;
    @opensearch-project/*)
      local short="${pkg_name#@opensearch-project/}"
      [ "$short" = "opensearch" ] && return 0
      return 1
      ;;
    *)
      return 0  # all-scope match or unscoped — already filtered by caller
      ;;
  esac
}

scan_node_modules() {
  local base="$1"
  [ -d "${base}/node_modules" ] || return 0

  # Scopes where ALL packages are compromised
  for scope in $COMPROMISED_SCOPES_ALL; do
    local scope_dir="${base}/node_modules/${scope}"
    [ -d "$scope_dir" ] || continue
    for pkg_dir in "$scope_dir"/*/; do
      [ -d "$pkg_dir" ] || continue
      check_npm_package "${scope}/$(basename "$pkg_dir")" "$pkg_dir"
    done
  done

  # @tanstack: only specific router packages
  if [ -d "${base}/node_modules/@tanstack" ]; then
    for short in $TANSTACK_COMPROMISED; do
      local pkg_dir="${base}/node_modules/@tanstack/${short}"
      [ -d "$pkg_dir" ] || continue
      check_npm_package "@tanstack/${short}" "$pkg_dir"
    done
  fi

  # @opensearch-project: only opensearch
  local os_dir="${base}/node_modules/@opensearch-project/opensearch"
  if [ -d "$os_dir" ]; then
    check_npm_package "@opensearch-project/opensearch" "$os_dir"
  fi

  # Unscoped packages
  for pkg in $COMPROMISED_UNSCOPED; do
    local pkg_dir="${base}/node_modules/${pkg}"
    [ -d "$pkg_dir" ] || continue
    check_npm_package "$pkg" "$pkg_dir"
  done
}

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: Persistence mechanisms (specific paths — instant)
# ═══════════════════════════════════════════════════════════════════════════
section "1/8  Persistence mechanisms"

found=0

# macOS LaunchAgent
if [ -f "${HOME_DIR}/Library/LaunchAgents/com.user.gh-token-monitor.plist" ]; then
  finding "macOS LaunchAgent file: ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  found=1
fi

# macOS: check if agent is loaded even if plist was deleted
if command -v launchctl &>/dev/null; then
  if launchctl list 2>/dev/null | grep -q "gh-token-monitor"; then
    finding "macOS LaunchAgent is LOADED: gh-token-monitor (active even if plist removed)"
    found=1
  fi
fi

# Linux systemd user service
if [ -f "${HOME_DIR}/.config/systemd/user/gh-token-monitor.service" ]; then
  finding "systemd persistence: ~/.config/systemd/user/gh-token-monitor.service"
  found=1
fi
if command -v systemctl &>/dev/null; then
  if systemctl --user is-active gh-token-monitor.service &>/dev/null; then
    finding "systemd service is ACTIVE: gh-token-monitor.service"
    found=1
  fi
fi

# Dead-man's switch script
if [ -f "${HOME_DIR}/.local/bin/gh-token-monitor.sh" ]; then
  finding "Dead-man's switch: ~/.local/bin/gh-token-monitor.sh"
  found=1
fi

# .claude directory payload drops
for cfile in router_runtime.js setup.mjs; do
  for dir in "$SCAN_DIR" "$HOME_DIR"; do
    if [ -f "${dir}/.claude/${cfile}" ]; then
      finding "Payload in .claude/: ${dir}/.claude/${cfile}"
      found=1
    fi
  done
done

# .claude/settings.json tampering
for dir in "$SCAN_DIR" "$HOME_DIR"; do
  if [ -f "${dir}/.claude/settings.json" ]; then
    if grep -qE "$C2_REGEX|$POISON_MARKERS" "${dir}/.claude/settings.json" 2>/dev/null; then
      finding "Tampered .claude/settings.json: ${dir}/.claude/settings.json"
      found=1
    fi
  fi
done

# .vscode payload drops
for vfile in setup.mjs tasks.json; do
  if [ -f "${SCAN_DIR}/.vscode/${vfile}" ]; then
    if grep -qE "$C2_REGEX|$POISON_MARKERS" "${SCAN_DIR}/.vscode/${vfile}" 2>/dev/null; then
      finding "Malicious .vscode/${vfile}: ${SCAN_DIR}/.vscode/${vfile}"
      found=1
    fi
  fi
done

# Injected GitHub Actions workflow (in scan dir)
if [ -f "${SCAN_DIR}/.github/workflows/codeql_analysis.yml" ]; then
  if grep -qE "$C2_REGEX" "${SCAN_DIR}/.github/workflows/codeql_analysis.yml" 2>/dev/null; then
    finding "Injected workflow: ${SCAN_DIR}/.github/workflows/codeql_analysis.yml"
    found=1
  fi
fi

# PyPI / temp droppers
for dropper in /tmp/transformers.pyz /tmp/router_init.js /tmp/tanstack_runner.js; do
  if [ -f "$dropper" ]; then
    finding "Dropper in /tmp: $dropper"
    found=1
  fi
done

[ "$found" -eq 0 ] && ok "No persistence mechanisms found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: Malicious file signatures (mdfind on macOS for speed)
# ═══════════════════════════════════════════════════════════════════════════
section "2/8  Malicious file signatures"

found=0
for fname in router_init.js tanstack_runner.js router_runtime.js gh-token-monitor.sh transformers.pyz; do
  results=()

  # mdfind is fast but may not index all dirs; use it and also check specific paths
  if command -v mdfind &>/dev/null; then
    while IFS= read -r f; do
      [ -n "$f" ] && results+=("$f")
    done < <(mdfind -onlyin "$SCAN_DIR" "kMDItemFSName == '$fname'" 2>/dev/null)
  else
    while IFS= read -r f; do
      [ -n "$f" ] && results+=("$f")
    done < <(find "$SCAN_DIR" -maxdepth 6 -name "$fname" \
      "${FIND_PRUNE[@]}" -not -path "*/.git/*" 2>/dev/null || true)
  fi

  for match in "${results[@]}"; do
    [[ "$match" == *"scan-shai-hulud"* ]] && continue
    hash=$(shasum -a 256 "$match" 2>/dev/null | awk '{print $1}')
    if hash_is_malicious "$hash"; then
      finding "CONFIRMED malicious: $match (SHA-256 match)"
    else
      warning "Suspicious filename: $match (hash: ${hash:0:16}…)"
    fi
    found=1
  done
done

[ "$found" -eq 0 ] && ok "No known malicious files found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: C2 indicators in config files
# ═══════════════════════════════════════════════════════════════════════════
section "3/8  C2 & exfiltration indicators"

found=0

# High-value config files
for f in \
  "${HOME_DIR}/.npmrc" \
  "${HOME_DIR}/.yarnrc" \
  "${HOME_DIR}/.yarnrc.yml" \
  "${HOME_DIR}/.bunfig.toml" \
  "${HOME_DIR}/.bashrc" \
  "${HOME_DIR}/.zshrc" \
  "${HOME_DIR}/.bash_profile" \
  "${HOME_DIR}/.zprofile" \
  "${SCAN_DIR}/.npmrc" \
  "${SCAN_DIR}/.env" \
  "${SCAN_DIR}/.env.local"; do
  [ -f "$f" ] || continue
  if grep -qE "$C2_REGEX" "$f" 2>/dev/null; then
    finding "C2 indicator: $f"
    found=1
  fi
done

# systemd config dir
if [ -d "${HOME_DIR}/.config/systemd" ]; then
  while IFS= read -r match; do
    [ -z "$match" ] && continue
    finding "C2 indicator: $match"
    found=1
  done < <(grep -rl -E "$C2_REGEX" "${HOME_DIR}/.config/systemd" 2>/dev/null | head -10 || true)
fi

# If scanning a project dir (not $HOME), grep source files — skip our own repo
if [ "$SCAN_DIR" != "$HOME_DIR" ]; then
  while IFS= read -r match; do
    [ -z "$match" ] && continue
    real_match="$(cd "$(dirname "$match")" 2>/dev/null && pwd)/$(basename "$match")"
    [[ "$real_match" == "$SELF_DIR"/* ]] && continue
    finding "C2 indicator: $match"
    found=1
  done < <(grep -rl --include='*.js' --include='*.mjs' --include='*.cjs' \
    --include='*.ts' --include='*.json' --include='*.yml' --include='*.yaml' \
    --include='*.sh' --include='*.py' --include='*.md' \
    -E "$C2_REGEX" "$SCAN_DIR" \
    --exclude-dir='.git' --exclude-dir='node_modules' \
    2>/dev/null | head -50 || true)
fi

[ "$found" -eq 0 ] && ok "No C2/exfiltration indicators found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: Compromised npm packages (node_modules + lockfiles + global)
# ═══════════════════════════════════════════════════════════════════════════
section "4/8  Compromised npm packages"

found_npm=0

# --- Locate node_modules ---
info "Searching for node_modules..."
nm_dirs=()

# Always use find (mdfind skips node_modules by default on macOS)
while IFS= read -r nm; do
  [ -z "$nm" ] && continue
  nm_dirs+=("$(dirname "$nm")")
done < <(find "$SCAN_DIR" -maxdepth 5 -name "node_modules" -type d \
  "${FIND_PRUNE[@]}" \
  -not -path "*/node_modules/*/node_modules/*" \
  2>/dev/null || true)

info "Found ${#nm_dirs[@]} node_modules tree(s)"

for parent in "${nm_dirs[@]}"; do
  info "Scanning: ${parent}/node_modules"
  scan_node_modules "$parent"
done

# --- npm global packages ---
if command -v npm &>/dev/null; then
  npm_global_root=$(timeout 10 npm root -g 2>/dev/null) || true
  if [ -n "$npm_global_root" ] && [ -d "$npm_global_root" ]; then
    info "Scanning npm global: $npm_global_root"
    scan_node_modules "$(dirname "$npm_global_root")"
  fi
fi

# --- Lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb) ---
info "Checking lockfiles..."
lockfiles=()
while IFS= read -r lf; do
  [ -z "$lf" ] && continue
  lockfiles+=("$lf")
done < <(find "$SCAN_DIR" -maxdepth 5 \
  \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" \) \
  -not -path "*/node_modules/*" \
  "${FIND_PRUNE[@]}" \
  2>/dev/null || true)

info "Found ${#lockfiles[@]} lockfile(s)"

for lockfile in "${lockfiles[@]}"; do
  # Malicious git commit reference
  if grep -q "$MALICIOUS_COMMIT" "$lockfile" 2>/dev/null; then
    finding "Malicious commit ref in lockfile: $lockfile"
    found_npm=1
  fi

  # Known-bad versions
  while IFS='|' read -r pkg ver; do
    if grep -qE "\"${pkg}\".*\"${ver}\"|${pkg}@${ver}|\"${pkg}\": \"${ver}\"" "$lockfile" 2>/dev/null; then
      finding "Malicious version in lockfile: ${pkg}@${ver} — $lockfile"
      found_npm=1
    fi
  done <<< "$KNOWN_BAD_VERSIONS"
done

# --- npm cache quick probe ---
NPM_CACHE="${HOME_DIR}/.npm/_cacache"
if [ -d "$NPM_CACHE" ]; then
  if timeout 15 grep -rl "getsession\.org\|$MALICIOUS_COMMIT" \
    "$NPM_CACHE/content-v2" 2>/dev/null | head -1 | grep -q .; then
    warning "npm cache may contain malicious package data — run: npm cache clean --force"
    found_npm=1
  fi
fi

[ "$found_npm" -eq 0 ] && ok "No compromised npm packages found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: Compromised PyPI packages + requirements files
# ═══════════════════════════════════════════════════════════════════════════
section "5/8  Compromised PyPI packages"

found_pypi=0

check_pip() {
  local pip_cmd="$1"
  command -v "$pip_cmd" &>/dev/null || return 0
  info "Checking: $pip_cmd"

  local ver
  ver=$(timeout 10 "$pip_cmd" show mistralai 2>/dev/null | grep -i "^Version:" | awk '{print $2}') || true
  if [ "$ver" = "2.4.6" ]; then
    finding "CONFIRMED malicious: mistralai==2.4.6 (via $pip_cmd)"
    found_pypi=1
  elif [ -n "$ver" ]; then
    info "mistralai==${ver} installed (malicious version is 2.4.6)"
  fi

  ver=$(timeout 10 "$pip_cmd" show guardrails-ai 2>/dev/null | grep -i "^Version:" | awk '{print $2}') || true
  if [ "$ver" = "0.10.1" ]; then
    finding "CONFIRMED malicious: guardrails-ai==0.10.1 (via $pip_cmd)"
    found_pypi=1
  elif [ -n "$ver" ]; then
    info "guardrails-ai==${ver} installed (malicious version is 0.10.1)"
  fi
}

for pip_cmd in pip pip3 pip3.10 pip3.11 pip3.12 pip3.13; do
  check_pip "$pip_cmd"
done

if command -v conda &>/dev/null; then
  while IFS= read -r env_path; do
    [ -z "$env_path" ] && continue
    [ -x "${env_path}/bin/pip" ] && check_pip "${env_path}/bin/pip"
  done < <(conda info --envs 2>/dev/null | grep -v '^#' | awk 'NF{print $NF}' || true)
fi

# Check requirements.txt / pyproject.toml for pinned malicious versions
while IFS= read -r reqfile; do
  [ -z "$reqfile" ] && continue
  if grep -qE 'mistralai[= ]*2\.4\.6|guardrails-ai[= ]*0\.10\.1' "$reqfile" 2>/dev/null; then
    finding "Malicious PyPI version pinned in: $reqfile"
    found_pypi=1
  fi
done < <(find "$SCAN_DIR" -maxdepth 4 \
  \( -name "requirements*.txt" -o -name "pyproject.toml" -o -name "Pipfile" -o -name "poetry.lock" \) \
  -not -path "*/node_modules/*" \
  "${FIND_PRUNE[@]}" \
  2>/dev/null || true)

[ "$found_pypi" -eq 0 ] && ok "No compromised PyPI packages found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 6: Git repository checks (worm propagation indicators)
# ═══════════════════════════════════════════════════════════════════════════
section "6/8  Git repository checks"

found_git=0

scan_git_repo() {
  local repo="$1"
  local git_dir="${repo}/.git"
  [ -d "$git_dir" ] || return 0

  # Check for malicious commit in history/reflog
  if git -C "$repo" log --all --oneline 2>/dev/null | grep -q "${MALICIOUS_COMMIT:0:12}"; then
    finding "Malicious commit in git history: $repo"
    found_git=1
  fi

  # Dead-drop branch pattern: dependabout/*/setup-formatter
  if git -C "$repo" branch -a 2>/dev/null | grep -q "dependabout.*setup-formatter"; then
    finding "Dead-drop branch found: $repo"
    found_git=1
  fi

  # Commits from dead-drop author
  if git -C "$repo" log --all --author="claude@users.noreply.github.com" --oneline 2>/dev/null | head -1 | grep -q .; then
    warning "Commits from dead-drop author (claude@users.noreply.github.com): $repo"
    found_git=1
  fi

  # Injected codeql_analysis.yml
  if [ -f "${repo}/.github/workflows/codeql_analysis.yml" ]; then
    if grep -qE "$C2_REGEX" "${repo}/.github/workflows/codeql_analysis.yml" 2>/dev/null; then
      finding "Injected workflow in repo: ${repo}/.github/workflows/codeql_analysis.yml"
      found_git=1
    fi
  fi
}

# Scan target directory if it's a git repo
if [ -d "${SCAN_DIR}/.git" ]; then
  info "Checking: $SCAN_DIR"
  scan_git_repo "$SCAN_DIR"
fi

# In full mode, find all git repos
if [ "$FULL_MODE" -eq 1 ]; then
  while IFS= read -r gitdir; do
    [ -z "$gitdir" ] && continue
    repo=$(dirname "$gitdir")
    [ "$repo" = "$SCAN_DIR" ] && continue  # already scanned
    info "Checking: $repo"
    scan_git_repo "$repo"
  done < <(find "$SCAN_DIR" -maxdepth 4 -name ".git" -type d \
    "${FIND_PRUNE[@]}" \
    2>/dev/null || true)
fi

[ "$found_git" -eq 0 ] && ok "No git-level indicators found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 7: Shell history & environment
# ═══════════════════════════════════════════════════════════════════════════
section "7/8  Shell history & environment"

found_shell=0

# Check shell history for payload execution artifacts
HISTORY_REGEX='tanstack_runner|router_init\.js|router_runtime\.js|getsession\.org|masscan\.cloud|git-tanstack\.com|transformers\.pyz|gh-token-monitor'

for histfile in \
  "${HOME_DIR}/.bash_history" \
  "${HOME_DIR}/.zsh_history" \
  "${HOME_DIR}/.local/share/fish/fish_history"; do
  [ -f "$histfile" ] || continue
  matches=$(grep -cE "$HISTORY_REGEX" "$histfile" 2>/dev/null) || true
  if [ "${matches:-0}" -gt 0 ]; then
    warning "Shell history contains ${matches} suspicious entries: $histfile"
    grep -nE "$HISTORY_REGEX" "$histfile" 2>/dev/null | head -5 | while IFS= read -r line; do
      echo -e "           ${DIM}${line}${RESET}"
    done
    found_shell=1
  fi
done

# Check shell RC files for injected content
for rcfile in \
  "${HOME_DIR}/.bashrc" \
  "${HOME_DIR}/.zshrc" \
  "${HOME_DIR}/.bash_profile" \
  "${HOME_DIR}/.zprofile" \
  "${HOME_DIR}/.profile"; do
  [ -f "$rcfile" ] || continue
  if grep -qE "$HISTORY_REGEX" "$rcfile" 2>/dev/null; then
    finding "Suspicious content in shell RC: $rcfile"
    found_shell=1
  fi
done

# Check for suspicious environment variables
for envvar in $(env 2>/dev/null | grep -oE '^[A-Z_]+=' | tr -d '='); do
  val="${!envvar:-}"
  if echo "$val" | grep -qE 'getsession\.org|masscan\.cloud|git-tanstack\.com' 2>/dev/null; then
    finding "C2 domain in env var: ${envvar}"
    found_shell=1
  fi
done

[ "$found_shell" -eq 0 ] && ok "No shell-level indicators found"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 8: Network indicators & npm tokens
# ═══════════════════════════════════════════════════════════════════════════
section "8/8  Network & token audit"

found_net=0

# Active connections to C2
if command -v lsof &>/dev/null; then
  c2_connections=$(lsof -i -n -P 2>/dev/null | grep -iE 'getsession|masscan\.cloud|git-tanstack' || true)
  if [ -n "$c2_connections" ]; then
    finding "ACTIVE connection(s) to C2 infrastructure:"
    echo "$c2_connections" | head -10 | while IFS= read -r line; do
      echo -e "           ${DIM}${line}${RESET}"
    done
    found_net=1
  fi
fi

# /etc/hosts
for domain in filev2.getsession.org seed1.getsession.org api.masscan.cloud git-tanstack.com; do
  if grep -q "$domain" /etc/hosts 2>/dev/null; then
    info "C2 domain in /etc/hosts: $domain (may be a block rule)"
  fi
done

# SSH known_hosts — check for C2 domains
if [ -f "${HOME_DIR}/.ssh/known_hosts" ]; then
  if grep -qE 'getsession\.org|masscan\.cloud|git-tanstack\.com' "${HOME_DIR}/.ssh/known_hosts" 2>/dev/null; then
    warning "C2 domain in ~/.ssh/known_hosts"
    found_net=1
  fi
fi

[ "$found_net" -eq 0 ] && ok "No active C2 connections detected"

# npm tokens
if command -v npm &>/dev/null; then
  npm_token_output=$(timeout 15 npm token list 2>&1) && {
    info "npm tokens (review for unrecognized entries):"
    echo "$npm_token_output" | sed 's/^/       /'
  } || {
    if echo "$npm_token_output" | grep -q "E401\|401 Unauthorized\|ENEEDAUTH"; then
      info "npm: not logged in — skipping token audit (run 'npm login' to enable)"
    else
      info "Could not list npm tokens (timed out or unavailable)"
    fi
  }
fi

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════
echo
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Scan Complete — $(date -u '+%Y-%m-%dT%H:%M:%SZ')${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════════${RESET}"

if [ "$FINDINGS" -gt 0 ]; then
  echo -e "${RED}${BOLD}  CRITICAL FINDINGS: ${FINDINGS}${RESET}"
  [ "$WARNINGS" -gt 0 ] && echo -e "  ${YELLOW}Warnings: ${WARNINGS}${RESET}"
  echo
  echo -e "  ${RED}Immediate actions required:${RESET}"
  echo "  1. Rotate ALL credentials reachable from this machine:"
  echo "     AWS keys, GitHub tokens (ghp_/gho_/ghs_), npm tokens,"
  echo "     Vault tokens, SSH keys, K8s service account tokens"
  echo "  2. Remove malicious packages:"
  echo "     npm cache clean --force && rm -rf node_modules && npm install"
  echo "  3. Remove persistence:"
  echo "     launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  echo "     rm ~/.local/bin/gh-token-monitor.sh"
  echo "  4. Block C2 at DNS: filev2.getsession.org, *.getsession.org,"
  echo "     api.masscan.cloud, git-tanstack.com"
  echo "  5. Audit GitHub Actions runs since 2026-05-11T19:20Z"
  echo "  6. Check for unauthorized npm publishes: npm access ls-packages"
elif [ "$WARNINGS" -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}  WARNINGS: ${WARNINGS}${RESET} (no confirmed compromise, review recommended)"
  echo
  echo "  Packages from affected scopes are installed. Verify versions"
  echo "  against: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"
else
  echo -e "${GREEN}${BOLD}  ALL CLEAR — no indicators of compromise found${RESET}"
  echo
  echo "  Checked: 170 npm packages (15 scopes) + 2 PyPI packages"
  echo "  Checked: file signatures, persistence (LaunchAgent/systemd/launchctl),"
  echo "  C2 indicators, node_modules, npm global, npm cache, lockfiles,"
  echo "  git repos (commits/branches/workflows), shell history, env vars,"
  echo "  Python requirements, SSH known_hosts, active connections, npm tokens"
fi

echo
echo "  CVE-2026-45321 | GHSA-g7cv-rxg3-hmpx | CVSS 9.6"
echo "  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"
echo

exit "$FINDINGS"
