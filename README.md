# Pi File Guard

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/pi-file-guard/pi-file-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/pi-file-guard/pi-file-guard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/pi-file-guard?color=cb3837&label=npm)](https://www.npmjs.com/package/pi-file-guard)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933)](https://nodejs.org)
[![Pi](https://img.shields.io/badge/pi-0.85%2B-8b5cf6)](https://github.com/earendil-works/pi-mono)

A lightweight, user-controlled **filesystem policy** for the [Pi coding
agent](https://github.com/earendil-works/pi-mono) on Linux. Protect secrets and
configurations from the agent with three states — **DENY / READ / WRITE** —
enforced on Pi's file tools and on **every** `bash`, `find` and `grep`
subprocess through one shared [Bubblewrap](https://github.com/containers/bubblewrap)
mount namespace.

```text
WRITE   readable + writable          default inside your project
READ    readable, not modifiable     /lock   (user semantics: lock)
DENY    not readable + not writable  /hide   (user semantics: hide)
         (pathname may still be visible)
```

```text
.env                 DENY     the agent cannot read or touch it
production.json      READ     the agent can read it, never modify it
src/**               WRITE    the agent works normally
```

**Security is kernel-level, not prompt-level.** Restrictions come from
filesystem mounts (with all capabilities dropped), so `cat`, `python`, `node`,
`cp`, `dd`, `sed`, nested shells and native `fd`/`rg` search all fail with
`EACCES`/`EROFS` — there is no command-string parsing and no post-hoc result
filtering anywhere.

> ⚠️ Read the [Security model](#security-model--read-this) — this is a file
> policy, not a full sandbox for the Pi process itself.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Semantics](#semantics)
- [Architecture](#architecture)
  - [bash enforcement](#bash-enforcement-no-command-parsing-ever)
  - [Search isolation (fd & rg)](#search-isolation-fd--rg)
  - [File tool enforcement](#file-tool-enforcement)
  - [Self-protection](#self-protection)
- [Security model — read this](#security-model--read-this)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing · Security · Changelog](#contributing--security--changelog)
- [License](#license)

---

## Requirements

- **Linux** with unprivileged **user namespaces** enabled
- **[bubblewrap](https://github.com/containers/bubblewrap)** (`apt install bubblewrap`)
- **Pi 0.85+**
- `fd` / `rg` — optional but recommended for sandboxed search (see
  [Search isolation](#search-isolation-fd--rg))

If bubblewrap or user namespaces are unavailable, Pi File Guard **fails
closed**: `bash` refuses to run — it never silently falls back to an
unsandboxed shell — and search falls back to a conservative mode limited to
DENY-free trees. File-tool policy enforcement keeps working in all cases.

## Installation

### As a pi package (recommended)

```bash
pi install git:github.com/pi-file-guard/pi-file-guard@v1.0.0
```

or from npm once published:

```bash
pi install npm:pi-file-guard
```

### As a plain extension

Copy the `pi-file-guard/` directory into an auto-discovered location and
restart pi:

```text
~/.pi/agent/extensions/pi-file-guard/      # global (all projects)
<project>/.pi/extensions/pi-file-guard/    # project-local
```

or run ad-hoc:

```bash
pi -e ./pi-file-guard
```

No runtime `npm install` is required — the extension imports only pi's own
bundled packages plus Node built-ins.

Rules persist across sessions in `~/.pi/agent/file-guard.json`, keyed by
canonical workspace path.

## Quick start

```text
/hide .env
DENY .env
Future agent tools and new shell processes cannot read or modify this path.
```

From this moment every new tool call and every new shell process is built from
a fresh policy snapshot — the `.env` content is unreachable via `read`, `bash`,
`grep`, `find` and `ls`, while the rest of the repository stays fully usable.

```text
/guard
```

prints the whole picture: workspace, DENY list, READ list, and the hard-coded
reserved deny paths.

## Usage

```text
/hide PATH          DENY — agent may see the name but cannot read, write,
                    edit, delete, rename-over or truncate it.
                    Trailing '/' protects a directory:  /hide secrets/
/lock PATH          READ — agent may read it but cannot modify, delete or
                    rename-over it.
/unhide PATH        remove a DENY override
/unlock PATH        remove a READ override
/guard              show the current workspace policy
/guard deny PATH    unified alias of /hide
/guard read PATH    unified alias of /lock
/guard reset PATH   unified alias of /unlock
/guard list         same as /guard
```

Paths may be relative, absolute, `~`, contain `..` and spaces; symlinks are
resolved so aliases cannot bypass a rule. Rules take effect **immediately**
for the next tool call and the next new `bash`/`fd`/`rg` invocation.

Only **you** can change policy. No model-callable tool exists that can grant,
remove or weaken protections.

### Semantics

| Operation | WRITE | READ | DENY |
| --- | --- | --- | --- |
| `read` tool / bash read (`cat`, `python`, `node`, `cp`, `dd`, …) | ✓ | ✓ | ✗ (EACCES) |
| `write` / `edit` tools | ✓ | ✗ | ✗ |
| bash write / append / truncate | ✓ | ✗ | ✗ |
| delete / rename-over | ✓ | ✗ (busy / RO mount) | ✗ |
| `ls parent` (entry name) | ✓ | ✓ | ✓ (name visible) |
| `ls DENYDIR` / recursive read of a DENY dir | — | — | ✗ |
| `grep` / `find` over a tree containing DENY paths | ✓ | ✓ | subtree inaccessible, rest searchable |
| `grep` / `find` with the **root** itself DENY | — | — | ✗ (explicit denial) |

DENY is **not** secrecy: pathnames can be observed in parent listings. It is
an **access failure**: any open/read/write/unlink attempt on the content fails
at the OS level inside the sandbox and at the policy level for host tools.
DENY ancestors dominate descendants (there is no "reopen child" rule),
mirroring a stricter-than-baseline overlay model.

## Architecture

```text
                     User
                      │
          /hide /lock /unlock /guard
                      ▼
              ┌──────────────┐        persistent policy
              │  GuardState  │──────► ~/.pi/agent/file-guard.json
              │ trusted RAM  │        (atomic tmp+fsync+rename)
              └──────┬───────┘
                     │   PermissionSnapshot (per invocation)
          ┌──────────┴───────────┐
          ▼                      ▼
 Pi file tools               bash / fd / rg
 (tool_call pre-check)      (sandboxed subprocesses)
          │                      │
          ▼                      ▼
     PolicyEngine           compileSandboxArgs(snapshot)
     (async realpath)           │
          │                 bubblewrap mount ns
          │                 /  RO → workspace RW →
          ▼                 READ overlays → DENY masks → cap-drop ALL
   Node filesystem          shell + process tree
```

Layers (`policy.ts`, `paths.ts`, `state.ts`, `bwrap.ts`, `sandbox-process.ts`,
`commands.ts`, `search/*`) are kept strictly separate: policy logic, mount
compilation, process execution, tool adapters and Pi integration never mix.
`enforce.ts` holds the shared file-tool decision logic used by both the Pi
hook and the tests.

### bash enforcement (no command parsing, ever)

Every agent bash command runs as:

```text
bwrap --die-with-parent --new-session --unshare-user --unshare-pid
      --ro-bind / /          # 1. whole filesystem READ (baseline)
      --dev /dev --proc /proc
      --tmpfs /tmp           # scratch
      --bind WORKSPACE WORKSPACE   # 2. workspace WRITE
      --ro-bind LOCKED LOCKED      # 3. READ overlays (after the workspace bind —
                                   #    order matters: a later RW bind would
                                   #    cover the protection)
      --perms 000 --tmpfs DENYDIR  # 4. DENY dirs (name visible, open/list fails)
      --ro-bind MASK DENYFILE      #    DENY files (000-mode synthetic mask;
                                   #    /dev/null is NOT used: empty reads are
                                   #    not access failure)
      --cap-drop ALL
      -- /bin/bash -c COMMAND
```

Each invocation builds a **fresh** namespace from the current policy snapshot,
so `/hide` during a session applies instantly to the next command. Killing the
bwrap process tears down the whole tree (it is PID 1 of its own namespace).

### Search isolation (fd & rg)

Pi File Guard does **not** implement its own file search engine, and it never
post-filters host search results.

```text
find → fd   ─┐
             ├─→ the SAME bwrap filesystem view used for bash
             │    (identical mounts, identical protection)
grep → rg   ─┘
```

- `find` uses **`fd`**, `grep` uses **ripgrep** — spawned **inside** the
  identical Bubblewrap filesystem view as agent shell commands. Node only
  parses output (fd's lines, rg's `--json` events); traversal, `.gitignore`,
  git-aware ignore behavior, glob and hidden-file semantics all come from the
  native tools, exactly matching Pi's built-in search.
- There is no second, parallel filesystem policy: `GuardState →
  compileSandboxArgs(snapshot)` is the single security backend for bash, fd
  and rg.
- Grep context lines come from **`rg -C` JSON context events** — the built-in
  grep's host-side second `readFile()` for context lines is deliberately not
  reused, so no host path is ever reopened after a sandboxed search.
- **fd/rg exclusion rules are an optimization, not a security boundary.** DENY
  paths inside a search root become `--exclude` / `--glob '!…'` arguments to
  reduce permission-error noise and traversal cost. Real protection is the
  bwrap filesystem view; the test suite runs with excludes disabled to prove
  DENY stays enforced.
- Searching a **DENY root** is an explicit denial (`Access denied by Pi File
  Guard … Policy: DENY`), never a misleading "No matches".
- With the sandbox healthy, `grep .` / `find … .` keep working on the whole
  repository while DENY subtrees exist — those subtrees are simply
  inaccessible.
- **Conservative fallback:** only when the sandboxed backend cannot
  initialize (no bubblewrap, or `fd`/`rg` binary missing) does search fall
  back to Pi's original host tools — and only when the tree is provably
  DENY-free. An unsandboxed search that could touch DENY content is refused
  outright, never filtered.
- Timeout/abort: fd/rg inherit the same `AbortSignal` + kill-the-namespace
  cleanup as bash; a 300 s fail-safe caps runaway searches so no orphaned
  native search process is left behind.

DENY does **not** guarantee filename secrecy: a native `fd`/`rg` run may or
may not reveal a DENY pathname depending on exclude optimization — that is by
design (v2 §3).

### File tool enforcement

| Tool | Enforcement |
| --- | --- |
| `read` | blocked when the resolved path is DENY |
| `write` / `edit` | blocked unless the resolved path is WRITE |
| `grep` | sandboxed `rg`; DENY search root blocked up front |
| `find` | sandboxed `fd`; DENY search root blocked up front |
| `ls` | `readdir` of a DENY path fails; parent listings show the name |

All checks are **pre-execution** on the canonical (realpath-resolved) target —
never post-execution content filtering.

### Self-protection

The following are hard-coded reserved DENY paths, merged into every policy
evaluation and every bwrap build, and cannot be removed with `/unlock`:

```text
~/.pi/agent/file-guard.json           # persisted policy
~/.pi/agent/file-guard/               # runtime dir (synthetic deny masks)
<extension dir>/                      # extension sources (when installed in
                                      # ~/.pi/agent/extensions or .pi/extensions)
```

The agent can observe that these paths exist; it cannot read or write them.
The guard's own host code updates the state file through atomic writes.

## Security model — read this

> Pi File Guard protects configured filesystem paths from **supported Pi file
> tools** and **bubblewrap-sandboxed bash subprocesses**.
>
> It does **not** sandbox the Pi process itself. Pi extensions execute with
> Pi's host privileges and are trusted — as is pi, your account, and you.

**In scope:** agent tool calls and the full process tree spawned by agent
bash commands (`bash -c`, `sh`, `python`, `node`, `npm` scripts, …). For
authentic OS-level isolation of the whole Pi process, follow Pi's own
[containerization guidance](https://github.com/earendil-works/pi-mono/blob/main/docs/containerization.md).

**Out of scope / not guaranteed:**

- **DENY does not guarantee pathname secrecy** — names may stay visible in
  listings and searches.
- Content already read into the model's context before a rule was set cannot
  be erased.
- Processes already running keep the capabilities from their launch snapshot;
  new rules bind only new invocations.
- **Hard links** are the same inode under another name — v1 does not scan the
  filesystem for every hard-link alias of a protected path.
- Same-user processes outside Pi, malicious extensions, a compromised pi host,
  and kernel exploits are outside the boundary.

**Behavioral notes:**

- The user's own `!` shell commands are **not** sandboxed — the user is the
  control plane and keeps full access, including to hidden paths.
- Outside the workspace the filesystem is **read-only** in the agent's
  sandbox, including `$HOME`; `/tmp` is a writable tmpfs scratch. Tooling that
  insists on a home cache (`npm` without a configured cache) may hit EROFS —
  use the workspace or `/tmp`.
- `powershell` (Windows-oriented) is not enforced; it is not part of the
  default Linux toolset.
- Dangling-symlink targets as protection paths fail closed with a clear error
  rather than being guessed at.

## Known limitations

- No glob-based user rules; no child-override under a DENY ancestor.
- `find`/`grep` need the native `fd`/`rg` binaries (Pi usually keeps them in
  `~/.pi/agent/bin`, or use system `fd`/`fdfind`/`rg`). When missing, search
  uses the conservative path (DENY-free trees only) or fails closed.
- Protecting a path whose **parent does not exist yet** materializes an empty
  `000`-mode placeholder on the host so the name is sealed; `/unlock` removes
  it again while still empty. Existing paths — the common case — never create
  placeholders.
- `/hide` of an ancestor of the workspace (e.g. your whole `$HOME`) makes the
  sandboxed cwd unreachable and the invocation fails closed — by design.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "bubblewrap is not available … bash is DISABLED" | `apt install bubblewrap`, enable unprivileged user namespaces, restart pi |
| tool error `Access denied by Pi File Guard: … Policy: DENY` | `/guard` to review; `/unlock PATH` to release |
| `cat: …: Permission denied` inside bash | that path is DENY (000 mask) or READ (RO mount) |
| `Read-only file system` outside the workspace | baseline RO filesystem — expected; use the workspace or `/tmp` |
| `find`/`grep` fall back to conservative mode | `fd`/`rg` missing or bubblewrap unavailable — install them |

## Development

```bash
npm install          # dev deps: typescript, tsx, @types/node, biome
npm run verify       # biome check + tsc --noEmit + full test suite
npm test             # runs every suite; real-bwrap tests skip if tools are missing
```

Test layout: policy/path/state unit tests; bwrap compiler + bash sandbox
integration (real Bubblewrap); `fd`/`rg` adapter unit and live-bwrap
integration; search security regression with excludes **both enabled and
disabled**; synthetic performance comparisons (1k / 15k / ignore-heavy trees,
native vs sandboxed); end-to-end slash-command flows. Developing on a machine
without every piece of tooling is fine — the native suites skip gracefully.

Live smoke tests against the real harness (`pi -e ./index.ts`): loading,
no-rule operation, pre-seeded persistent DENY rules enforced on both the
`read` tool and bash (`cat`, `node`, `echo >`), sandboxed `grep`/`find`, and
normal-file READ/WRITE remaining unaffected while a rule is active.

## Contributing · Security · Changelog

- [Contributing](./CONTRIBUTING.md) — design principles, setup, review checklist.
- [Security](./SECURITY.md) — private reporting and the supported threat model.
- [Changelog](./CHANGELOG.md) — Keep a Changelog format.

## License

MIT — see [LICENSE](./LICENSE).