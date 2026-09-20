# Architecture

This document explains *why* Pi File Guard is built the way it is, for
maintainers and reviewers. For usage, semantics and the user-facing threat
model, see the [README](../README.md). For API/behavior guarantees, see the
tests — especially `tests/search-security.test.ts`.

Pi File Guard was implemented in two passes:

- **v1** established the three-state policy and the Bubblewrap enforcement for
  `bash` and in-process file tools.
- **v2** replaced a custom Node search walker with sandboxed native tools
  (`fd`, `rg`) and unified every subprocess behind one filesystem compiler.

The historical task specs (guide.md, guide_v2.md) are deliberately **not**
part of the repository — this document is the distilled, maintained form of
their design decisions.

## 1. Mission and boundary

The extension lets the **user** (the control plane) temporarily revoke the
agent's read or write capability for chosen files/directories, in-session and
across sessions:

```text
WRITE   readable + writable          default inside the workspace
READ    readable + not writable      /lock
DENY    not readable + not writable  /hide   (pathname may stay visible)
```

Constraints that shape everything else:

- The security boundary must be **OS/kernel level** for agent processes
  (mount namespaces + dropped capabilities). Shell-command parsing, prompt
  instructions, model compliance and `path.startsWith` comparisons are never a
  security boundary.
- **Pi itself is trusted.** Extensions run with Pi's host privileges; the
  guard only constrains agent tool calls and the process trees those calls
  spawn.
- **The agent cannot change policy.** Only user slash commands (`/hide`,
  `/lock`, `/unhide`, `/unlock`, `/guard`) mutate `GuardState`. No
  model-callable tool can grant, remove or weaken a protection, and sandbox
  failure never degrades to an unsandboxed run.

## 2. Permission model

A single policy engine (`policy.ts`) evaluates every path to exactly one of:

```text
reserved DENY  >  user DENY  >  user READ  >  baseline (WRITE in workspace, READ elsewhere)
```

- Rules store the **canonical (realpath-resolved) path** plus the normalized
  logical path; evaluation matches against both so symlink aliases cannot
  bypass a rule in either direction (`/hide link` protects its target,
  `/hide target` is not reachable through an alias).
- **Deny/read ancestors dominate descendants** (no "reopen child" rules).
- Hard-coded **reserved deny paths** (`~/.pi/agent/file-guard.json`, the
  runtime mask dir, and the extension's own sources when in an auto-discovery
  location) are merged into every evaluation and every sandbox build; they
  cannot be removed via the commands.

Baseline (Codex style): the whole filesystem is READ, the workspace is WRITE.
READ overlays are mounted *after* the workspace bind (order matters: a later
RW bind would cover them), then DENY overlays last, then `--cap-drop ALL`.

## 3. Two enforcement paths, one policy

```text
                    GuardState
                        │  snapshotOf(state) per invocation
        ┌───────────────┴───────────────┐
        ▼                               ▼
  In-process tools               Native subprocesses
  read / write / edit / ls      bash / fd / rg
        │                               │
        ▼                               ▼
  resolveFileToolMode()         compileSandboxArgs(snapshot)
  (pre-execution policy)        (the single bwrap compiler)
```

- **In-process tools** are checked **before** execution against the canonical
  target. No post-execution content filtering ever happens — if a path was
  openable, the boundary was already crossed.
- **Every subprocess** — shell commands, `fd`, `rg` — starts inside a fresh
  Bubblewrap namespace assembled by the *same* compiler, so all of them
  observe the identical filesystem view (`_e.g._ a DENY file is an
  unreadable 000-mode mount for `cat`, `python`, `node` **and** `rg` alike).

### DENY rendering

- **File** → a synthetic 000-mode mask file is read-only bound over the
  target (a plain `/dev/null` bind is rejected: empty reads would be success,
  not denial). Open is `EACCES`; unlink/rename-over fail on the busy/RO
  mount.
- **Directory** → empty tmpfs with mode 000 over the target: the name remains
  visible in the parent, but `open`/`list`/`write`/`rename` of the dir or its
  contents all fail.
- Missing targets that must be masked are materialized as empty 000/444
  placeholders (recorded as `created` and removed on `/unlock` while empty).
  **Reserved paths are never touched on the host** — the guard's own state
  file must stay readable/writable by the extension.

## 4. Sandboxed subprocess execution

`sandbox-process.ts` is the single spawn primitive: it compiles bwrap
arguments from the snapshot, spawns `bwrap` (PID 1 of its own namespace),
exposes stdout/stderr plus `kill()` (namespace teardown), and enforces
timeouts/abort by killing the namespace — no orphaned descendant process is
possible.

`runGuardedBash` and both search adapters are thin, argv-specific wrappers
around this primitive. They never construct their own filesystem policy.

## 5. Search: native tools inside the sandbox

v1 implemented `find` with a custom Node recursive walker. v2 removed it.

- `find` runs **`fd`**, `grep` runs **ripgrep**, both as subprocesses *inside*
  the same bwrap view as `bash`. Node only parses their output (`fd` lines,
  `rg --json` events).
- `.gitignore`, git-aware ignore semantics, glob, hidden-file handling,
  symlink behavior and result limits all come from the native tools —
  matching Pi's built-in search exactly (the adapter mirrors Pi's argument
  construction). There is no second filesystem semantics to drift.
- Grep **context lines are rendered from `rg -C` JSON events**, not from a
  host re-read — reopening a file after a sandboxed search would be a second,
  uncontrolled access path.
- `fd --exclude` / `rg --glob '!…'` arguments derived from DENY rules under
  the search root are **an optimization only** (less permission noise, faster
  traversal). Security is the filesystem view; the security tests run with
  excludes disabled to prove DENY is still enforced.
- A search whose **root is itself DENY** is an explicit denial — never a
  misleading "No matches".
- **Conservative fallback** (no bubblewrap, or missing native binary): only a
  tree provably free of DENY paths may run against Pi's original host tools.
  An unsandboxed search that could reach DENY content is refused outright,
  never filtered.
- rg stderr classification tolerates *expected* permission noise from
  unreadable DENY subtrees, but any line that smells like a sandbox
  construction failure (`bwrap:`, mount errors) fails the invocation closed —
  exit-code quirks must never swallow a sandbox failure.

## 6. Lifecycle, state and dynamic rules

- Rules live in `GuardState` in Pi's memory and are persisted atomically
  (temp file + fsync + rename) to `~/.pi/agent/file-guard.json`, keyed by
  canonical workspace.
- Every enforcement action takes a **snapshot** of the state at invocation
  time. Rules changed mid-session therefore apply to the next tool call and
  the next new subprocess; already-running processes keep their launch
  capabilities (documented).
- `session_start` loads persisted rules and probes bwrap; `session_shutdown`
  drops the in-memory state.

## 7. Fail-closed contract

The following situations refuse the operation (often with a policy error) and
**never** fall back to weaker behavior:

- bubblewrap missing / user namespaces unavailable;
- workspace unusable, policy cannot be canonicalized, or a mask cannot be
  built;
- a sandboxed search cannot be constructed and the tree is not provably
  DENY-free;
- a plausible sandbox-construction failure appears on a search's stderr;
- the guard state cannot be loaded (user rules disabled, reserved
  protections stay active).

## 8. Non-goals (out of scope)

Network sandboxing, domain allowlists, env-var masking, command
classification, `sudo`/`rm` detection, approval workflows, seccomp,
resource limits, secret redaction, hard-link alias discovery, pathname
secrecy, and isolation of the Pi process itself (see README's security model
for the containerization guidance).

## Code map

```text
index.ts              Pi wiring: tool registrations, tool_call guard, commands
policy.ts             three-state model, precedence, ancestor matching
paths.ts              normalization, canonicalization, symlink forms
state.ts              GuardState, PermissionSnapshot, persistence, placeholders
enforce.ts            shared in-process tool decision logic
bwrap.ts              the single filesystem compiler (mount layering + probe)
sandbox-process.ts    the single subprocess primitive (spawn/kill/timeout)
commands.ts           slash commands / UX messages
search/excludes.ts    exclude optimization (never the boundary)
search/fallback.ts    conservative fallback decisions (DENY-free only)
search/find.ts        fd adapter (args + output formatting)
search/grep.ts        rg adapter (args + --json parsing + stderr classification)
search/tool-path.ts   fd/rg binary resolution (~/.pi/agent/bin then PATH)
tests/                see README → Development for the suite layout
```