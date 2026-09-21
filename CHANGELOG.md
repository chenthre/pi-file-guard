# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-09-20

Initial public release. The v2 search architecture is included from day one.

### Security model

- Three-state filesystem policy: `DENY` (hide), `READ` (lock), `WRITE` (default inside the workspace).
- Single filesystem security backend: `GuardState → compileSandboxArgs(snapshot)` drives **bash**, **fd** and **rg** through the same Bubblewrap mount namespace.
- Fail closed: bwrap/compiler errors never fall back to unsandboxed execution; search tool failures are never swallowed via stderr classification.
- Hard-coded reserved deny paths protect the persistent policy file, the runtime mask directory and the extension's own sources.
- Host-side file tools (`read`/`write`/`edit`/`ls`) are enforced pre-execution through the shared policy engine; `grep`/`find` require the native `ripgrep`/`fd` binaries inside the sandbox view.

### Features

- Slash commands: `/hide`, `/lock`, `/unhide`, `/unlock`, `/guard` (including `/guard deny|read|reset PATH` and `/guard list`).
- Persistent, project-keyed rules in `~/.pi/agent/file-guard.json` via atomic writes.
- Symlink-aware canonical path handling; placeholder sealing for not-yet-existing protected targets.
- Dynamic rules: every tool call and every new bash/fd/rg invocation snapshots the current policy.
- Seeded as a [pi package](https://pi.dev/packages) (`pi install` via npm or git), with runtime deps as `peerDependencies`.

### Known limitations

- No glob-based user rules, no child-override under a DENY ancestor.
- DENY does not guarantee pathname secrecy; hard-link aliases are not auto-discovered.
- Requires Linux + Bubblewrap; filesystem outside the workspace is read-only for agent processes (`/tmp` is a writable tmpfs scratch).

[Unreleased]: https://github.com/chenthre/pi-file-guard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chenthre/pi-file-guard/releases/tag/v1.0.0