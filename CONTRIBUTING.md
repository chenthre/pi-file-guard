# Contributing

Thanks for taking the time to contribute! This project is a security-sensitive
extension for the Pi coding agent, so we ask contributors to keep a few
principles in mind.

## Design principles

1. **The security boundary is the Bubblewrap filesystem view**, not command
   parsing, prompt instructions, or post-hoc result filtering. Keep it that way.
2. **One policy, one compiler.** Never add a second filesystem policy
   implementation next to `GuardState → compileSandboxArgs`.
3. **Fail closed.** When in doubt about a path or a sandbox error, refuse the
   operation with a clear message — never run unsandboxed, never filter after
   the fact.
4. **Permissions are user-controlled.** Never register model-callable tools
   that grant, remove or weaken protections.

## Development setup

```bash
git clone <repo-url>
cd pi-file-guard
npm install      # dev deps: typescript, tsx, @types/node, biome
npm run verify   # biome check + tsc --noEmit + full test suite
```

The test suite runs real Bubblewrap sandboxes (skip gracefully when bwrap or
`fd`/`rg` are unavailable). `fd`/`rg` come from your system or from Pi's own
tools directory at `~/.pi/agent/bin`.

To smoke-test against the real harness:

```bash
pi -e ./index.ts
```

## Before submitting

- `npm run verify` passes.
- New behavior ships with tests: unit tests for policy/paths/state, live-bwrap
  integration for enforcement, and — for anything touching search — the
  security suite runs with excludes **both** enabled and disabled.
- No `any`/`@ts-ignore`, strict TypeScript only, formatted by Biome.
- CHANGELOG entry added under [Unreleased].

## Security issues

See [SECURITY.md](./SECURITY.md). Do not open a public issue for
security-sensitive bugs.