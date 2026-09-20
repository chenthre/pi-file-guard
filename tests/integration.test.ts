/**
 * integration.test.ts — end-to-end flows over real files: slash-command
 * mutations, dynamic enforcement, and (when bwrap exists) real sandbox runs.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { test } from "node:test";
import { BWRAP_BIN } from "../bwrap.ts";
import { applyRule, formatSetMessage, GuardCommandError, guardCommand, removeRule } from "../commands.ts";
import { grepMayReachDeny, resolveFileToolMode } from "../enforce.ts";
import { AccessMode } from "../policy.ts";
import { runGuardedBash } from "../sandbox-process.ts";
import { runSandboxedFd } from "../search/find.ts";
import { resolveSearchToolBinary } from "../search/tool-path.ts";
import { GuardState, snapshotOf } from "../state.ts";

const haveBwrap = (() => {
	try {
		return spawnSync(BWRAP_BIN, ["--version"], { stdio: "ignore" }).status === 0;
	} catch {
		return false;
	}
})();

interface Env {
	ws: string;
	agentDir: string;
	state: GuardState;
	cleanup: () => void;
}

async function makeEnv(): Promise<Env> {
	const root = mkdtempSync(nodePath.join(tmpdir(), "guard-int-"));
	const ws = nodePath.join(root, "ws");
	mkdirSync(ws);
	const agentDir = nodePath.join(root, "agent");
	mkdirSync(agentDir);
	writeFileSync(nodePath.join(ws, ".env"), "TOKEN=abc123\n");
	writeFileSync(nodePath.join(ws, "prod.json"), "version: 1\n");
	writeFileSync(nodePath.join(ws, "src.ts"), "export const x = 1;\n");
	mkdirSync(nodePath.join(ws, "secrets"));
	writeFileSync(nodePath.join(ws, "secrets", "key.pem"), "PRIVATE\n");
	return {
		ws,
		agentDir,
		state: new GuardState(ws, agentDir),
		cleanup: () => rmSync(root, { recursive: true, force: true }),
	};
}

const deps = (env: Env) => ({
	state: () => env.state,
	reload: async () => env.state,
});

test("read tool: WRITE file allowed, DENY file blocked, READ file allowed", async () => {
	const env = await makeEnv();
	try {
		assert.equal((await resolveFileToolMode("src.ts", env.ws, env.state)).mode, AccessMode.Write);
		await env.state.setRule({
			path: nodePath.join(env.ws, ".env"),
			mode: AccessMode.Deny,
			logicalPath: ".env",
		});
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Deny);
		await env.state.setRule({
			path: nodePath.join(env.ws, "prod.json"),
			mode: AccessMode.Read,
		});
		assert.equal((await resolveFileToolMode("prod.json", env.ws, env.state)).mode, AccessMode.Read);
	} finally {
		env.cleanup();
	}
});

test("write/edit tool: DENY and READ both block, WRITE passes", async () => {
	const env = await makeEnv();
	try {
		await env.state.setRule({
			path: nodePath.join(env.ws, ".env"),
			mode: AccessMode.Deny,
		});
		await env.state.setRule({
			path: nodePath.join(env.ws, "prod.json"),
			mode: AccessMode.Read,
		});
		assert.notEqual((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Write);
		assert.notEqual((await resolveFileToolMode("prod.json", env.ws, env.state)).mode, AccessMode.Write);
		assert.equal((await resolveFileToolMode("src.ts", env.ws, env.state)).mode, AccessMode.Write);
		// Relative + .. inputs resolve the same
		assert.notEqual((await resolveFileToolMode("./sub/../.env", env.ws, env.state)).mode, AccessMode.Write);
	} finally {
		env.cleanup();
	}
});

test("grep: blocked when root is DENY or contains DENY descendants", async () => {
	const env = await makeEnv();
	try {
		await env.state.setRule({
			path: nodePath.join(env.ws, ".env"),
			mode: AccessMode.Deny,
		});
		assert.equal(await grepMayReachDeny(".", env.ws, env.state), true, "root has DENY descendant");
		assert.equal(await grepMayReachDeny("nonexistent-dir", env.ws, env.state), false);
		await env.state.setRule({
			path: nodePath.join(env.ws, "secrets"),
			mode: AccessMode.Deny,
			asDirectory: true,
		});
		assert.equal(await grepMayReachDeny("secrets", env.ws, env.state), true);
		// A subdir with no deny descendants is fine
		await mkdir(nodePath.join(env.ws, "clean"));
		await writeFile(nodePath.join(env.ws, "clean", "f.txt"), "x");
		assert.equal(await grepMayReachDeny("clean", env.ws, env.state), false);
	} finally {
		env.cleanup();
	}
});

test("slash commands: /hide + /unlock round trip with persistence and placeholders", async () => {
	const env = await makeEnv();
	try {
		// Hide an existing file
		const hideResult = await applyRule(deps(env), ".env", AccessMode.Deny);
		assert.match(hideResult.message, /DENY \.env/);
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Deny);
		// Lock
		const lockResult = await applyRule(deps(env), "prod.json", AccessMode.Read);
		assert.match(lockResult.message, /READ prod\.json/);
		assert.equal((await resolveFileToolMode("prod.json", env.ws, env.state)).mode, AccessMode.Read);
		// Show
		const show = await guardCommand(deps(env), "");
		assert.match(show.message, /DENY:/);
		assert.match(show.message, /\.env/);
		assert.match(show.message, /prod\.json/);
		// Persisted
		const persisted = await readFile(nodePath.join(env.agentDir, "file-guard.json"), "utf8");
		assert.ok(persisted.includes("deny"));
		assert.ok(persisted.includes("read"));
		// Unlock both
		await removeRule(deps(env), ".env");
		await removeRule(deps(env), "prod.json");
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Write);
		assert.equal((await resolveFileToolMode("prod.json", env.ws, env.state)).mode, AccessMode.Write);
	} finally {
		env.cleanup();
	}
});

test("slash commands: guard subcommands deny/read/reset/list", async () => {
	const env = await makeEnv();
	try {
		await guardCommand(deps(env), "deny .env");
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Deny);
		await guardCommand(deps(env), "read prod.json");
		assert.equal((await resolveFileToolMode("prod.json", env.ws, env.state)).mode, AccessMode.Read);
		await guardCommand(deps(env), "reset .env");
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Write);
		const list = await guardCommand(deps(env), "list");
		assert.match(list.message, /READ:/);
		await assert.rejects(guardCommand(deps(env), "bogus .env"), /Unknown \/guard subcommand/);
	} finally {
		env.cleanup();
	}
});

test("slash commands: reserved paths cannot be protected or unlocked", async () => {
	const env = await makeEnv();
	try {
		await assert.rejects(applyRule(deps(env), env.state.stateFile, AccessMode.Deny), /reserved/);
		const msg = formatSetMessage(AccessMode.Deny, "x", false);
		assert.match(msg, /DENY x/);
	} finally {
		env.cleanup();
	}
});

test("dynamic rules affect the next tool decision immediately (Gate 7 / AC10)", async () => {
	const env = await makeEnv();
	try {
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Write);
		await guardCommand(deps(env), "deny .env");
		assert.equal((await resolveFileToolMode(".env", env.ws, env.state)).mode, AccessMode.Deny);
	} finally {
		env.cleanup();
	}
});

test("symlink rule: /hide target blocks alias reads; /hide alias blocks target (Gate 5)", async () => {
	const env = await makeEnv();
	try {
		const target = nodePath.join(env.ws, "real-secret.txt");
		writeFileSync(target, "hidden\n");
		const alias = nodePath.join(env.ws, "alias.txt");
		symlinkSync(target, alias);

		// Hide the target; alias form must still resolve to DENY.
		await guardCommand(deps(env), "deny real-secret.txt");
		for (const input of ["real-secret.txt", "alias.txt"]) {
			const { mode, canonical } = await resolveFileToolMode(input, env.ws, env.state);
			assert.equal(mode, AccessMode.Deny, `${input} -> ${canonical}`);
		}

		// Reset, then hide the alias; the canonical target must be protected.
		await guardCommand(deps(env), "reset real-secret.txt");
		await guardCommand(deps(env), "deny alias.txt");
		const { mode, canonical } = await resolveFileToolMode("real-secret.txt", env.ws, env.state);
		assert.equal(canonical, target, "rule stored canonical target");
		assert.equal(mode, AccessMode.Deny);
	} finally {
		env.cleanup();
	}
});

test("spaces and unicode filenames round-trip through commands", async () => {
	const env = await makeEnv();
	try {
		const spaced = nodePath.join(env.ws, "my file.txt");
		writeFileSync(spaced, "s\n");
		const unicode = nodePath.join(env.ws, "秘密 파일.txt");
		writeFileSync(unicode, "u\n");
		await applyRule(deps(env), "./sub/../my file.txt", AccessMode.Deny);
		// Unicode path as single arg
		await applyRule(deps(env), "秘密 파일.txt", AccessMode.Deny);
		assert.equal((await resolveFileToolMode("my file.txt", env.ws, env.state)).mode, AccessMode.Deny);
		assert.equal((await resolveFileToolMode("秘密 파일.txt", env.ws, env.state)).mode, AccessMode.Deny);
	} finally {
		env.cleanup();
	}
});

test("find: DENY subtree is never traversed by the sandboxed fd backend", async (t) => {
	if (!haveBwrap) return t.skip("bubblewrap not installed");
	const env = await makeEnv();
	try {
		await guardCommand(deps(env), "deny secrets/");
		// Sandboxed fd with excludes disabled: bwrap is still the boundary.
		const fdBin = resolveSearchToolBinary("fd", env.agentDir);
		if (!fdBin) return t.skip("fd not installed");
		const out = await runSandboxedFd({
			pattern: "**",
			searchPath: env.ws,
			fdPath: fdBin,
			snapshot: snapshotOf(env.state),
			useExcludes: false,
			denyRules: env.state.rules,
		});
		assert.ok(!out.lines.some((l) => l.includes("key.pem")), "deny subtree not traversed");
		assert.ok(
			out.lines.some((l) => l.includes("src.ts")),
			"rest of repo still searchable",
		);
	} finally {
		env.cleanup();
	}
});

test("bwrap integration: full slash-command flow changes the NEXT bash invocation", async (t) => {
	if (!haveBwrap) return t.skip("bubblewrap not installed");
	const env = await makeEnv();
	try {
		const before = await runGuardedBash({
			command: "cat .env",
			cwd: env.ws,
			onData: () => {},
			snapshot: snapshotOf(env.state),
		});
		assert.equal(before.exitCode, 0);

		// /hide .env
		await guardCommand(deps(env), "deny .env");

		const collector = { chunks: [] as Buffer[] };
		const after = await runGuardedBash({
			command: "cat .env 2>&1; echo done",
			cwd: env.ws,
			onData: (c: Buffer) => collector.chunks.push(c),
			snapshot: snapshotOf(env.state),
		});
		assert.equal(after.exitCode, 0);
		const log = Buffer.concat(collector.chunks).toString("utf8");
		assert.match(log, /Permission denied/, "new namespace reflects the new rule");
		assert.ok(!log.includes("TOKEN=abc123"), "content not readable");

		// /unlock .env → next bash invocation can read again
		await guardCommand(deps(env), "reset .env");
		const c2 = { chunks: [] as Buffer[] };
		const afterReset = await runGuardedBash({
			command: "cat .env",
			cwd: env.ws,
			onData: (ch: Buffer) => c2.chunks.push(ch),
			snapshot: snapshotOf(env.state),
		});
		assert.equal(afterReset.exitCode, 0);
		assert.ok(Buffer.concat(c2.chunks).toString("utf8").includes("TOKEN=abc123"));
	} finally {
		env.cleanup();
	}
});

test("state self-protection holds across a full session bootstrap", async () => {
	const env = await makeEnv();
	try {
		// Simulated pre-session rule (persisted before session start)
		await env.state.setRule({
			path: nodePath.join(env.ws, "prod.json"),
			mode: AccessMode.Read,
		});

		// Boot a fresh state from disk (as session_start does)
		const fresh = new GuardState(env.ws, env.agentDir);
		const { loadState } = await import("../state.ts");
		const persisted = await loadState(env.agentDir);
		const project = persisted.projects[env.ws];
		fresh.replaceRules(
			project.rules.map((r) => ({
				path: r.path,
				mode: r.mode === "deny" ? AccessMode.Deny : AccessMode.Read,
				logicalPath: r.logicalPath,
			})),
		);
		assert.equal(fresh.rules.length, 1);
		assert.equal((await resolveFileToolMode("prod.json", env.ws, fresh)).mode, AccessMode.Read);
		// Reserved still enforced on the fresh state
		assert.equal((await resolveFileToolMode(fresh.stateFile, fresh.workspace, fresh)).mode, AccessMode.Deny);
	} finally {
		env.cleanup();
	}
});

test("fuzz: random .. patterns cannot escape an ancestor deny rule", async () => {
	const env = await makeEnv();
	try {
		await guardCommand(deps(env), "deny secrets/");
		const seeds = [
			"secrets",
			"./secrets",
			"sub/../secrets",
			"secrets/",
			"secrets/../secrets/key.pem",
			"sub/../secrets/./key.pem",
		];
		for (const seed of seeds) {
			const { mode } = await resolveFileToolMode(seed, env.ws, env.state);
			assert.equal(mode, AccessMode.Deny, `seed "${seed}"`);
		}
		// Sanity: a pattern that genuinely escapes the workspace targets a
		// DIFFERENT (unprotected) path — normalization-then-check semantics.
		const { mode, logical } = await resolveFileToolMode("sub/../../secrets", env.ws, env.state);
		assert.notEqual(logical, nodePath.join(env.ws, "secrets"));
		assert.notEqual(mode, AccessMode.Deny);
	} finally {
		env.cleanup();
	}
});

test("GuardCommandError carries notFound meta for missing rules", async () => {
	const env = await makeEnv();
	try {
		await assert.rejects(removeRule(deps(env), "never-protected.txt"), (err: unknown) => {
			assert.ok(err instanceof GuardCommandError);
			assert.equal(err.meta.notFound, true);
			return true;
		});
	} finally {
		env.cleanup();
	}
});
