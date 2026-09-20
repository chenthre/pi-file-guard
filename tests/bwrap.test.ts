/**
 * bwrap.test.ts — argv construction and mount ordering (Gate 4) + real bwrap
 * integration when bubblewrap is available (AC4/AC5/AC6/AC7/AC8/AC9).
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { access, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { test } from "node:test";
import { BWRAP_BIN, BwrapError, compileBwrapArgs } from "../bwrap.ts";
import { AccessMode } from "../policy.ts";
import { runGuardedBash } from "../sandbox-process.ts";
import { GuardState, snapshotOf } from "../state.ts";

const haveBwrap = (() => {
	try {
		return spawnSync(BWRAP_BIN, ["--version"], { stdio: "ignore" }).status === 0;
	} catch {
		return false;
	}
})();

function makeWs(): { dir: string; ws: string; cleanup: () => void } {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-bwrap-"));
	const ws = nodePath.join(dir, "ws");
	mkdirSync(ws);
	return {
		dir,
		ws,
		cleanup: () => rmSync(dir, { recursive: true, force: true }),
	};
}

function makeCollector(): { onData: (c: Buffer) => void; get: () => string } {
	const chunks: Buffer[] = [];
	return {
		onData: (c) => chunks.push(c),
		get: () => Buffer.concat(chunks).toString("utf8"),
	};
}

async function makeState(ws: string): Promise<{ state: GuardState; agentDir: string; cleanup: () => void }> {
	const agentDir = mkdtempSync(nodePath.join(tmpdir(), "guard-ag-"));
	const state = new GuardState(ws, agentDir);
	return {
		state,
		agentDir,
		cleanup: () => rmSync(agentDir, { recursive: true, force: true }),
	};
}

// ---------------------------------------------------------------------------
// Compiler unit tests (no bwrap required)
// ---------------------------------------------------------------------------

test("compileBwrapArgs: baseline layers in the security-critical order", async () => {
	const { dir, ws, cleanup } = makeWs();
	try {
		const reservedState = nodePath.join(dir, "agent", "file-guard.json");
		mkdirSync(nodePath.dirname(reservedState), { recursive: true });
		writeFileSync(reservedState, "{}");
		const prod = nodePath.join(ws, "prod.json");
		const env = nodePath.join(ws, ".env");
		const secrets = nodePath.join(ws, "secrets");
		writeFileSync(prod, "{}");
		writeFileSync(env, "x");
		mkdirSync(secrets);
		const compiled = await compileBwrapArgs({
			workspace: ws,
			rules: [
				{ path: prod, mode: AccessMode.Read },
				{ path: env, mode: AccessMode.Deny },
				{ path: secrets, mode: AccessMode.Deny },
			],
			reserved: [{ path: reservedState, mode: AccessMode.Deny }],
			runtimeDir: nodePath.join(dir, "runtime"),
		});
		const a = compiled.sandboxArgs;

		const roIdx = a.indexOf("--ro-bind");
		assert.ok(roIdx >= 0);
		const devIdx = a.indexOf("--dev");
		const procIdx = a.indexOf("--proc");
		const wsBindIdx = a.indexOf("--bind");
		assert.ok(devIdx < procIdx && procIdx < wsBindIdx, "dev/proc before workspace bind");
		// READ overlay after workspace bind
		const readIdx = a.indexOf("--ro-bind", wsBindIdx);
		assert.ok(readIdx > wsBindIdx, "READ overlay after workspace bind");
		// DENY overlay after READ overlay
		const permsIdx = a.indexOf("--perms");
		assert.ok(permsIdx > readIdx, "DENY overlay after READ overlay");
		// use namespaces and drop caps
		assert.ok(a.includes("--unshare-user"));
		assert.ok(a.includes("--unshare-pid"));
		assert.ok(a.includes("--die-with-parent"));
		assert.ok(a.includes("--new-session"));
		const capIdx = a.indexOf("--cap-drop");
		assert.equal(a[capIdx + 1], "ALL");
	} finally {
		cleanup();
	}
});

test("compileBwrapArgs: DENY dir -> tmpfs 000; DENY file -> 000 mask bind", async () => {
	const { ws, cleanup } = makeWs();
	try {
		mkdirSync(nodePath.join(ws, "secrets"));
		writeFileSync(nodePath.join(ws, ".env"), "x");
		const runtimeDir = nodePath.join(ws, "..", "runtime");
		const compiled = await compileBwrapArgs({
			workspace: ws,
			rules: [
				{ path: nodePath.join(ws, "secrets"), mode: AccessMode.Deny },
				{ path: nodePath.join(ws, ".env"), mode: AccessMode.Deny },
			],
			reserved: [],
			runtimeDir,
		});
		const a = compiled.sandboxArgs;
		const permsIdx = a.indexOf("--perms");
		assert.equal(a[permsIdx + 1], "000");
		assert.equal(a[permsIdx + 2], "--tmpfs");
		assert.equal(a[permsIdx + 3], nodePath.join(ws, "secrets"));
		const maskIdx = a.indexOf("--ro-bind", a.indexOf("--bind"));
		const maskSrc = a[maskIdx + 1];
		assert.ok(maskSrc.includes("deny-"), "mask file under runtime dir");
		assert.equal(a[maskIdx + 2], nodePath.join(ws, ".env"));
		assert.equal(existsSync(maskSrc), true, "mask file materialized");
		assert.equal(statSync(maskSrc).mode & 0o777, 0o000, "mask file is 000");
	} finally {
		cleanup();
	}
});

test("compileBwrapArgs: workspace root refused (fail closed)", async () => {
	await assert.rejects(
		compileBwrapArgs({
			workspace: "/",
			rules: [],
			reserved: [],
			runtimeDir: "/tmp/xx",
		}),
		BwrapError,
	);
});

test("compileBwrapArgs: missing DENY target materializes placeholder and masks it", async () => {
	const { ws, cleanup } = makeWs();
	try {
		const target = nodePath.join(ws, "future", "secret.txt");
		const runtimeDir = nodePath.join(ws, "..", "runtime");
		const compiled = await compileBwrapArgs({
			workspace: ws,
			rules: [{ path: target, mode: AccessMode.Deny, asDirectory: false }],
			reserved: [],
			runtimeDir,
		});
		const a = compiled.sandboxArgs;
		assert.ok(a.includes(target), "target mounted");
		assert.equal(existsSync(target), true, "placeholder created");
		assert.equal(
			compiled.createdPlaceholders.some((p) => p.target === target),
			true,
		);
	} finally {
		cleanup();
	}
});

// ---------------------------------------------------------------------------
// Real bwrap integration
// ---------------------------------------------------------------------------

if (haveBwrap) {
	test("bash: normal files read+write inside bwrap", async () => {
		const { ws, cleanup } = makeWs();
		try {
			await writeFile(nodePath.join(ws, "ok.txt"), "plain\n");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			const c = makeCollector();
			const out = await runGuardedBash({
				command: "cat ok.txt && echo appended >> ok.txt && cat ok.txt",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			assert.ok(c.get().includes("appended"));
			assert.ok((await readFile(nodePath.join(ws, "ok.txt"), "utf8")).includes("appended"));
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: READ file readable but not modifiable", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const target = nodePath.join(ws, "prod.json");
			await writeFile(target, "version: 1\n");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: target,
				mode: AccessMode.Read,
				logicalPath: "prod.json",
			});
			const c = makeCollector();
			const out = await runGuardedBash({
				command: "cat prod.json; echo x >> prod.json 2>&1; rm prod.json 2>&1; echo done",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			assert.match(c.get(), /version: 1/);
			assert.match(c.get(), /Read-only file system|Operation not permitted/);
			assert.equal(await readFile(target, "utf8"), "version: 1\n", "content not modified");
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: DENY file content unreadable by any tool", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const target = nodePath.join(ws, ".env");
			await writeFile(target, "TOKEN=super-secret\n");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: target,
				mode: AccessMode.Deny,
				logicalPath: ".env",
			});
			const c = makeCollector();
			const out = await runGuardedBash({
				command:
					"cat .env 2>&1; python3 -c 'print(open(\".env\").read())' 2>&1; " +
					'node -e \'console.log(require("fs").readFileSync(".env","utf8"))\' 2>&1; ' +
					"cp .env /tmp/leak 2>&1; ls /tmp/leak 2>&1; echo ok",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			const log = c.get();
			assert.ok(!log.includes("TOKEN"), `secret leaked: ${log}`);
			assert.match(log, /Permission denied|EACCES|Read-only file system/);
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: deny dir name visible at parent, content+modify denied", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const dir = nodePath.join(ws, "secrets");
			mkdirSync(dir);
			await writeFile(nodePath.join(dir, "key"), "TOPSECRETDIRKEY");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: dir,
				mode: AccessMode.Deny,
				logicalPath: "secrets/",
				asDirectory: true,
			});
			const c = makeCollector();
			const out = await runGuardedBash({
				command: "ls -1; ls secrets 2>&1; cat secrets/key 2>&1; touch secrets/new 2>&1; echo done",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			const log = c.get();
			assert.match(log, /^secrets$/m, "name visible at parent");
			assert.match(log, /Permission denied/);
			assert.ok(!log.includes("TOPSECRETDIRKEY"), `dir content leaked: ${log}`);
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: symlink alias cannot bypass deny (Gate 5)", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const target = nodePath.join(ws, "real.txt");
			await writeFile(target, "realtarget\n");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: target,
				mode: AccessMode.Deny,
				logicalPath: "real.txt",
			});
			const c = makeCollector();
			const out = await runGuardedBash({
				command: "ln -sf real.txt alias.txt; cat alias.txt 2>&1; cat real.txt 2>&1; echo done",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			const log = c.get();
			assert.match(log, /Permission denied/);
			assert.ok(!log.includes("realtarget"), `alias leaked: ${log}`);
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: state file is always denied (AC9)", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: nodePath.join(ws, "x.txt"),
				mode: AccessMode.Read,
			});
			const stateFile = state.stateFile;
			assert.equal(
				await access(stateFile).then(
					() => true,
					() => false,
				),
				true,
				"state persists on disk",
			);
			const c = makeCollector();
			const out = await runGuardedBash({
				command: `cat ${stateFile} 2>&1; echo TOKEN=SECRET > ${stateFile} 2>&1; rm -f ${stateFile} 2>&1; echo done`,
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			assert.match(c.get(), /Permission denied|Read-only file system/);
			// Guard itself may append `created` flags to its own state between
			// reads; what matters is that the agent's tamper never landed and
			// the file still parses as the guard's own format.
			const after = await readFile(stateFile, "utf8");
			assert.ok(!after.includes("TOKEN=SECRET"), "state file tampered with");
			const parsed = JSON.parse(after);
			assert.equal(parsed.version, 1);
			assert.equal(parsed.projects[ws].rules[0].mode, "read");
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: process tree descendants inherit restrictions", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const target = nodePath.join(ws, "hidden.txt");
			await writeFile(target, "deep\n");
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			await state.setRule({
				path: target,
				mode: AccessMode.Deny,
				logicalPath: "hidden.txt",
			});
			const c = makeCollector();
			const out = await runGuardedBash({
				command:
					"bash -c 'sh -c \"cat hidden.txt\"' 2>&1; echo ---; " +
					'node -e \'require("child_process").execSync("cat hidden.txt",{stdio:"inherit"})\' 2>&1; echo done',
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
			});
			assert.equal(out.exitCode, 0);
			assert.ok(!c.get().includes("deep"), "nested process escaped");
			cleanupAgent();
		} finally {
			cleanup();
		}
	});

	test("bash: timeout and abort kill the whole namespace", async () => {
		const { ws, cleanup } = makeWs();
		try {
			const { state, cleanup: cleanupAgent } = await makeState(ws);
			const c = makeCollector();
			// timeout
			await assert.rejects(
				runGuardedBash({
					command: "echo start; sleep 30; echo end",
					cwd: ws,
					onData: c.onData,
					timeout: 1,
					snapshot: snapshotOf(state),
				}),
				/timeout/,
			);
			assert.match(c.get(), /start/, "child started and was killed");
			assert.ok(!c.get().includes("end"), "child killed before completing");
			// abort
			const ac = new AbortController();
			ac.abort();
			await assert.rejects(
				runGuardedBash({
					command: "sleep 30",
					cwd: ws,
					onData: c.onData,
					signal: ac.signal,
					snapshot: snapshotOf(state),
				}),
				/aborted/,
			);
			cleanupAgent();
		} finally {
			cleanup();
		}
	});
} else {
	test("bwrap integration: skipped (bubblewrap not installed)", { skip: "bubblewrap not installed" }, () => {});
}

test("fail closed: missing bwrap binary rejects instead of running unsandboxed", async () => {
	const { ws, cleanup } = makeWs();
	try {
		const { state, cleanup: cleanupAgent } = await makeState(ws);
		const c = makeCollector();
		// Force spawn to fail with ENOENT by removing bwrap from PATH.
		await assert.rejects(
			runGuardedBash({
				command: "echo this-must-not-run > /tmp/guard-failclosed-marker",
				cwd: ws,
				onData: c.onData,
				snapshot: snapshotOf(state),
				env: { PATH: "/nonexistent" },
			}),
			/bubblewrap|ENOENT|failed to start|spawn/i,
		);
		assert.equal(existsSync("/tmp/guard-failclosed-marker"), false, "command must never run unsandboxed");
		cleanupAgent();
	} finally {
		cleanup();
	}
});
