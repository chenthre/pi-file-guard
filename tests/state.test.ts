/**
 * state.test.ts — GuardState, persistence, reserved paths, placeholders.
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { test } from "node:test";
import { AccessMode } from "../policy.ts";
import {
	atomicWriteJson,
	cleanupPlaceholder,
	ensureMaskableTarget,
	GuardState,
	loadState,
	STATE_FILE_NAME,
} from "../state.ts";

function tempAgentDir(): string {
	return mkdtempSync(nodePath.join(tmpdir(), "guard-state-"));
}

test("GuardState: setRule/removeRule + persistence round trip", async () => {
	const agentDir = tempAgentDir();
	try {
		const ws = "/work/proj";
		const state = new GuardState(ws, agentDir);
		await state.setRule({
			path: "/work/proj/.env",
			mode: AccessMode.Deny,
			logicalPath: "/work/proj/.env",
		});
		await state.setRule({
			path: "/work/proj/prod.json",
			mode: AccessMode.Read,
			logicalPath: "/work/proj/prod.json",
		});

		// Persisted atomically at the agent dir.
		const raw = JSON.parse(readFileSync(nodePath.join(agentDir, STATE_FILE_NAME), "utf8"));
		assert.equal(raw.version, 1);
		assert.equal(raw.projects[ws].rules.length, 2);

		// Reload into a fresh state.
		const fresh = new GuardState(ws, agentDir);
		const persisted = await loadState(agentDir);
		const project = persisted.projects[ws];
		fresh.replaceRules(
			project.rules.map((r) => ({
				path: r.path,
				mode: r.mode === "deny" ? AccessMode.Deny : AccessMode.Read,
				logicalPath: r.logicalPath,
				asDirectory: r.asDirectory,
				created: r.created,
			})),
		);
		assert.equal(fresh.rules.length, 2);
		assert.equal(fresh.rules.find((r) => r.path === "/work/proj/.env")?.mode, AccessMode.Deny);

		// Removal.
		const removed = await fresh.removeRule({ path: "/work/proj/.env" });
		assert.ok(removed);
		assert.equal(fresh.rules.length, 1);
		const after = await loadState(agentDir);
		assert.equal(after.projects[ws].rules.length, 1);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("GuardState: projects are keyed by workspace and do not clobber each other", async () => {
	const agentDir = tempAgentDir();
	try {
		const a = new GuardState("/work/a", agentDir);
		const b = new GuardState("/work/b", agentDir);
		await a.setRule({ path: "/work/a/.env", mode: AccessMode.Deny });
		await b.setRule({ path: "/work/b/x", mode: AccessMode.Read });
		const persisted = await loadState(agentDir);
		assert.equal(persisted.projects["/work/a"].rules.length, 1);
		assert.equal(persisted.projects["/work/b"].rules.length, 1);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("GuardState: cannot set a rule on reserved paths", async () => {
	const agentDir = tempAgentDir();
	try {
		const state = new GuardState("/work/proj", agentDir);
		const stateFile = state.stateFile;
		await assert.rejects(state.setRule({ path: stateFile, mode: AccessMode.Deny }), /reserved/);
		await assert.rejects(
			state.setRule({
				path: nodePath.join(agentDir, "file-guard", "x"),
				mode: AccessMode.Read,
			}),
			/reserved/,
		);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("atomicWriteJson writes durable content", async () => {
	const agentDir = tempAgentDir();
	try {
		const file = nodePath.join(agentDir, "nested", "dir", "state.json");
		await atomicWriteJson(file, { version: 1, ok: true });
		assert.equal(JSON.parse(readFileSync(file, "utf8")).ok, true);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("ensureMaskableTarget: creates 000 file for DENY, 444 for READ, 755 dir", async () => {
	const agentDir = tempAgentDir();
	try {
		const f = nodePath.join(agentDir, "f");
		const { created, type } = await ensureMaskableTarget(f, false, AccessMode.Deny);
		assert.equal(created, true);
		assert.equal(type, "file");
		assert.equal(statSync(f).mode & 0o777, 0o000);

		const r = nodePath.join(agentDir, "r");
		await ensureMaskableTarget(r, false, AccessMode.Read);
		assert.equal(statSync(r).mode & 0o777, 0o444);

		const d = nodePath.join(agentDir, "d");
		await ensureMaskableTarget(d, true, AccessMode.Deny);
		assert.equal(statSync(d).isDirectory(), true);

		// Second call: not "created" again.
		const again = await ensureMaskableTarget(f, false, AccessMode.Deny);
		assert.equal(again.created, false);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("cleanupPlaceholder removes only empty, guard-created targets", async () => {
	const { chmod, writeFile } = await import("node:fs/promises");
	const agentDir = tempAgentDir();
	try {
		const empty = nodePath.join(agentDir, "empty-file");
		await ensureMaskableTarget(empty, false, AccessMode.Deny);
		await cleanupPlaceholder(empty, "file");
		assert.equal(existsSync(empty), false);

		const nonEmpty = nodePath.join(agentDir, "filled");
		await ensureMaskableTarget(nonEmpty, false, AccessMode.Deny);
		// fill it with real content (must chmod first — placeholder is 000)
		await chmod(nonEmpty, 0o600);
		await writeFile(nonEmpty, "user content");
		await cleanupPlaceholder(nonEmpty, "file");
		assert.equal(existsSync(nonEmpty), true);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});

test("markPlaceholders tags only matching rules", async () => {
	const agentDir = tempAgentDir();
	try {
		const state = new GuardState("/work/proj", agentDir);
		await state.setRule({
			path: "/work/proj/future.txt",
			mode: AccessMode.Deny,
			logicalPath: "/work/proj/future.txt",
		});
		assert.equal(state.rules[0].created, undefined);
		await state.markPlaceholders([{ target: "/work/proj/future.txt", type: "file" }]);
		assert.equal(state.rules[0].created, true);
		const persisted = await loadState(agentDir);
		assert.equal(persisted.projects["/work/proj"].rules[0].created, true);
	} finally {
		rmSync(agentDir, { recursive: true, force: true });
	}
});
