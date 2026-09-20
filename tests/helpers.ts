/**
 * tests/helpers.ts — shared fixture utilities for v2 search tests.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { normalizeAbsolute } from "../paths.ts";
import { AccessMode, type GuardRule } from "../policy.ts";
import { GuardState, snapshotOf } from "../state.ts";

export const haveBwrap = (() => {
	try {
		return spawnSync("bwrap", ["--version"], { stdio: "ignore" }).status === 0;
	} catch {
		return false;
	}
})();

export function haveTool(name: "fd" | "rg"): boolean {
	try {
		return spawnSync(name, ["--version"], { stdio: "ignore" }).status === 0;
	} catch {
		return false;
	}
}

export interface SearchEnv {
	ws: string;
	agentDir: string;
	state: GuardState;
	/** Convenience: workspace-relative DENY/READ rule helpers. */
	deny(rel: string, asDirectory?: boolean): Promise<void>;
	read(rel: string): Promise<void>;
	cleanup(): void;
}

export function makeSearchEnv(): SearchEnv {
	const root = mkdtempSync(nodePath.join(tmpdir(), "guard-search-"));
	const ws = nodePath.join(root, "ws");
	mkdirSync(ws);
	const agentDir = nodePath.join(root, "agent");
	mkdirSync(agentDir);
	const state = new GuardState(ws, agentDir);

	return {
		ws,
		agentDir,
		state,
		async deny(rel, asDirectory = false) {
			await state.setRule({
				path: normalizeAbsolute(nodePath.join(ws, rel)),
				mode: AccessMode.Deny,
				logicalPath: rel,
				asDirectory,
			});
		},
		async read(rel) {
			await state.setRule({
				path: nodePath.join(ws, rel),
				mode: AccessMode.Read,
				logicalPath: rel,
			});
		},
		cleanup: () => rmSync(root, { recursive: true, force: true }),
	};
}

/** Populate a directory tree from a spec: keys are relative paths, values are contents. */
export function populate(ws: string, files: Record<string, string>): void {
	for (const [rel, content] of Object.entries(files)) {
		const p = nodePath.join(ws, rel);
		mkdirSync(nodePath.dirname(p), { recursive: true });
		writeFileSync(p, content);
	}
}

export function rulesOf(env: SearchEnv): GuardRule[] {
	return env.state.rules;
}

export function snapshotOfEnv(env: SearchEnv) {
	return snapshotOf(env.state);
}

export { existsSync, nodePath as path };
