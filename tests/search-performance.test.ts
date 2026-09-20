/**
 * tests/search-performance.test.ts — v2 Gate 8 regression benchmarks.
 *
 * Objective: prove the sandboxed native search (bwrap + fd / bwrap + rg)
 * does not regress traversal performance by an order of magnitude compared
 * with running the same native tool unsandboxed. Bwrap startup (~10-100ms)
 * is a fixed per-invocation cost; traversal itself stays in fd/rg.
 *
 * Trees: small (1k files), medium (15k files), ignore-heavy (src + big
 * node_modules + .gitignore). Assertions are deliberately lenient to avoid
 * CI flakiness; timings are printed for the report.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import nodePath from "node:path";
import { test } from "node:test";
import { runSandboxedFd } from "../search/find.ts";
import { runSandboxedRg } from "../search/grep.ts";
import { resolveSearchToolBinary } from "../search/tool-path.ts";
import { haveBwrap, makeSearchEnv, snapshotOfEnv } from "./helpers.ts";

const agentDir = nodePath.join(process.env.HOME ?? "/", ".pi", "agent");
const fdPath = resolveSearchToolBinary("fd", agentDir);
const rgPath = resolveSearchToolBinary("rg", agentDir);
const allTools = haveBwrap && fdPath && rgPath;

/** Create `count` small files under dir/batch-<i>/ with modest write spread. */
async function buildTree(dir: string, count: number, subdirs = true): Promise<void> {
	// eslint-disable-next-line @typescript-eslint/no-require-imports
	const { mkdir, writeFile } = await import("node:fs/promises");
	const BATCH = 512;
	const batchDirs = Math.ceil(count / BATCH);
	if (subdirs) {
		for (let b = 0; b < batchDirs; b++) {
			await mkdir(nodePath.join(dir, `d${b}`), { recursive: true });
		}
	} else {
		await mkdir(dir, { recursive: true });
	}
	let i = 0;
	while (i < count) {
		const jobs: Promise<void>[] = [];
		for (let j = 0; j < BATCH && i < count; j++, i++) {
			const p = subdirs
				? nodePath.join(dir, `d${Math.floor(i / BATCH)}`, `f${i}.txt`)
				: nodePath.join(dir, `f${i}.txt`);
			jobs.push(writeFile(p, `line ${i}\nsome content ${i % 7}\n`));
		}
		await Promise.all(jobs);
	}
}

/** Run fd natively (host) and return wall-clock ms. */
async function timeNativeFd(_searchPath: string, args: string[]): Promise<number> {
	const start = performance.now();
	await new Promise<void>((resolve, reject) => {
		const child = spawn(fdPath as string, args, {
			stdio: ["ignore", "pipe", "pipe"],
		});
		child.stdout?.resume();
		child.stderr?.resume();
		child.on("error", reject);
		child.on("close", () => resolve());
	});
	return performance.now() - start;
}

/** Run rg natively (host) and return wall-clock ms. */
async function timeNativeRg(searchPath: string, args: string[]): Promise<number> {
	const start = performance.now();
	await new Promise<void>((resolve, reject) => {
		const child = spawn(rgPath as string, args, {
			cwd: searchPath,
			stdio: ["ignore", "pipe", "pipe"],
		});
		child.stdout?.resume();
		child.stderr?.resume();
		child.on("error", reject);
		child.on("close", () => resolve());
	});
	return performance.now() - start;
}

if (!allTools) {
	test("search performance: skipped", { skip: "bubblewrap or fd/rg unavailable" }, () => {});
}

if (allTools) {
	test("performance: fd broad search across a 15k-file tree", async () => {
		const env = makeSearchEnv();
		try {
			await buildTree(env.ws, 15_000);
			const limit = 1000;
			const nativeMs = await timeNativeFd(env.ws, [
				"--glob",
				"--color=never",
				"--hidden",
				"--no-require-git",
				"--max-results",
				String(limit),
				"--",
				"*",
				env.ws,
			]);
			const sandboxStart = performance.now();
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath as string,
				limit,
				snapshot: snapshotOfEnv(env),
			});
			const sandboxMs = performance.now() - sandboxStart;
			console.log(
				`\n  [perf] fd ${env.ws.split("/").pop()} native=${nativeMs.toFixed(1)}ms sandboxed=${sandboxMs.toFixed(1)}ms lines=${out.lines.length}`,
			);
			assert.equal(out.exitCode, 0, out.stderr);
			assert.ok(out.lines.length > 0, "no results");
			assert.ok(
				sandboxMs < nativeMs * 6 + 2000,
				`sandboxed fd too slow: ${nativeMs.toFixed(1)}ms native vs ${sandboxMs.toFixed(1)}ms sandboxed`,
			);
		} finally {
			env.cleanup();
		}
	});

	test("performance: rg broad search across a 15k-file tree", async () => {
		const env = makeSearchEnv();
		try {
			await buildTree(env.ws, 15_000);
			const nativeMs = await timeNativeRg(env.ws, [
				"--line-number",
				"--color=never",
				"--hidden",
				"--no-messages",
				"--",
				"some content",
				env.ws,
			]);
			const sandboxStart = performance.now();
			const out = await runSandboxedRg({
				pattern: "some content",
				searchPath: env.ws,
				rgPath: rgPath as string,
				limit: 100,
				snapshot: snapshotOfEnv(env),
			});
			const sandboxMs = performance.now() - sandboxStart;
			console.log(
				`\n  [perf] rg native=${nativeMs.toFixed(1)}ms sandboxed=${sandboxMs.toFixed(1)}ms matches=${out.matchCount}`,
			);
			assert.ok(out.matchCount > 0);
			assert.ok(
				sandboxMs < nativeMs * 6 + 2000,
				`sandboxed rg too slow: ${nativeMs.toFixed(1)}ms native vs ${sandboxMs.toFixed(1)}ms sandboxed`,
			);
		} finally {
			env.cleanup();
		}
	});

	test("performance: ignore-heavy tree (src + node_modules + .gitignore)", async () => {
		const env = makeSearchEnv();
		try {
			// eslint-disable-next-line @typescript-eslint/no-require-imports
			const { mkdirSync, writeFileSync } = await import("node:fs");
			mkdirSync(nodePath.join(env.ws, ".git"), { recursive: true });
			writeFileSync(nodePath.join(env.ws, ".gitignore"), "node_modules/\nbuild/\n");
			await buildTree(nodePath.join(env.ws, "src"), 5_000);
			await buildTree(nodePath.join(env.ws, "node_modules"), 10_000);
			await buildTree(nodePath.join(env.ws, "build"), 5_000);

			const nativeMs = await timeNativeFd(env.ws, [
				"--glob",
				"--color=never",
				"--hidden",
				"--max-results",
				"1000",
				"--",
				"*",
				env.ws,
			]);
			const sandboxStart = performance.now();
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath as string,
				limit: 1000,
				snapshot: snapshotOfEnv(env),
			});
			const sandboxMs = performance.now() - sandboxStart;
			console.log(
				`\n  [perf] fd ignore-heavy native=${nativeMs.toFixed(1)}ms sandboxed=${sandboxMs.toFixed(1)}ms lines=${out.lines.length}`,
			);
			// .gitignore must be honored (node_modules/build excluded)
			assert.ok(!out.lines.some((l) => l.includes("node_modules")), "node_modules not ignored");
			assert.ok(!out.lines.some((l) => l.includes("/build/")), "build not ignored");
			assert.ok(sandboxMs < nativeMs * 6 + 3000, `sandboxed fd too slow on ignore-heavy tree`);
		} finally {
			env.cleanup();
		}
	});

	test("performance: DENY subtree present does not slow the whole search path", async () => {
		const env = makeSearchEnv();
		try {
			await buildTree(env.ws, 8_000);
			await env.deny("d0", true); // one deny subtree with many files
			const start = performance.now();
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath as string,
				limit: 1000,
				snapshot: snapshotOfEnv(env),
				useExcludes: true,
				denyRules: env.state.rules,
			});
			const ms = performance.now() - start;
			console.log(`\n  [perf] fd with DENY subtree ${ms.toFixed(1)}ms lines=${out.lines.length}`);
			assert.ok(out.lines.length > 0);
			assert.ok(ms < 10_000, `search with deny subtree too slow: ${ms.toFixed(1)}ms`);
		} finally {
			env.cleanup();
		}
	});

	test("performance: small 1k-tree search completes with fixed bwrap overhead", async () => {
		const env = makeSearchEnv();
		try {
			await buildTree(env.ws, 1_000);
			const start = performance.now();
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath as string,
				limit: 100,
				snapshot: snapshotOfEnv(env),
			});
			const ms = performance.now() - start;
			console.log(`\n  [perf] fd small ${ms.toFixed(1)}ms lines=${out.lines.length}`);
			assert.ok(out.lines.length > 0);
			assert.ok(ms < 4_000, `small sandboxed search too slow: ${ms.toFixed(1)}ms`);
		} finally {
			env.cleanup();
		}
	});
}
