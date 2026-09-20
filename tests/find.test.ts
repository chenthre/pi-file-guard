/**
 * tests/find.test.ts — sandboxed fd adapter (v2 Gate 3) + real integration.
 */

import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import nodePath from "node:path";
import { test } from "node:test";
import {
	buildFdArgs,
	FIND_DEFAULT_LIMIT,
	formatFindOutput,
	relativizeFindResultPath,
	runSandboxedFd,
} from "../search/find.ts";
import { resolveSearchToolBinary } from "../search/tool-path.ts";
import { haveBwrap, makeSearchEnv, populate, snapshotOfEnv } from "./helpers.ts";

// ---------------------------------------------------------------------------
// Unit: argument construction
// ---------------------------------------------------------------------------

test("buildFdArgs: baseline Pi semantics", () => {
	const args = buildFdArgs({
		pattern: "*.ts",
		searchPath: "/tmp/x",
		limit: 1000,
	});
	assert.ok(args.includes("--glob"));
	assert.ok(args.includes("--color=never"));
	assert.ok(args.includes("--hidden"));
	assert.ok(args.includes("--max-results"));
	assert.equal(args[args.indexOf("--max-results") + 1], "1000");
	// glob + limit + searchPath at the end
	const dash = args.indexOf("--");
	assert.equal(args[dash + 1].includes("[*]") || args[dash + 1], "*.ts");
	assert.equal(args[dash + 2], "/tmp/x");
});

test("buildFdArgs: path-containing pattern gets --full-path + **/ prefix", () => {
	const args = buildFdArgs({
		pattern: "src/**/*.spec.ts",
		searchPath: "/tmp/x",
		limit: 10,
	});
	assert.ok(args.includes("--full-path"));
	const idx = args.indexOf("--");
	assert.equal(args[idx + 1], "**/src/**/*.spec.ts");
});

test("buildFdArgs: excludes added when deny rules under root", async () => {
	const base = makeSearchEnv();
	try {
		await base.deny(".env");
		await base.deny("secrets/", true);
		const args = buildFdArgs({
			pattern: "**",
			searchPath: base.ws,
			limit: 100,
			useExcludes: true,
			denyRules: rulesOf(base),
		});
		assert.ok(args.includes("--exclude"));
		const exIdx = args.indexOf("--exclude");
		assert.equal(args[exIdx + 1], "./.env");
		assert.ok(args.some((a, i) => args[i - 1] === "--exclude" && a === "./secrets"));
	} finally {
		base.cleanup();
	}
});

test("buildFdArgs: excludes disabled when useExcludes false", async () => {
	const base = makeSearchEnv();
	try {
		await base.deny(".env");
		const args = buildFdArgs({
			pattern: "**",
			searchPath: base.ws,
			limit: 100,
			useExcludes: false,
			denyRules: rulesOf(base),
		});
		assert.ok(!args.includes("--exclude"));
	} finally {
		base.cleanup();
	}
});

test("relativizeFindResultPath mirrors Pi semantics", () => {
	assert.equal(relativizeFindResultPath("/a/b/c.ts", "/a"), "b/c.ts");
	assert.equal(relativizeFindResultPath(`${nodePath.join("/a", "d", "e")}/`, "/a"), "d/e/");
});

// ---------------------------------------------------------------------------
// Integration (real bwrap + fd)
// ---------------------------------------------------------------------------

const fdPath = resolveSearchToolBinary("fd", nodePath.join(process.env.HOME ?? "/", ".pi", "agent"));
const haveFd = fdPath !== null;

if (haveBwrap && haveFd) {
	test("sandboxed fd: finds files, respects .gitignore inside a repo", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, {
				"src/a.ts": "a",
				"src/b.ts": "b",
				"ignored.txt": "x",
				".gitignore": "ignored.txt\nnode_modules/\n",
				"node_modules/pkg/index.js": "y",
			});
			mkdirSync(nodePath.join(env.ws, ".git"));
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath!,
				snapshot: snapshotOfEnv(env),
			});
			const formatted = formatFindOutput({
				lines: out.lines,
				searchPath: env.ws,
				limit: FIND_DEFAULT_LIMIT,
				stderr: out.stderr,
				exitCode: out.exitCode,
			});
			assert.equal(out.exitCode, 0, out.stderr);
			assert.match(formatted.text, /src\/a\.ts/);
			assert.match(formatted.text, /src\/b\.ts/);
			assert.ok(!formatted.text.includes("ignored.txt"), `.gitignore not honored: ${formatted.text}`);
			assert.ok(!formatted.text.includes("node_modules"), `node_modules leaked: ${formatted.text}`);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed fd: works outside git repos (--no-require-git path)", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "plain.txt": "x", ".hidden": "h" });
			const out = await runSandboxedFd({
				pattern: "*",
				searchPath: env.ws,
				fdPath: fdPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.exitCode, 0, out.stderr);
			assert.match(out.lines.join("\n"), /plain\.txt/);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed fd: no matches yields Pi-compatible text", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "a.txt": "x" });
			const out = await runSandboxedFd({
				pattern: "*.nomatch",
				searchPath: env.ws,
				fdPath: fdPath!,
				snapshot: snapshotOfEnv(env),
			});
			const formatted = formatFindOutput({
				lines: out.lines,
				searchPath: env.ws,
				limit: FIND_DEFAULT_LIMIT,
				stderr: out.stderr,
				exitCode: out.exitCode,
			});
			assert.equal(formatted.text, "No files found matching pattern");
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed fd: nonexistent path surfaces an error, not empty results", async () => {
		const env = makeSearchEnv();
		try {
			const missing = nodePath.join(env.ws, "does-not-exist");
			await assert.rejects(
				runSandboxedFd({
					pattern: "**",
					searchPath: missing,
					fdPath: fdPath!,
					snapshot: snapshotOfEnv(env),
				}),
				/Path not found/,
			);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed fd: limit caps results via --max-results", async () => {
		const env = makeSearchEnv();
		try {
			const files: Record<string, string> = {};
			for (let i = 0; i < 25; i++) files[`f${String(i).padStart(2, "0")}.txt`] = i.toString();
			populate(env.ws, files);
			const out = await runSandboxedFd({
				pattern: "*.txt",
				searchPath: env.ws,
				fdPath: fdPath!,
				limit: 10,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.lines.length, 10);
			const formatted = formatFindOutput({
				lines: out.lines,
				searchPath: env.ws,
				limit: 10,
				stderr: out.stderr,
				exitCode: out.exitCode,
			});
			assert.match(formatted.text, /10 results limit reached/);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed fd: abort kills the search (no orphan)", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "a.txt": "x" });
			const ac = new AbortController();
			ac.abort();
			const out = await runSandboxedFd({
				pattern: "**",
				searchPath: env.ws,
				fdPath: fdPath!,
				snapshot: snapshotOfEnv(env),
				signal: ac.signal,
			});
			assert.equal(out.killed, true);
		} finally {
			env.cleanup();
		}
	});
} else {
	test("sandboxed fd integration: skipped", { skip: "bubblewrap or fd unavailable" }, () => {});
}

function rulesOf(env: ReturnType<typeof makeSearchEnv>) {
	return env.state.rules;
}
