/**
 * tests/grep.test.ts — sandboxed rg adapter (v2 Gate 4) + real integration.
 */

import assert from "node:assert/strict";
import nodePath from "node:path";
import { test } from "node:test";
import { stderrIsBenignSearchNoise } from "../sandbox-process.ts";
import {
	buildRgArgs,
	classifyGrepFailure,
	formatGrepOutput,
	GREP_DEFAULT_LIMIT,
	runSandboxedRg,
} from "../search/grep.ts";
import { resolveSearchToolBinary } from "../search/tool-path.ts";
import { haveBwrap, makeSearchEnv, populate, snapshotOfEnv } from "./helpers.ts";

const rgPath = resolveSearchToolBinary("rg", nodePath.join(process.env.HOME ?? "/", ".pi", "agent"));
const haveRg = rgPath !== null;

// ---------------------------------------------------------------------------
// Unit
// ---------------------------------------------------------------------------

test("buildRgArgs: baseline mirrors Pi semantics", () => {
	const args = buildRgArgs({ pattern: "foo", searchPath: "/x" });
	for (const flag of ["--json", "--line-number", "--color=never", "--hidden"]) {
		assert.ok(args.includes(flag), flag);
	}
	const idx = args.indexOf("--");
	assert.equal(args[idx + 1], "foo");
	assert.equal(args[idx + 2], "/x");
});

test("buildRgArgs: flags, glob and context (-C from rg itself)", () => {
	const args = buildRgArgs({
		pattern: "FOO",
		searchPath: "/x",
		ignoreCase: true,
		literal: true,
		glob: "*.ts",
		context: 3,
	});
	assert.ok(args.includes("--ignore-case"));
	assert.ok(args.includes("--fixed-strings"));
	assert.ok(args.includes("--glob"));
	assert.ok(args.includes("-C"));
	assert.equal(args[args.indexOf("-C") + 1], "3");
});

test("buildRgArgs: deny excludes become negated globs, skippable", async () => {
	const env = makeSearchEnv();
	try {
		await env.deny(".env");
		await env.deny("secrets/", true);
		const args = buildRgArgs({
			pattern: "x",
			searchPath: env.ws,
			useExcludes: true,
			denyRules: env.state.rules,
		});
		assert.ok(args.includes("--glob") && args.includes("!.env"));
		assert.ok(args.includes("!secrets/**"));
		const off = buildRgArgs({
			pattern: "x",
			searchPath: env.ws,
			useExcludes: false,
			denyRules: env.state.rules,
		});
		assert.ok(!off.includes("!.env"));
	} finally {
		env.cleanup();
	}
});

test("stderrIsBenignSearchNoise: permission noise tolerated, real errors not", () => {
	assert.equal(stderrIsBenignSearchNoise(""), true);
	assert.equal(stderrIsBenignSearchNoise("Error: permission denied while opening /x/.env"), true);
	assert.equal(stderrIsBenignSearchNoise("invalid regex pattern: '['"), false);
	assert.equal(stderrIsBenignSearchNoise("bwrap: Failed to mount /proc: Operation not permitted\n"), false);
});

function grepOut(
	partial: Partial<Parameters<typeof classifyGrepFailure>[0]>,
): Parameters<typeof classifyGrepFailure>[0] {
	return {
		outputLines: [],
		stderr: "",
		exitCode: 0,
		killed: false,
		timedOut: false,
		matchCount: 0,
		matchLimitReached: false,
		linesTruncated: false,
		...partial,
	};
}

test("classifyGrepFailure: sandbox failures never tolerated", () => {
	assert.equal(
		classifyGrepFailure(grepOut({ exitCode: 2, stderr: "bwrap: error creating sandbox" })),
		"bwrap: error creating sandbox",
	);
	assert.equal(classifyGrepFailure(grepOut({ exitCode: 2, stderr: "error parsing regex" })), "error parsing regex");
	assert.equal(classifyGrepFailure(grepOut({ exitCode: 2, stderr: "Permission denied when searching /a" })), null);
	assert.equal(classifyGrepFailure(grepOut({ exitCode: 1 })), null);
	assert.equal(classifyGrepFailure(grepOut({ exitCode: 0 })), null);
	assert.equal(classifyGrepFailure(grepOut({ exitCode: null, killed: true })), null);
});

// ---------------------------------------------------------------------------
// Integration (real bwrap + rg)
// ---------------------------------------------------------------------------

if (haveBwrap && haveRg) {
	test("sandboxed rg: finds matches with file:line output", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, {
				"a.ts": "const ONE = 1;\nconst TWO = 2;\n",
				"b.txt": "ONE here\n",
			});
			const out = await runSandboxedRg({
				pattern: "ONE",
				searchPath: env.ws,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.exitCode, 0, out.stderr);
			assert.equal(out.matchCount, 2);
			const formatted = formatGrepOutput({
				outputLines: out.outputLines,
				matchCount: out.matchCount,
				matchLimitReached: false,
				linesTruncated: false,
				limit: GREP_DEFAULT_LIMIT,
			});
			assert.match(formatted.text, /a\.ts:1: const ONE = 1/);
			assert.match(formatted.text, /b\.txt:1: ONE here/);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: ignoreCase, literal and glob applied", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, {
				"a.ts": "hello world\nHELLO again\n",
				"b.md": "hello md\n",
			});
			const ic = await runSandboxedRg({
				pattern: "HELLO",
				searchPath: env.ws,
				ignoreCase: true,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			// matches in a.ts (2) + b.md (1)
			assert.equal(ic.matchCount, 3);
			const lit = await runSandboxedRg({
				pattern: "hello world",
				searchPath: env.ws,
				literal: true,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(lit.matchCount, 1);
			const glob = await runSandboxedRg({
				pattern: "hello",
				searchPath: env.ws,
				glob: "*.ts",
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.ok(!glob.outputLines.join("\n").includes("b.md"));
			// without -i, "hello" matches only the lowercase line 1 of a.ts
			assert.equal(glob.matchCount, 1);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: context lines rendered from rg itself (no host re-read)", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, {
				"file.txt": "line1\nline2\nTARGET\nline4\nline5\n",
			});
			const out = await runSandboxedRg({
				pattern: "TARGET",
				searchPath: env.ws,
				context: 1,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			const lines = out.outputLines;
			assert.ok(
				lines.some((l) => l === "file.txt-2- line2"),
				`before-context missing: ${lines.join("|")}`,
			);
			assert.ok(
				lines.some((l) => l === "file.txt:3: TARGET"),
				`match line missing: ${lines.join("|")}`,
			);
			assert.ok(
				lines.some((l) => l === "file.txt-4- line4"),
				`after-context missing: ${lines.join("|")}`,
			);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: no matches yields Pi-compatible text", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "a.txt": "content\n" });
			const out = await runSandboxedRg({
				pattern: "zzz-nomatch",
				searchPath: env.ws,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.exitCode, 1);
			const formatted = formatGrepOutput({
				outputLines: out.outputLines,
				matchCount: out.matchCount,
				matchLimitReached: false,
				linesTruncated: false,
				limit: GREP_DEFAULT_LIMIT,
			});
			assert.equal(formatted.text, "No matches found");
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: limit kills rg and reports limit reached", async () => {
		const env = makeSearchEnv();
		try {
			const files: Record<string, string> = {};
			for (let i = 0; i < 30; i++) files[`f${i}.txt`] = `match ${i}\n`;
			populate(env.ws, files);
			const out = await runSandboxedRg({
				pattern: "match",
				searchPath: env.ws,
				limit: 5,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.matchLimitReached, true);
			assert.equal(out.matchCount, 5);
			assert.equal(out.killed, true, "rg should have been killed at the limit");
			const formatted = formatGrepOutput({
				outputLines: out.outputLines,
				matchCount: out.matchCount,
				matchLimitReached: out.matchLimitReached,
				linesTruncated: false,
				limit: 5,
			});
			assert.match(formatted.text, /5 matches limit reached/);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: nonexistent search path rejected explicitly", async () => {
		const env = makeSearchEnv();
		try {
			await assert.rejects(
				runSandboxedRg({
					pattern: "x",
					searchPath: nodePath.join(env.ws, "missing"),
					rgPath: rgPath!,
					snapshot: snapshotOfEnv(env),
				}),
				/Path not found/,
			);
		} finally {
			env.cleanup();
		}
	});

	test("sandboxed rg: abort kills the search", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "a.txt": "x\n" });
			const ac = new AbortController();
			ac.abort();
			const out = await runSandboxedRg({
				pattern: "x",
				searchPath: env.ws,
				rgPath: rgPath!,
				snapshot: snapshotOfEnv(env),
				signal: ac.signal,
			});
			assert.equal(out.killed, true);
		} finally {
			env.cleanup();
		}
	});
} else {
	test("sandboxed rg integration: skipped", { skip: "bubblewrap or rg unavailable" }, () => {});
}
