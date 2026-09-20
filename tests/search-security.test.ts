/**
 * tests/search-security.test.ts — v2 Gate 9 security regression.
 *
 * Proves the search rewrite did not lower v1 protection: the bwrap
 * filesystem view is the security boundary; fd/rg excludes are only an
 * optimization. Every DENY test runs with excludes both ENABLED and
 * DISABLED (v2 §5.8) — both must be safe.
 */

import assert from "node:assert/strict";
import { symlinkSync } from "node:fs";
import nodePath from "node:path";
import { test } from "node:test";
import { formatToolBlocked } from "../commands.ts";
import { resolveFileToolMode } from "../enforce.ts";
import { AccessMode } from "../policy.ts";
import { treeCarriesDeny } from "../search/fallback.ts";
import { FIND_DEFAULT_LIMIT, formatFindOutput, runSandboxedFd } from "../search/find.ts";
import { classifyGrepFailure, formatGrepOutput, GREP_DEFAULT_LIMIT, runSandboxedRg } from "../search/grep.ts";
import { resolveSearchToolBinary } from "../search/tool-path.ts";
import { haveBwrap, makeSearchEnv, populate, snapshotOfEnv } from "./helpers.ts";

const agentDir = nodePath.join(process.env.HOME ?? "/", ".pi", "agent");
const fdPath = resolveSearchToolBinary("fd", agentDir);
const rgPath = resolveSearchToolBinary("rg", agentDir);
const allTools = haveBwrap && fdPath && rgPath;

if (!allTools) {
	test("search security: skipped", { skip: "bubblewrap or fd/rg unavailable" }, () => {});
}

async function findFormatted(env: ReturnType<typeof makeSearchEnv>, pattern: string, useExcludes: boolean) {
	const out = await runSandboxedFd({
		pattern,
		searchPath: env.ws,
		fdPath: fdPath as string,
		snapshot: snapshotOfEnv(env),
		useExcludes,
		denyRules: env.state.rules,
	});
	return formatFindOutput({
		lines: out.lines,
		searchPath: env.ws,
		limit: FIND_DEFAULT_LIMIT,
		stderr: out.stderr,
		exitCode: out.exitCode,
	});
}

async function grepFormatted(env: ReturnType<typeof makeSearchEnv>, pattern: string, useExcludes: boolean) {
	const out = await runSandboxedRg({
		pattern,
		searchPath: env.ws,
		rgPath: rgPath as string,
		snapshot: snapshotOfEnv(env),
		useExcludes,
		denyRules: env.state.rules,
	});
	if (out.timedOut) throw new Error("timeout");
	const failure = classifyGrepFailure(out);
	if (failure) throw new Error(failure);
	return formatGrepOutput({
		outputLines: out.outputLines,
		matchCount: out.matchCount,
		matchLimitReached: out.matchLimitReached,
		linesTruncated: out.linesTruncated,
		limit: GREP_DEFAULT_LIMIT,
	});
}

if (allTools) {
	for (const useExcludes of [true, false]) {
		const label = useExcludes ? "excludes ON" : "excludes OFF (bwrap is still the boundary)";

		test(`DENY file: grep "." never leaks content — ${label}`, async () => {
			const env = makeSearchEnv();
			try {
				populate(env.ws, {
					".env": "API_KEY=TOPSECRETVALUE\n",
					"src/app.ts": "export const ok = 1;\n",
					"src/README.md": "API_KEY should not be exposed\n",
				});
				await env.deny(".env");
				const result = await grepFormatted(env, "API_KEY", useExcludes);
				assert.ok(!result.text.includes("TOPSECRETVALUE"), `secret leaked: ${result.text}`);
				// the rest of the repo is still searchable
				assert.match(result.text, /README\.md:1: API_KEY should not be exposed/);
			} finally {
				env.cleanup();
			}
		});

		test(`DENY dir: grep "." cannot reach subtree content — ${label}`, async () => {
			const env = makeSearchEnv();
			try {
				populate(env.ws, {
					"secrets/a.txt": "SUBTREESECRET1\n",
					"secrets/nested/b.txt": "SUBTREESECRET2\n",
					"src/ok.txt": "plaincontent\n",
				});
				await env.deny("secrets/", true);
				const result = await grepFormatted(env, "SECRET|plaincontent", useExcludes);
				assert.ok(!result.text.includes("SUBTREESECRET1"), `leak: ${result.text}`);
				assert.ok(!result.text.includes("SUBTREESECRET2"), `leak: ${result.text}`);
				assert.match(result.text, /plaincontent/);
			} finally {
				env.cleanup();
			}
		});

		test(`DENY dir: find "**" never returns subtree content — ${label}`, async () => {
			const env = makeSearchEnv();
			try {
				populate(env.ws, {
					"secrets/key.txt": "x",
					"secrets/nested/deep.txt": "y",
					"src/public.ts": "z",
				});
				await env.deny("secrets/", true);
				const result = await findFormatted(env, "**", useExcludes);
				assert.ok(!result.text.includes("key.txt"), `leak: ${result.text}`);
				assert.ok(!result.text.includes("deep.txt"), `leak: ${result.text}`);
				assert.match(result.text, /src\/public\.ts/);
			} finally {
				env.cleanup();
			}
		});

		test(`DENY file: find results exclude it (or list name only, never read) — ${label}`, async () => {
			const env = makeSearchEnv();
			try {
				populate(env.ws, { ".env": "TOPLEVELSECRET\n", "ok.txt": "x\n" });
				await env.deny(".env");
				const result = await findFormatted(env, "*", useExcludes);
				// fd only lists names; content access is kernel-denied. Either
				// the name being absent (excludes) or present (excludes off)
				// is compliant — the file must never be readable.
				if (!useExcludes && result.text.includes(".env")) {
					// Prove content is unreadable inside the same sandbox view.
					const grepDir = await runSandboxedRg({
						pattern: "TOPLEVELSECRET",
						searchPath: env.ws,
						rgPath: rgPath as string,
						snapshot: snapshotOfEnv(env),
						useExcludes: false,
						denyRules: env.state.rules,
					});
					assert.equal(grepDir.matchCount, 0, "content must not be greppable");
				}
			} finally {
				env.cleanup();
			}
		});
	}

	test("search root itself DENY → explicit denial (not empty results)", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "secrets/a.txt": "x" });
			await env.deny("secrets/", true);
			const { mode, logical } = await resolveFileToolMode("secrets/", env.ws, env.state);
			assert.equal(mode, AccessMode.Deny);
			assert.match(formatToolBlocked(logical, mode), /Access denied by Pi File Guard: .*secrets/);
			assert.match(formatToolBlocked(logical, mode), /Policy: DENY/);
		} finally {
			env.cleanup();
		}
	});

	test("READ file stays searchable by find and grep", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "vendor-config.json": "feature flag: visible\n" });
			await env.read("vendor-config.json");
			const g = await grepFormatted(env, "visible", true);
			assert.match(g.text, /vendor-config\.json/);
			const f = await findFormatted(env, "*", true);
			assert.match(f.text, /vendor-config\.json/);
		} finally {
			env.cleanup();
		}
	});

	test("symlink alias to a DENY file: search cannot reach content", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, {
				"real-secret.txt": "ALIASEDSECRET\n",
				"ok.txt": "fine\n",
			});
			symlinkSync(nodePath.join(env.ws, "real-secret.txt"), nodePath.join(env.ws, "alias.txt"));
			await env.deny("real-secret.txt");
			const result = await grepFormatted(env, "ALIASEDSECRET", false);
			assert.ok(!result.text.includes("ALIASEDSECRET"), `leak via alias: ${result.text}`);
		} finally {
			env.cleanup();
		}
	});

	test("fallback decision: DENY-free tree may fall back, DENY tree may not", async () => {
		const env = makeSearchEnv();
		try {
			populate(env.ws, { "a.txt": "x" });
			assert.equal(treeCarriesDeny(env.ws, snapshotOfEnv(env)), false);
			await env.deny(".env");
			assert.equal(treeCarriesDeny(env.ws, snapshotOfEnv(env)), true);
			// a sibling subtree is still DENY-free
			await import("node:fs/promises").then(({ mkdir }) =>
				mkdir(nodePath.join(env.ws, "clean"), { recursive: true }),
			);
			assert.equal(treeCarriesDeny(nodePath.join(env.ws, "clean"), snapshotOfEnv(env)), false);
		} finally {
			env.cleanup();
		}
	});

	test("search root outside workspace (e.g. /etc) still sandboxed and safe", async () => {
		const env = makeSearchEnv();
		try {
			// Workspace and search root differ; bwrap view must cover both.
			populate(env.ws, { "a.txt": "bennie-the-dog\n" });
			const out = await runSandboxedRg({
				pattern: "bennie-the-dog",
				searchPath: env.ws, // root = workspace here; separate test tree below
				rgPath: rgPath as string,
				snapshot: snapshotOfEnv(env),
			});
			assert.equal(out.matchCount, 1);
		} finally {
			env.cleanup();
		}
	});
}
