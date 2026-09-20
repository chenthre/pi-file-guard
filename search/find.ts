/**
 * search/find.ts — sandboxed `fd` backend for the find tool (v2 Gate 3).
 *
 * The Node recursive walker from v1 is gone. fd runs INSIDE the same bwrap
 * filesystem view as bash, so:
 *   - `.gitignore` / nested-repo semantics come back (fd-native)
 *   - glob / hidden / symlink handling match Pi's built-in find
 *   - DENY paths are kernel-inaccessible; fd skips or warns, never leaks
 *   - optional --exclude patterns (search/excludes.ts) only reduce noise
 *
 * Argument construction mirrors Pi's current find.ts (verified against the
 * installed coding-agent 0.85.1): --glob --color=never --hidden, git-aware
 * --no-require-git behavior, --max-results, --full-path for path patterns.
 */

import { access } from "node:fs/promises";
import nodePath from "node:path";
import { createInterface } from "node:readline";

async function pathExists(p: string): Promise<boolean> {
	try {
		await access(p);
		return true;
	} catch {
		return false;
	}
}

import { DEFAULT_MAX_BYTES, type FindToolDetails, formatSize, truncateHead } from "@earendil-works/pi-coding-agent";
import { BwrapError, compileSandboxArgs } from "../bwrap.ts";
import type { GuardRule } from "../policy.ts";
import { sandboxFailureMarker, startSandboxedProcess } from "../sandbox-process.ts";
import type { PermissionSnapshot } from "../state.ts";
import { buildSearchExcludes } from "./excludes.ts";

export const FIND_DEFAULT_LIMIT = 1000;

export interface SandboxedFindOptions {
	pattern: string;
	/** Resolved absolute search path. */
	searchPath: string;
	/** Absolute path (or command name) of the fd binary visible in the sandbox. */
	fdPath: string;
	/** Result cap (fd --max-results). Default FIND_DEFAULT_LIMIT. */
	limit?: number;
	snapshot: PermissionSnapshot;
	signal?: AbortSignal;
	timeoutMs?: number;
	/** When false, fd --exclude optimization is skipped (security tests). */
	useExcludes?: boolean;
	/** Extra deny rules for excludes (usually snapshot.rules). */
	denyRules?: GuardRule[];
}

export interface SandboxedFindOutput {
	lines: string[];
	stderr: string;
	exitCode: number | null;
	killed: boolean;
	timedOut: boolean;
}

/** Relativize a raw fd output line against the search root (Pi-compatible). */
export function relativizeFindResultPath(resultPath: string, searchPath: string): string {
	const hadTrailingSeparator = resultPath.endsWith("/");
	const relativePath = nodePath.isAbsolute(resultPath) ? nodePath.relative(searchPath, resultPath) : resultPath;
	const normalized = relativePath.split(nodePath.sep).join("/");
	return hadTrailingSeparator && !normalized.endsWith("/") ? `${normalized}/` : normalized;
}

/** Build fd argv mirroring Pi's find tool semantics. */
export function buildFdArgs(options: {
	pattern: string;
	searchPath: string;
	limit: number;
	useExcludes?: boolean;
	denyRules?: GuardRule[];
}): string[] {
	const args: string[] = ["--glob", "--color=never", "--hidden"];

	// Git-aware: fd normally only honors .gitignore inside a repo; Pi keeps
	// --no-require-git outside repos so plain dirs still respect ignores
	// only when they are repos (same logic as Pi's find.ts).
	let insideGitRepo = false;
	for (let current = options.searchPath; ; ) {
		if (nodePathExists(nodePath.join(current, ".git"))) {
			insideGitRepo = true;
			break;
		}
		const parent = nodePath.dirname(current);
		if (parent === current) break;
		current = parent;
	}
	if (!insideGitRepo) args.push("--no-require-git");

	args.push("--max-results", String(options.limit));

	if (options.useExcludes !== false && options.denyRules && options.denyRules.length > 0) {
		for (const ex of buildSearchExcludes(options.searchPath, options.denyRules).fdExcludes) {
			args.push("--exclude", ex);
		}
	}

	// Path-containing glob patterns need --full-path + a leading '**/' prefix
	// (fd matches full paths in that mode). Mirrors Pi's find.ts.
	let effectivePattern = options.pattern;
	if (options.pattern.includes("/")) {
		args.push("--full-path");
		if (!options.pattern.startsWith("/") && !options.pattern.startsWith("**/") && options.pattern !== "**") {
			effectivePattern = `**/${options.pattern}`;
		}
	}
	args.push("--", effectivePattern, options.searchPath);
	return args;
}

function nodePathExists(p: string): boolean {
	try {
		// eslint-disable-next-line @typescript-eslint/no-require-imports
		const { accessSync } = require("node:fs");
		accessSync(p);
		return true;
	} catch {
		return false;
	}
}

/**
 * Run fd inside a fresh bwrap namespace and stream its results.
 * Throws BwrapError on sandbox construction failure; resolves with the
 * collected output otherwise (fail-closed decision lives with the caller).
 */
export async function runSandboxedFd(options: SandboxedFindOptions): Promise<SandboxedFindOutput> {
	// Pi's find rejects missing roots with an explicit message — never a quiet
	// "no files" and never a confusing sandbox spawn error.
	if (!(await pathExists(options.searchPath))) {
		throw new Error(`Path not found: ${options.searchPath}`);
	}
	const { sandboxArgs } = await compileSandboxArgs(options.snapshot);
	const fdArgs = buildFdArgs({
		pattern: options.pattern,
		searchPath: options.searchPath,
		limit: Math.max(1, options.limit ?? FIND_DEFAULT_LIMIT),
		useExcludes: options.useExcludes,
		denyRules: options.denyRules,
	});

	const proc = startSandboxedProcess({
		sandboxArgs,
		commandArgv: [options.fdPath, ...fdArgs],
		cwd: options.searchPath,
	});

	const rl = createInterface({ input: proc.stdout });
	const lines: string[] = [];
	let stderr = "";
	let killed = false;

	proc.stderr.on("data", (chunk) => {
		stderr += chunk.toString();
	});
	rl.on("line", (line) => lines.push(line));

	const stop = (signal: NodeJS.Signals = "SIGTERM") => {
		if (!killed && !proc.exited) {
			killed = true;
			proc.kill(signal);
		}
	};

	let timedOut = false;
	let timeoutHandle: NodeJS.Timeout | undefined;
	if (options.timeoutMs !== undefined && options.timeoutMs > 0) {
		timeoutHandle = setTimeout(() => {
			timedOut = true;
			stop("SIGKILL");
		}, options.timeoutMs);
	}
	const onAbort = () => stop("SIGKILL");
	if (options.signal) {
		if (options.signal.aborted) onAbort();
		else options.signal.addEventListener("abort", onAbort, { once: true });
	}

	try {
		const exitCode = await proc.exitCode;
		if (exitCode === -2) {
			throw new BwrapError("bubblewrap failed to start (spawn error)");
		}
		const sandboxFailure = sandboxFailureMarker(stderr);
		if (sandboxFailure) throw new BwrapError(sandboxFailure);
		return { lines, stderr, exitCode, killed: killed || timedOut, timedOut };
	} finally {
		rl.close();
		if (timeoutHandle) clearTimeout(timeoutHandle);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

/** Pi-compatible result text from raw fd output. */
export function formatFindOutput(options: {
	lines: string[];
	searchPath: string;
	limit: number;
	stderr: string;
	exitCode: number | null;
}): { text: string; details: FindToolDetails | undefined; error?: string } {
	const { lines, searchPath, limit } = options;

	// fd exit codes: 0 = some results, 1 = no matches. Anything else is a
	// (possibly sandbox-related) error — unless output already exists, in
	// which case partial results are returned like Pi does.
	if (options.exitCode !== null && options.exitCode !== 0 && options.exitCode !== 1) {
		const errorMsg = options.stderr.trim() || `fd exited with code ${options.exitCode}`;
		if (lines.length === 0) return { text: "", details: undefined, error: errorMsg };
	}

	if (lines.length === 0) {
		return { text: "No files found matching pattern", details: undefined };
	}

	const relativized: string[] = [];
	for (const rawLine of lines) {
		const line = rawLine.replace(/\r$/, "").trim();
		if (!line) continue;
		relativized.push(relativizeFindResultPath(line, searchPath));
	}

	const resultLimitReached = relativized.length >= limit;
	const rawOutput = relativized.join("\n");
	const truncation = truncateHead(rawOutput, {
		maxLines: Number.MAX_SAFE_INTEGER,
	});
	let resultOutput = truncation.content;
	const details: FindToolDetails = {};
	const notices: string[] = [];
	if (resultLimitReached) {
		notices.push(`${limit} results limit reached. Use limit=${limit * 2} for more, or refine pattern`);
		details.resultLimitReached = limit;
	}
	if (truncation.truncated) {
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
		details.truncation = truncation;
	}
	if (notices.length > 0) resultOutput += `\n\n[${notices.join(". ")}]`;
	return {
		text: resultOutput,
		details: Object.keys(details).length > 0 ? details : undefined,
	};
}
