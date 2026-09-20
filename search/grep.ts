/**
 * search/grep.ts — sandboxed `ripgrep` backend for the grep tool (v2 Gate 4).
 *
 * The whole search runs inside the same bwrap filesystem view as bash:
 *
 *   GuardState → compileSandboxArgs → bwrap -- rg --json ...
 *
 * Context lines come from rg itself (-C/--context JSON "context" events),
 * so there is NO host-side second read of any file (v2 §5.7) — the
 * operations.readFile path that the built-in grep uses for context is
 * deliberately not reused.
 *
 * rg JSON parse mirrors Pi's grep.ts event handling; stderr is classified so
 * expected permission warnings (DENY subtrees) never poison results while
 * unexpected sandbox failures ("bwrap:", spawn errors) fail closed.
 */

import { access, lstat } from "node:fs/promises";
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

import {
	DEFAULT_MAX_BYTES,
	formatSize,
	type GrepToolDetails,
	truncateHead,
	truncateLine,
} from "@earendil-works/pi-coding-agent";
import { BwrapError, compileSandboxArgs } from "../bwrap.ts";
import type { GuardRule } from "../policy.ts";
import { startSandboxedProcess } from "../sandbox-process.ts";
import type { PermissionSnapshot } from "../state.ts";
import { buildSearchExcludes } from "./excludes.ts";

export const GREP_DEFAULT_LIMIT = 100;

export interface SandboxedGrepOptions {
	pattern: string;
	/** Resolved absolute search path (dir or file). */
	searchPath: string;
	glob?: string;
	ignoreCase?: boolean;
	literal?: boolean;
	context?: number;
	limit?: number;
	/** Absolute path (or command name) of the rg binary visible in the sandbox. */
	rgPath: string;
	snapshot: PermissionSnapshot;
	signal?: AbortSignal;
	timeoutMs?: number;
	/** When false, rg --glob negation optimization is skipped (security tests). */
	useExcludes?: boolean;
	/** Extra deny rules for excludes (usually snapshot.rules). */
	denyRules?: GuardRule[];
	/** Directory that will exist in the sandbox (spawn cwd). Defaults to searchPath dir. */
	cwdDir?: string;
}

export interface SandboxedGrepOutput {
	outputLines: string[];
	stderr: string;
	exitCode: number | null;
	killed: boolean;
	timedOut: boolean;
	matchCount: number;
	matchLimitReached: boolean;
	linesTruncated: boolean;
}

/** Build rg argv mirroring Pi's grep tool semantics (+ -C context from rg). */
export function buildRgArgs(options: {
	pattern: string;
	searchPath: string;
	glob?: string;
	ignoreCase?: boolean;
	literal?: boolean;
	context?: number;
	useExcludes?: boolean;
	denyRules?: GuardRule[];
}): string[] {
	const args: string[] = ["--json", "--line-number", "--color=never", "--hidden"];
	if (options.ignoreCase) args.push("--ignore-case");
	if (options.literal) args.push("--fixed-strings");
	if (options.glob) args.push("--glob", options.glob);
	const contextValue = options.context && options.context > 0 ? options.context : 0;
	if (contextValue > 0) args.push("-C", String(contextValue));
	if (options.useExcludes !== false && options.denyRules && options.denyRules.length > 0) {
		for (const neg of buildSearchExcludes(options.searchPath, options.denyRules).rgGlobNegations) {
			args.push("--glob", neg);
		}
	}
	args.push("--", options.pattern, options.searchPath);
	return args;
}

import { sandboxFailureMarker, stderrIsBenignSearchNoise } from "../sandbox-process.ts";

interface RgJsonEvent {
	type: "begin" | "end" | "match" | "context" | "summary" | string;
	data?: {
		path?: { text?: string };
		line_number?: number;
		lines?: { text?: string };
	};
}

/**
 * Run rg inside a fresh bwrap namespace, parsing --json events into
 * pre-formatted output lines (context rendered from rg itself).
 */
export async function runSandboxedRg(options: SandboxedGrepOptions): Promise<SandboxedGrepOutput> {
	if (!(await pathExists(options.searchPath))) {
		throw new Error(`Path not found: ${options.searchPath}`);
	}
	const { sandboxArgs } = await compileSandboxArgs(options.snapshot);
	const rgArgs = buildRgArgs({
		pattern: options.pattern,
		searchPath: options.searchPath,
		glob: options.glob,
		ignoreCase: options.ignoreCase,
		literal: options.literal,
		context: options.context,
		useExcludes: options.useExcludes,
		denyRules: options.denyRules,
	});

	const isDirectory = (await isDir(options.searchPath)) ?? true;
	const effectiveLimit = Math.max(1, options.limit ?? GREP_DEFAULT_LIMIT);
	const contextValue = options.context && options.context > 0 ? options.context : 0;

	const cwdDir = options.cwdDir ?? (isDirectory ? options.searchPath : nodePath.dirname(options.searchPath));
	const proc = startSandboxedProcess({
		sandboxArgs,
		commandArgv: [options.rgPath, ...rgArgs],
		cwd: cwdDir,
	});

	const rl = createInterface({ input: proc.stdout });
	const outputLines: string[] = [];
	let stderr = "";
	let matchCount = 0;
	let matchLimitReached = false;
	let linesTruncated = false;
	let killed = false;
	let timedOut = false;

	proc.stderr.on("data", (chunk) => {
		stderr += chunk.toString();
	});

	const stop = (signal: NodeJS.Signals = "SIGTERM") => {
		if (!killed) {
			killed = true;
			proc.kill(signal);
		}
	};

	const formatPath = (filePath: string): string => {
		if (isDirectory) {
			const relative = nodePath.relative(options.searchPath, filePath);
			if (relative && !relative.startsWith("..")) return relative.replace(/\\/g, "/");
		}
		return nodePath.basename(filePath);
	};

	const clean = (text: string): string => text.replace(/\r\n/g, "\n").replace(/\r/g, "").replace(/\n$/, "");

	rl.on("line", (line) => {
		if (!line.trim() || matchCount >= effectiveLimit) return;
		let event: RgJsonEvent;
		try {
			event = JSON.parse(line) as RgJsonEvent;
		} catch {
			return;
		}
		if (event.type !== "match" && event.type !== "context") return;
		const filePath = event.data?.path?.text;
		const lineNumber = event.data?.line_number;
		const lineText = event.data?.lines?.text;
		if (typeof filePath !== "string" || typeof lineNumber !== "number") return;

		const relPath = formatPath(filePath);
		const sanitized = clean(typeof lineText === "string" ? lineText : "");
		const { text, wasTruncated } = truncateLine(sanitized);
		if (wasTruncated) linesTruncated = true;

		if (event.type === "match") {
			matchCount++;
			outputLines.push(`${relPath}:${lineNumber}: ${text}`);
			if (matchCount >= effectiveLimit) {
				matchLimitReached = true;
				stop();
			}
		} else if (contextValue > 0) {
			// Context events render directly from rg — no host readFile.
			outputLines.push(`${relPath}-${lineNumber}- ${text}`);
		}
	});

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
		if (exitCode === -2) throw new BwrapError("bubblewrap failed to start (spawn error)");
		const sandboxFailure = sandboxFailureMarker(stderr);
		if (sandboxFailure) throw new BwrapError(sandboxFailure);
		return {
			outputLines,
			stderr,
			exitCode,
			killed,
			timedOut,
			matchCount,
			matchLimitReached,
			linesTruncated,
		};
	} finally {
		rl.close();
		if (timeoutHandle) clearTimeout(timeoutHandle);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

async function isDir(p: string): Promise<boolean | null> {
	try {
		return (await lstat(p)).isDirectory();
	} catch {
		return null; // missing
	}
}

/** Decide whether a raw rg result is usable or a real failure. */
export function classifyGrepFailure(output: SandboxedGrepOutput): string | null {
	const { exitCode, killed, stderr } = output;
	if (exitCode === null || exitCode === 0 || exitCode === 1 || killed) return null;
	if (!stderrIsBenignSearchNoise(stderr)) {
		return stderr.trim() || `ripgrep exited with code ${exitCode}`;
	}
	return null;
}

/** Pi-compatible final text with truncation and limit notices. */
export function formatGrepOutput(options: {
	outputLines: string[];
	matchCount: number;
	matchLimitReached: boolean;
	linesTruncated: boolean;
	limit: number;
}): { text: string; details: GrepToolDetails | undefined } {
	if (options.matchCount === 0) {
		return { text: "No matches found", details: undefined };
	}
	const rawOutput = options.outputLines.join("\n");
	const truncation = truncateHead(rawOutput, {
		maxLines: Number.MAX_SAFE_INTEGER,
	});
	let output = truncation.content;
	const details: GrepToolDetails = {};
	const notices: string[] = [];
	if (options.matchLimitReached) {
		notices.push(
			`${options.limit} matches limit reached. Use limit=${options.limit * 2} for more, or refine pattern`,
		);
		details.matchLimitReached = options.limit;
	}
	if (truncation.truncated) {
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
		details.truncation = truncation;
	}
	if (options.linesTruncated) {
		notices.push(`Some lines truncated to 500 chars. Use read tool to see full lines`);
		details.linesTruncated = true;
	}
	if (notices.length > 0) output += `\n\n[${notices.join(". ")}]`;
	return {
		text: output,
		details: Object.keys(details).length > 0 ? details : undefined,
	};
}
