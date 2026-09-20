/**
 * index.ts — Pi File Guard extension entry point (v2).
 *
 * Protection surface:
 *   - read/write/edit : pre-execution enforcement via the shared PolicyEngine
 *     in the `tool_call` event (built-in tools unchanged otherwise)
 *   - bash            : same-name tool override — every command runs inside a
 *     fresh bubblewrap namespace built from the current policy snapshot
 *   - find            : same-name override — sandboxed `fd` inside the same
 *     bwrap filesystem view (no JS walker; .gitignore/glob/hidden semantics
 *     come from fd itself)
 *   - grep            : same-name override — sandboxed `rg --json` inside
 *     bwrap; context lines come from rg, never a host re-read
 *   - ls              : ops override — readdir of a DENY path fails
 *
 * Search dispatch (v2 §5.12): sandboxed native backend when available;
 * otherwise the conservative fallback runs the ORIGINAL host Pi find/grep —
 * exactly and only when the tree is provably DENY-free, and never with
 * post-result filtering.
 */

import { access, readdir as fsReaddir, stat as fsStat } from "node:fs/promises";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AgentToolResult,
	type AgentToolUpdateCallback,
	type BashOperations,
	createBashTool,
	createFindToolDefinition,
	createGrepToolDefinition,
	createLsTool,
	type ExtensionAPI,
	type ExtensionContext,
	type FindToolDetails,
	type GrepToolDetails,
	getAgentDir,
	isToolCallEventType,
	type LsOperations,
	type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { Static } from "typebox";
import { assertBwrapAvailable, BwrapError } from "./bwrap.ts";
import {
	applyRule,
	formatToolBlocked,
	formatWriteBlocked,
	GuardCommandError,
	guardCommand,
	removeRule,
} from "./commands.ts";
import { resolveFileToolMode } from "./enforce.ts";
import { buildPathForms, canonicalizePath, normalizeInputPath } from "./paths.ts";
import { AccessMode, resolveAccess } from "./policy.ts";
import { runGuardedBash } from "./sandbox-process.ts";
import { fallbackBlockedMessage, treeCarriesDeny } from "./search/fallback.ts";
import { FIND_DEFAULT_LIMIT, formatFindOutput, runSandboxedFd } from "./search/find.ts";
import { classifyGrepFailure, formatGrepOutput, GREP_DEFAULT_LIMIT, runSandboxedRg } from "./search/grep.ts";
import { resolveSearchToolBinary } from "./search/tool-path.ts";
import { GuardState, loadState, snapshotOf } from "./state.ts";

/** Safety net against orphaned rg/fd (v2 §5.14). */
const SEARCH_TIMEOUT_MS = 300_000;

// ---------------------------------------------------------------------------
// Module-level mutable snapshot (updated per session; tools read it lazily)
// ---------------------------------------------------------------------------

let currentState: GuardState | null = null;
let bwrapOk = false;
let agentDir = "";
let extensionReservedDir: string | null = null;

function requireState(): GuardState {
	if (!currentState) {
		throw new BwrapError(
			"Pi File Guard has no active policy this session. Bash, find and grep are refused until the guard initializes.",
		);
	}
	return currentState;
}

function policyContext(state: GuardState) {
	return {
		workspace: state.workspace,
		reservedDenyPaths: state.reservedDenyPaths,
	};
}

async function bwrapReady(): Promise<boolean> {
	bwrapOk = bwrapOk || (await probeBwrapLazy());
	return bwrapOk;
}

async function probeBwrapLazy(): Promise<boolean> {
	try {
		await assertBwrapAvailable();
		return true;
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// File tool enforcement (shared PolicyEngine + pre-execution blocking)
// ---------------------------------------------------------------------------

function registerToolCallGuard(pi: ExtensionAPI): void {
	pi.on("tool_call", async (event, ctx) => {
		if (!currentState) return; // guard not initialized; bash/search ops still fail closed

		if (isToolCallEventType("read", event)) {
			const { mode, logical } = await resolveFileToolMode(event.input.path, ctx.cwd, currentState);
			if (mode === AccessMode.Deny) return { block: true, reason: formatToolBlocked(logical, mode) };
			return;
		}

		if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
			const { mode, logical } = await resolveFileToolMode(event.input.path, ctx.cwd, currentState);
			if (mode !== AccessMode.Write) return { block: true, reason: formatWriteBlocked(logical, mode) };
			return;
		}

		// find/grep/ls: only the search ROOT being DENY is blocked here — DENY
		// subtrees are handled by the sandboxed fd/rg inside the tool itself
		// (v2 Gate 7: no blanket subtree blocks in normal mode).
		if (
			isToolCallEventType("grep", event) ||
			isToolCallEventType("find", event) ||
			isToolCallEventType("ls", event)
		) {
			const target = event.input.path ?? ".";
			const { mode, logical } = await resolveFileToolMode(target, ctx.cwd, currentState);
			if (mode === AccessMode.Deny) return { block: true, reason: formatToolBlocked(logical, mode) };
			return;
		}

		// bash / powershell: enforced inside the sandbox (bwrap), not here.
		return;
	});
}

// ---------------------------------------------------------------------------
// bash: bubblewrap-backed operations
// ---------------------------------------------------------------------------

function createGuardBashOperations(): BashOperations {
	return {
		async exec(command, cwd, { onData, signal, timeout, env }) {
			bwrapOk = await bwrapReady();
			if (!bwrapOk) {
				throw new BwrapError(
					"Pi File Guard: bubblewrap unavailable — refusing to run bash unsandboxed. " +
						"Install bubblewrap and restart pi.",
				);
			}
			const state = requireState();
			return runGuardedBash({
				command,
				cwd,
				env,
				onData,
				signal,
				timeout,
				snapshot: snapshotOf(state),
			});
		},
	};
}

// ---------------------------------------------------------------------------
// find: sandboxed fd (primary) with conservative fallback
// ---------------------------------------------------------------------------

function guardFindExecute(
	toolCallId: string,
	params: FindParams,
	signal: AbortSignal | undefined,
	onUpdate: AgentToolUpdateCallback<FindToolDetails | undefined> | undefined,
	ctx: ExtensionContext | undefined,
	originalExecute: FindOriginalExecute,
) {
	return (async () => {
		const state = requireState();
		const cwd = ctx?.cwd ?? process.cwd();
		const forms = await buildPathForms(params.path ?? ".", cwd);
		const mode = resolveAccess(forms.canonical, policyContext(state), state.rules, [forms.canonical, forms.logical]);
		if (mode === AccessMode.Deny) {
			// v2 §5.9: explicit denial, not "No matches".
			throw new Error(formatToolBlocked(forms.logical, mode));
		}
		const snapshot = snapshotOf(state);
		const limit = Math.max(1, params.limit ?? FIND_DEFAULT_LIMIT);

		const fdPath = (await bwrapReady()) ? resolveSearchToolBinary("fd", agentDir) : null;
		if (fdPath) {
			const out = await runSandboxedFd({
				pattern: params.pattern,
				searchPath: forms.canonical,
				fdPath,
				limit,
				snapshot,
				signal,
				timeoutMs: SEARCH_TIMEOUT_MS,
				denyRules: state.rules,
			});
			if (signal?.aborted) throw new Error("Operation aborted");
			if (out.timedOut) throw new Error("find timed out");
			const formatted = formatFindOutput({
				lines: out.lines,
				searchPath: forms.canonical,
				limit,
				stderr: out.stderr,
				exitCode: out.exitCode,
			});
			if (formatted.error) throw new Error(formatted.error);
			return {
				content: [{ type: "text" as const, text: formatted.text }],
				details: formatted.details,
			};
		}

		// Conservative fallback: safe only for a provably DENY-free tree.
		if (treeCarriesDeny(forms.canonical, snapshot)) throw new Error(fallbackBlockedMessage());
		return originalExecute(toolCallId, params, signal, onUpdate, ctx as ExtensionContext);
	})();
}

type FindParams = Static<typeof defaultFindDefinition.parameters>;
type GrepParams = Static<typeof defaultGrepDefinition.parameters>;

type FindOriginalExecute = (
	toolCallId: string,
	params: FindParams,
	signal: AbortSignal | undefined,
	onUpdate: AgentToolUpdateCallback<FindToolDetails | undefined> | undefined,
	ctx: ExtensionContext,
) => Promise<AgentToolResult<FindToolDetails | undefined>>;

type GrepOriginalExecute = (
	toolCallId: string,
	params: GrepParams,
	signal: AbortSignal | undefined,
	onUpdate: AgentToolUpdateCallback<GrepToolDetails | undefined> | undefined,
	ctx: ExtensionContext,
) => Promise<AgentToolResult<GrepToolDetails | undefined>>;

const defaultFindDefinition = createFindToolDefinition(nodePath.resolve("."));
const defaultGrepDefinition = createGrepToolDefinition(nodePath.resolve("."));

// ---------------------------------------------------------------------------
// grep: sandboxed rg (primary) with conservative fallback
// ---------------------------------------------------------------------------

function guardGrepExecute(
	toolCallId: string,
	params: GrepParams,
	signal: AbortSignal | undefined,
	onUpdate: AgentToolUpdateCallback<GrepToolDetails | undefined> | undefined,
	ctx: ExtensionContext | undefined,
	originalExecute: GrepOriginalExecute,
) {
	return (async () => {
		const state = requireState();
		const cwd = ctx?.cwd ?? process.cwd();
		const forms = await buildPathForms(params.path ?? ".", cwd);
		const mode = resolveAccess(forms.canonical, policyContext(state), state.rules, [forms.canonical, forms.logical]);
		if (mode === AccessMode.Deny) {
			throw new Error(formatToolBlocked(forms.logical, mode));
		}
		const snapshot = snapshotOf(state);
		const effectiveLimit = Math.max(1, params.limit ?? GREP_DEFAULT_LIMIT);

		const rgPath = (await bwrapReady()) ? resolveSearchToolBinary("rg", agentDir) : null;
		if (rgPath) {
			const out = await runSandboxedRg({
				pattern: params.pattern,
				searchPath: forms.canonical,
				glob: params.glob,
				ignoreCase: params.ignoreCase,
				literal: params.literal,
				context: params.context,
				limit: effectiveLimit,
				rgPath,
				snapshot,
				signal,
				timeoutMs: SEARCH_TIMEOUT_MS,
				denyRules: state.rules,
				cwdDir: cwd,
			});
			if (signal?.aborted) throw new Error("Operation aborted");
			if (out.timedOut) throw new Error("grep timed out");
			const failure = classifyGrepFailure(out);
			if (failure) throw new Error(failure);
			const formatted = formatGrepOutput({
				outputLines: out.outputLines,
				matchCount: out.matchCount,
				matchLimitReached: out.matchLimitReached,
				linesTruncated: out.linesTruncated,
				limit: effectiveLimit,
			});
			return {
				content: [{ type: "text" as const, text: formatted.text }],
				details: formatted.details,
			};
		}

		// Conservative fallback: safe only for a provably DENY-free tree.
		if (treeCarriesDeny(forms.canonical, snapshot)) throw new Error(fallbackBlockedMessage());
		return originalExecute(toolCallId, params, signal, onUpdate, ctx as ExtensionContext);
	})();
}

// ---------------------------------------------------------------------------
// ls: readdir enforcement (covers symlink aliases via canonical form)
// ---------------------------------------------------------------------------

function createGuardLsOperations(): LsOperations {
	return {
		exists: async (p) => {
			try {
				await access(p);
				return true;
			} catch {
				return false;
			}
		},
		stat: (p) => fsStat(p),
		async readdir(p) {
			const state = currentState;
			if (state) {
				let canonical = p;
				try {
					canonical = await canonicalizePath(p);
				} catch {
					canonical = normalizeInputPath(p, state.workspace);
				}
				const mode = resolveAccess(canonical, policyContext(state), state.rules, [canonical, p]);
				if (mode === AccessMode.Deny) {
					const err = new Error(`Access denied by Pi File Guard: ${p}`) as NodeJS.ErrnoException;
					err.code = "EACCES";
					throw err;
				}
			}
			return fsReaddir(p);
		},
	};
}

// ---------------------------------------------------------------------------
// Extension wiring
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI): void {
	agentDir = getAgentDir();
	const selfDir = nodePath.dirname(fileURLToPath(import.meta.url));
	recordExtensionReservedDir(selfDir);
	const cwd = process.cwd();

	// Bash override — every agent bash call goes through bwrap.
	const guardedBash = createBashTool(cwd, {
		operations: createGuardBashOperations(),
	});
	pi.registerTool({
		...guardedBash,
		label: "bash (file-guard)",
		description: guardedBash.description,
	});

	// find override — sandboxed fd with conservative fallback.
	const guardedFind: ToolDefinition<typeof defaultFindDefinition.parameters, FindToolDetails | undefined> = {
		...defaultFindDefinition,
		label: "find (file-guard)",
		execute: (
			toolCallId: string,
			params: FindParams,
			signal: AbortSignal | undefined,
			onUpdate: AgentToolUpdateCallback<FindToolDetails | undefined> | undefined,
			ctx?: ExtensionContext,
		) => guardFindExecute(toolCallId, params, signal, onUpdate, ctx, defaultFindDefinition.execute),
	};
	pi.registerTool(guardedFind);

	// grep override — sandboxed rg with conservative fallback.
	const guardedGrep: ToolDefinition<typeof defaultGrepDefinition.parameters, GrepToolDetails | undefined> = {
		...defaultGrepDefinition,
		label: "grep (file-guard)",
		execute: (
			toolCallId: string,
			params: GrepParams,
			signal: AbortSignal | undefined,
			onUpdate: AgentToolUpdateCallback<GrepToolDetails | undefined> | undefined,
			ctx?: ExtensionContext,
		) => guardGrepExecute(toolCallId, params, signal, onUpdate, ctx, defaultGrepDefinition.execute),
	};
	pi.registerTool(guardedGrep);

	// ls override — DENY dirs listable at parent, contents unreadable.
	const guardedLs = createLsTool(cwd, {
		operations: createGuardLsOperations(),
	});
	pi.registerTool({ ...guardedLs, label: "ls (file-guard)" });

	registerToolCallGuard(pi);

	// Slash commands (control plane only).
	const deps = {
		state: () => currentState,
		reload: async () => {
			await initGuard(currentState?.workspace ?? process.cwd());
			return currentState;
		},
	};

	pi.registerCommand("hide", {
		description: "Protect a path from the agent: name visible, content and modification denied (DENY)",
		handler: async (args, ctx) => execCommand(ctx, () => applyRule(deps, args, AccessMode.Deny)),
	});
	pi.registerCommand("lock", {
		description: "Protect a path from the agent: readable, not modifiable (READ)",
		handler: async (args, ctx) => execCommand(ctx, () => applyRule(deps, args, AccessMode.Read)),
	});
	pi.registerCommand("unhide", {
		description: "Remove a DENY override",
		handler: async (args, ctx) => execCommand(ctx, () => removeRule(deps, args)),
	});
	pi.registerCommand("unlock", {
		description: "Remove a READ override",
		handler: async (args, ctx) => execCommand(ctx, () => removeRule(deps, args)),
	});
	pi.registerCommand("guard", {
		description: "Show the current Pi File Guard policy, or: /guard deny|read|reset PATH, /guard list",
		handler: async (args, ctx) => execCommand(ctx, () => guardCommand(deps, args)),
	});

	pi.on("session_start", async (_event, ctx) => {
		try {
			const workspace = await canonicalizePath(ctx.cwd);
			await initGuard(workspace);
			if (ctx.hasUI) {
				if (!bwrapOk) {
					ctx.ui.notify(
						"Pi File Guard: bubblewrap is unavailable — bash is DISABLED (fail closed). File tools still enforce policy.",
						"error",
					);
				} else {
					ctx.ui.setStatus("file-guard", "🔒 Pi File Guard active");
				}
			}
		} catch (err) {
			ctx.ui.notify(`Pi File Guard init failed: ${(err as Error).message}`, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		currentState = null;
	});

	// user_bash (! commands) intentionally stays unsandboxed: the user is the
	// trusted control plane and must retain full access to their own machine,
	// including paths hidden from the agent. See README threat model.
}

async function execCommand(ctx: ExtensionContext, fn: () => Promise<{ message: string }>): Promise<void> {
	try {
		const { message } = await fn();
		ctx.ui.notify(message, "info");
	} catch (err) {
		if (err instanceof GuardCommandError && err.meta.notFound) {
			ctx.ui.notify(err.message, "warning");
			return;
		}
		ctx.ui.notify(`Pi File Guard: ${(err as Error).message}`, "error");
	}
}

/**
 * Record the extension's own directory as reserved, when it is one of the
 * auto-discovery locations (global ~/.pi/agent/extensions or project
 * .pi/extensions). A -e-loaded dev copy inside the workspace is not reserved:
 * hiding the workspace itself would brick the session.
 */
function recordExtensionReservedDir(dir: string): void {
	if (dir.endsWith(`${nodePath.sep}extensions`)) {
		extensionReservedDir = dir;
	}
}

async function initGuard(workspace: string): Promise<GuardState> {
	let rules: GuardState["rules"] = [];
	let loadWarning: string | null = null;
	try {
		const persisted = await loadState(agentDir);
		const project = persisted.projects[workspace];
		if (project) {
			rules = project.rules.map((r): GuardState["rules"][number] => ({
				path: r.path,
				mode: r.mode === "deny" ? AccessMode.Deny : AccessMode.Read,
				logicalPath: r.logicalPath,
				asDirectory: r.asDirectory,
				created: r.created,
			}));
		}
	} catch (err) {
		// Fail closed on policy read: keep reserved protections, drop user
		// rules, and tell the user loudly. The state file itself stays DENY.
		loadWarning =
			`Pi File Guard: guard state could not be loaded (${(err as Error).message}) — ` +
			`user rules are inactive this session; reserved protections remain enforced.`;
		rules = [];
	}

	const reserved: string[] = extensionReservedDir && extensionReservedDir !== workspace ? [extensionReservedDir] : [];
	const state = new GuardState(workspace, agentDir, reserved);
	state.replaceRules(rules);
	currentState = state;

	bwrapOk = await probeBwrapLazy();
	if (loadWarning) console.warn(loadWarning);
	return state;
}
