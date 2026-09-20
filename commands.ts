/**
 * commands.ts — slash command UX. User-invoked only; no tools are registered
 * for the model, so the model can never mutate policy (section 4: Forbidden).
 *
 * Shortcuts:
 *   /hide PATH        -> DENY override  (name visible, content/modify denied)
 *   /lock PATH        -> READ override  (readable, not modifiable)
 *   /unhide PATH      -> remove override
 *   /unlock PATH      -> remove override
 *
 * Unified:
 *   /guard                     -> show policy
 *   /guard deny PATH
 *   /guard read PATH
 *   /guard reset PATH
 *   /guard list
 */

import { buildPathForms } from "./paths.ts";
import { AccessMode, type GuardRule } from "./policy.ts";
import { cleanupPlaceholder, type GuardState } from "./state.ts";

export type GuardCommandResult = { message: string; error?: boolean };

interface CommandDeps {
	state(): GuardState | null;
	/** Re-read the persisted rules for the current workspace (new session). */
	reload(): Promise<GuardState | null>;
}

/** Notifications per Gate 9. */
export function formatSetMessage(mode: AccessMode, display: string, placeholder?: boolean): string {
	if (mode === AccessMode.Deny) {
		return (
			`DENY ${display}${placeholder ? " (placeholder)" : ""}\n` +
			`Future agent tools and new shell processes cannot read or modify this path.`
		);
	}
	return `READ ${display}${placeholder ? " (placeholder)" : ""}\nThe agent may read this path but cannot modify it.`;
}

export function formatRemoveMessage(display: string): string {
	return `Restored ${display}\nNormal access rules apply again from the next tool or bash invocation.`;
}

export function formatToolBlocked(display: string, mode: AccessMode): string {
	return `Access denied by Pi File Guard: ${display}\nPolicy: ${mode.toUpperCase()}`;
}

export function formatWriteBlocked(display: string, mode: AccessMode): string {
	return `Write denied by Pi File Guard: ${display}\nPolicy: ${mode.toUpperCase()}`;
}

export function parseCommandArgs(args: string): string[] {
	return args.trim().split(/\s+/).filter(Boolean);
}

/**
 * Display form of a path: workspace-relative when inside the workspace,
 * absolute otherwise (matches the Gate 9 UX examples: "/hide .env").
 */
export function displayPath(logical: string, workspace: string): string {
	if (logical === workspace) return ".";
	if (logical.startsWith(workspace.endsWith("/") ? workspace : `${workspace}/`)) {
		return logical.slice(workspace.length).replace(/^\//, "") || logical;
	}
	return logical;
}

/**
 * Set a protection rule (DENY via hide, READ via lock). The whole argument
 * string is the path, so paths with spaces work. Returns a message and the
 * resulting rule. Throws GuardCommandError for user-facing rejections.
 */
export async function applyRule(
	deps: CommandDeps,
	args: string,
	mode: AccessMode.Deny | AccessMode.Read,
): Promise<GuardCommandResult> {
	const state = deps.state();
	if (!state) throw new GuardCommandError("Pi File Guard is not initialized yet");
	const input = args.trim();
	if (input.length === 0) {
		throw new GuardCommandError(
			`Usage: ${mode === AccessMode.Deny ? "/hide" : "/lock"} PATH      (trailing '/' protects a directory)`,
		);
	}
	const forms = await buildPathForms(input, state.workspace);
	if (forms.canonical === state.workspace) {
		throw new GuardCommandError("Refusing to hide or lock the workspace itself");
	}
	const rule: GuardRule = {
		path: forms.canonical,
		mode,
		logicalPath: forms.logical,
		asDirectory: input.endsWith("/"),
	};
	await state.setRule(rule);
	return {
		message: formatSetMessage(mode, displayPath(forms.logical, state.workspace), rule.created),
	};
}

/** Remove a protection rule. Throws GuardCommandError for user-facing errors. */
export async function removeRule(deps: CommandDeps, args: string): Promise<GuardCommandResult> {
	const state = deps.state();
	if (!state) throw new GuardCommandError("Pi File Guard is not initialized yet");
	const input = args.trim();
	if (input.length === 0) throw new GuardCommandError("Usage: /unlock PATH");
	const forms = await buildPathForms(input, state.workspace);
	const removed = await state.removeRule({
		path: forms.canonical,
		logicalPath: forms.logical,
	});
	if (!removed) {
		// Fall back to fuzzy display: the path is not protected.
		throw new GuardCommandError(`No rule found for ${displayPath(forms.logical, state.workspace)}`, {
			notFound: true,
		});
	}
	if (removed.created) {
		await cleanupPlaceholder(removed.path, removed.asDirectory ? "dir" : "file");
	}
	return {
		message: formatRemoveMessage(displayPath(removed.logicalPath ?? removed.path, state.workspace)),
	};
}

/** Unified /guard handler. */
export async function guardCommand(deps: CommandDeps, args: string): Promise<GuardCommandResult> {
	const state = deps.state();
	if (!state) {
		// Attempt a reload (session may not have started the guard yet).
		const reloaded = await deps.reload();
		if (!reloaded) throw new GuardCommandError("Pi File Guard is not initialized yet");
		return { message: reloaded.describe() };
	}
	const tokens = parseCommandArgs(args);
	if (tokens.length === 0 || tokens[0] === "list") {
		return { message: state.describe() };
	}
	const sub = tokens[0];
	const rest = args.trim().slice(sub.length).trim();
	if (sub === "deny" || sub === "hide") {
		return applyRule(deps, rest, AccessMode.Deny);
	}
	if (sub === "read" || sub === "lock") {
		return applyRule(deps, rest, AccessMode.Read);
	}
	if (sub === "reset" || sub === "unhide" || sub === "unlock") {
		return removeRule(deps, rest);
	}
	throw new GuardCommandError(`Unknown /guard subcommand: ${sub}\nUsage: /guard [deny|read|reset PATH | list]`);
}

/** User-facing error carrying an optional structured hint. */
export class GuardCommandError extends Error {
	constructor(
		message: string,
		readonly meta: { notFound?: boolean } = {},
	) {
		super(message);
		this.name = "GuardCommandError";
	}
}
