/**
 * policy.ts — Pi File Guard three-state filesystem policy.
 *
 * The single source of truth for access decisions. Pure logic, no fs access,
 * no Pi imports, no bwrap imports — unit-testable in isolation (Gate 1).
 *
 * Model (mirrors the Codex filesystem permission abstraction):
 *
 *   Deny  -> pathname may be observable, content and modification unavailable
 *   Read  -> content readable, modification unavailable
 *   Write -> readable and writable (default inside the workspace)
 *
 * Baseline (Codex style):
 *   /              -> READ
 *   <workspace>    -> WRITE
 *   reserved paths -> DENY (always, cannot be overridden)
 *
 * User rules (only Deny/Read are user-settable) overlay the baseline with
 * strict precedence: DENY > READ > baseline. v1 has no "reopen child" rule:
 * DENY ancestors dominate descendants; READ ancestors prevent descendant
 * writes (section 5.7).
 */

export enum AccessMode {
	Deny = "deny",
	Read = "read",
	Write = "write",
}

/**
 * A user-defined protection rule.
 *
 * `path` is the canonical (realpath-resolved) filesystem path — the one
 * enforcement backends bind against.
 *
 * `logicalPath` is the normalized-but-not-symlink-resolved form the user
 * typed (/workspace/link for a symlink pointing at /tmp/secret). Policy
 * evaluation matches against both so a symlink alias cannot walk around a
 * rule (section 5.6, Gate 5).
 *
 * `created` marks placeholder files/dirs the guard created on disk so the
 * sandbox can mask a target that did not exist yet; /unlock may remove them
 * again when they are still empty.
 */
export interface GuardRule {
	path: string;
	mode: AccessMode.Deny | AccessMode.Read;
	logicalPath?: string;
	/** Trailing-slash directory intent from the user's input. */
	asDirectory?: boolean;
	/** Placeholder file/dir the guard created so a missing target could be masked. */
	created?: boolean;
}

export interface PolicyContext {
	/** Canonical workspace path. Inside it the baseline is WRITE. */
	workspace: string;
	/** Hard-coded deny paths (state file, mask dir, extension dir). Always DENY. */
	reservedDenyPaths: string[];
}

/** String form used in error messages and command output. */
export function modeLabel(mode: AccessMode): string {
	return mode === AccessMode.Deny ? "DENY" : mode === AccessMode.Read ? "READ" : "WRITE";
}

const ORDER: Record<AccessMode, number> = {
	[AccessMode.Deny]: 0,
	[AccessMode.Read]: 1,
	[AccessMode.Write]: 2,
};

function stricter(a: AccessMode, b: AccessMode): AccessMode {
	return ORDER[a] <= ORDER[b] ? a : b;
}

/**
 * Does `parent` equal `child` or is it an ancestor of `child`?
 * Both inputs must be absolute, normalized, and free of trailing slashes
 * (except root "/").
 */
export function isSameOrAncestor(parent: string, child: string): boolean {
	if (parent === child) return true;
	if (parent === "/") return child.startsWith("/") && child !== "";
	if (child === "/") return false;
	return child.startsWith(parent.endsWith("/") ? parent : `${parent}/`);
}

/**
 * Applies a single rule against every candidate form of an input path.
 * A rule matches when its canonical path is the same-or-ancestor of any
 * candidate form, or its logical path is the same-or-ancestor of any
 * candidate form.
 */
function ruleAppliesTo(rule: GuardRule, candidateForms: string[]): boolean {
	const targets = [rule.path];
	if (rule.logicalPath && rule.logicalPath !== rule.path) targets.push(rule.logicalPath);
	for (const target of targets) {
		for (const form of candidateForms) {
			if (isSameOrAncestor(target, form)) return true;
		}
	}
	return false;
}

/**
 * Resolve the effective access mode for `inputPath`.
 *
 * `inputPath` should already be normalized to an absolute path; pass both the
 * logical form (normalized, symlinks unresolved) and the canonical form
 * (realpath) via `candidateForms` when the caller has both available. If only
 * one form is supplied the other is derived from it.
 *
 * Precedence: reserved DENY > user DENY > user READ > workspace WRITE > READ.
 */
export function resolveAccess(
	inputPath: string,
	context: PolicyContext,
	rules: GuardRule[],
	candidateForms?: string[],
): AccessMode {
	const forms = candidateForms && candidateForms.length > 0 ? [...new Set(candidateForms)] : [inputPath];

	// 1. Hard-coded self-protection always wins.
	for (const reserved of context.reservedDenyPaths) {
		for (const form of forms) {
			if (isSameOrAncestor(reserved, form)) return AccessMode.Deny;
		}
	}

	// 2. Most restrictive matching user rule.
	let effective: AccessMode | undefined;
	for (const rule of rules) {
		if (!ruleAppliesTo(rule, forms)) continue;
		effective = effective === undefined ? rule.mode : stricter(effective, rule.mode);
	}
	if (effective !== undefined) return effective;

	// 3. Baseline.
	for (const form of forms) {
		if (isSameOrAncestor(context.workspace, form)) return AccessMode.Write;
	}

	// Workspace itself being the filesystem root or outside the workspace.
	if (context.workspace === "/") return AccessMode.Write;
	return AccessMode.Read;
}

/** Short description of the complete effective state, used by /guard. */
export function describeRules(workspace: string, rules: GuardRule[], reservedDenyPaths: string[]): string {
	const deny = rules.filter((r) => r.mode === AccessMode.Deny);
	const read = rules.filter((r) => r.mode === AccessMode.Read);
	const show = (r: GuardRule) =>
		`${displayIn(workspace, r.logicalPath ?? r.path)}${r.created ? " (placeholder)" : ""}`;
	const lines = [`Workspace: ${workspace}`, ``, `Baseline: filesystem READ, workspace WRITE`];
	lines.push(``, `DENY:`);
	if (deny.length > 0) {
		for (const r of deny) lines.push(`  ${show(r)}`);
	} else {
		lines.push(`  (none)`);
	}
	lines.push(``, `READ:`);
	if (read.length > 0) {
		for (const r of read) lines.push(`  ${show(r)}`);
	} else {
		lines.push(`  (none)`);
	}
	lines.push(``, `Reserved deny paths (always enforced):`);
	for (const reserved of reservedDenyPaths) lines.push(`  ${reserved}`);
	return lines.join("\n");
}

/** Workspace-relative display for a path (used by describeRules). */
function displayIn(workspace: string, p: string): string {
	const prefix = workspace === "/" ? "/" : `${workspace}/`;
	if (p === workspace) return ".";
	if (p.startsWith(prefix)) return p.slice(prefix.length);
	return p;
}
