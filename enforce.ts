/**
 * enforce.ts — file-tool enforcement decisions shared by the Pi `tool_call`
 * guard and integration tests. Pi-free and fs-backed (real canonicalization).
 */

import { buildPathForms } from "./paths.ts";
import { AccessMode, isSameOrAncestor, resolveAccess } from "./policy.ts";
import type { GuardState } from "./state.ts";

export interface ResolvedToolMode {
	mode: AccessMode;
	logical: string;
	canonical: string;
}

/** Effective access for a file-tool path argument (read/write/edit/find/ls). */
export async function resolveFileToolMode(
	inputPath: string,
	cwd: string,
	state: GuardState,
): Promise<ResolvedToolMode> {
	const forms = await buildPathForms(inputPath, cwd);
	const mode = resolveAccess(
		forms.canonical,
		{ workspace: state.workspace, reservedDenyPaths: state.reservedDenyPaths },
		state.rules,
		[forms.canonical, forms.logical],
	);
	return { mode, logical: forms.logical, canonical: forms.canonical };
}

/**
 * True when a grep search rooted at `root` could reach DENY-protected content,
 * either because the root itself is DENY or a DENY rule lives under it
 * (conservative v1 policy: block rather than content-filter).
 */
export async function grepMayReachDeny(rootInput: string, cwd: string, state: GuardState): Promise<boolean> {
	const forms = await buildPathForms(rootInput, cwd);
	const mode = resolveAccess(
		forms.canonical,
		{ workspace: state.workspace, reservedDenyPaths: state.reservedDenyPaths },
		state.rules,
		[forms.canonical, forms.logical],
	);
	if (mode === AccessMode.Deny) return true;
	for (const rule of state.rules) {
		if (rule.mode !== AccessMode.Deny) continue;
		if (isSameOrAncestor(forms.canonical, rule.path)) return true;
		if (rule.logicalPath && isSameOrAncestor(forms.canonical, rule.logicalPath)) return true;
	}
	return false;
}
