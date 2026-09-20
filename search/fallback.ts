/**
 * search/fallback.ts — conservative search fallback (v2 §5.12).
 *
 * Used ONLY when the sandboxed native backend cannot initialize (bwrap
 * missing, fd/rg binary missing). The rule: the host Pi find/grep tool may
 * run unsandboxed ONLY when the whole search tree is provably DENY-free —
 * an unsandboxed search that could reach DENY content is refused outright,
 * never filtered afterwards.
 */

import { AccessMode, isSameOrAncestor } from "../policy.ts";
import type { PermissionSnapshot } from "../state.ts";

/**
 * True when the search tree rooted at `searchRoot` contains any DENY path
 * (root itself or a descendant), including reserved deny paths.
 */
export function treeCarriesDeny(searchRoot: string, snapshot: PermissionSnapshot): boolean {
	for (const rule of snapshot.rules) {
		if (rule.mode !== AccessMode.Deny) continue;
		if (isSameOrAncestor(searchRoot, rule.path)) return true;
	}
	for (const reserved of snapshot.reservedDenyPaths) {
		if (isSameOrAncestor(searchRoot, reserved)) return true;
	}
	return false;
}

export function fallbackBlockedMessage(): string {
	return (
		"Pi File Guard: this search tree contains DENY-protected paths and the sandboxed " +
		"search backend is unavailable. Refusing to run an unsandboxed search. " +
		"Install bubblewrap and fd/ripgrep, then restart pi."
	);
}
