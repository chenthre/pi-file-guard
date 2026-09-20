/**
 * search/excludes.ts — OPTIONAL traversal optimization (v2 Gate 5).
 *
 * Turns DENY rules that live under the search root into fd/rg exclusion
 * arguments. Purpose: avoid pointless opens/stat traversal of paths that the
 * bwrap filesystem view already makes inaccessible, cutting permission-error
 * noise and improving traversal performance.
 *
 * This is NOT a security boundary. Exclusions are purely subtractive: bugs
 * here can only hide MORE results or produce more noise, never reveal DENY
 * content. The security enforcement is the shared bwrap filesystem view.
 * Tests explicitly disable excludes and prove DENY remains enforced (v2 5.8).
 */

import nodePath from "node:path";
import { AccessMode, type GuardRule, isSameOrAncestor } from "../policy.ts";

export interface SearchExcludePlan {
	/** Relative (to searchRoot) `--exclude` patterns for fd. */
	fdExcludes: string[];
	/** `--glob '!pattern'` patterns for rg. */
	rgGlobNegations: string[];
}

/**
 * Compute exclude patterns for DENY rules that are same-or-descendants of
 * `searchRoot`. Rules pointing elsewhere are ignored (not under traversal;
 * bwrap still protects them if they are reached another way).
 */
export function buildSearchExcludes(searchRoot: string, rules: GuardRule[]): SearchExcludePlan {
	const fdExcludes: string[] = [];
	const rgGlobNegations: string[] = [];

	for (const rule of rules) {
		if (rule.mode !== AccessMode.Deny) continue;
		// Protect against non-canonical searchRoot forms.
		const root = nodePath.normalize(searchRoot);
		const rulePath = nodePath.normalize(rule.path);
		if (!isSameOrAncestor(root, rulePath)) continue;

		const rel = nodePath.relative(root, rulePath);
		if (!rel) continue; // the root itself is DENY — caller blocks separately
		const isDir = Boolean(rule.asDirectory);

		// fd: --exclude matches path components relative to the search root.
		// A dir gets 'name' (fd prunes it entirely); a file gets its rel path.
		if (isDir) {
			const top = rel.split(nodePath.sep)[0];
			if (top) fdExcludes.push(`./${top}`);
		} else {
			fdExcludes.push(`./${rel}`);
		}

		// rg: negated globs. Files: exact relative pattern. Dirs: everything
		// beneath (rg globs have no directory-exclusion, so deny the tree).
		if (isDir) {
			rgGlobNegations.push(`!${rel}/**`);
		}
		rgGlobNegations.push(`!${rel}`);
	}

	return {
		fdExcludes: [...new Set(fdExcludes)],
		rgGlobNegations: [...new Set(rgGlobNegations)],
	};
}
