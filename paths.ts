/**
 * paths.ts — path normalization, canonicalization and symlink handling.
 *
 * Never compare raw input strings (section 5.6). Every path that enters the
 * policy engine or the bwrap compiler is first normalized to an absolute
 * logical form, then canonicalized through realpath() with a fail-closed
 * fallback for paths that do not exist yet (the deepest existing ancestor is
 * resolved and the remainder appended).
 *
 * Symlink handling (Gate 5): rules record both the logical path typed by the
 * user and the canonical target. This module provides the pieces; state.ts
 * stores both forms per rule.
 */

import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import nodePath from "node:path";

const HOME = homedir();

/** True for absolute Unix paths (/foo, /, //foo). */
export function isAbsolute(p: string): boolean {
	return p.startsWith("/");
}

/**
 * Normalize a raw user-supplied path into an absolute, dot-free logical form.
 *
 * Handles: `~` / `$HOME`, leading `@` (built-in tools accept @-prefixed paths),
 * relative paths against `cwd`, `.` and `..`, repeated and trailing slashes.
 * Does NOT follow symlinks.
 */
export function normalizeInputPath(input: string, cwd: string): string {
	let p = input.trim();
	if (p.length === 0) return cwd;
	// Built-in tools strip a leading '@' before resolving (model habit).
	if (p.startsWith("@")) p = p.slice(1);
	if (p === "~") p = HOME;
	else if (p.startsWith("~/")) p = HOME + p.slice(1);
	else if (!isAbsolute(p)) p = nodePath.join(cwd, p);
	return normalizeAbsolute(p);
}

/** Remove trailing slashes, collapse `.`/`..`/`//` for an absolute path. */
export function normalizeAbsolute(p: string): string {
	const sep = "/";
	const isRoot = p === sep;
	const trailing = p.length > 1 && p.endsWith(sep);
	let normalized = nodePath.normalize(p);
	if (normalized === "") normalized = "/";
	if (trailing && normalized.length > 1) normalized = normalized.replace(/\/+$/, "");
	if (!isRoot && normalized.endsWith(sep)) normalized = normalized.replace(/\/+$/, "");
	return isRoot ? sep : normalized;
}

/**
 * Canonicalize a path: resolve symlinks all the way down. When the path does
 * not exist, resolve the deepest existing ancestor and append the remainder —
 * this keeps near-miss targets deterministic instead of failing (section 5.8:
 * canonicalization ambiguity must never silently allow).
 *
 * Fail-closed contract from the caller's perspective: if `realpath` throws for
 * something other than ENOENT (e.g. permission denied or a broken loop),
 * the error propagates — the caller must deny the operation.
 */
export async function canonicalizePath(p: string): Promise<string> {
	const absolute = normalizeAbsolute(p);
	try {
		return await realpath(absolute);
	} catch (err) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code !== "ENOENT" && code !== "ENOTDIR") throw err;
		// Find deepest existing ancestor.
		let current = absolute;
		const tail: string[] = [];
		for (;;) {
			try {
				const resolved = await realpath(current);
				return normalizeAbsolute(nodePath.join(resolved, ...tail));
			} catch (err2) {
				const code2 = (err2 as NodeJS.ErrnoException).code;
				if (code2 !== "ENOENT" && code2 !== "ENOTDIR") throw err2;
				const base = nodePath.basename(current);
				if (base === "" || base === current) {
					throw new Error(`Cannot canonicalize path: ${p}`);
				}
				tail.unshift(base);
				current = nodePath.dirname(current);
			}
		}
	}
}

/**
 * stat()-free "is this path likely a directory" hint from the input string.
 * Only used to decide the placeholder type for missing targets.
 */
export function hasTrailingSeparator(p: string): boolean {
	return p.length > 1 && p.endsWith("/");
}

export interface PathForms {
	/** Logical normalized absolute path (symlinks unresolved). */
	logical: string;
	/** Canonical path (symlinks resolved, missing tail appended). */
	canonical: string;
	/** Whether the target existed at canonicalization time. */
	existed: boolean;
}

/**
 * Build the two forms used throughout enforcement: logical + canonical.
 * Callers pass both to resolveAccess() and to the bwrap mount compiler.
 */
export async function buildPathForms(inputPath: string, cwd: string): Promise<PathForms> {
	const logical = normalizeInputPath(inputPath, cwd);
	const canonical = await canonicalizePath(logical);
	// Existence probe on the canonical final component (lstat, no follow —
	// a dangling symlink counts as not-yet-existing for masking purposes).
	let existed = true;
	try {
		await lstat(canonical);
	} catch {
		existed = false;
	}
	return { logical, canonical, existed };
}

export { nodePath as path };
