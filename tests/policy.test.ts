/**
 * policy.test.ts — PolicyEngine semantics (Gate 1, AC2).
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import {
	AccessMode,
	describeRules,
	type GuardRule,
	isSameOrAncestor,
	type PolicyContext,
	resolveAccess,
} from "../policy.ts";

const WS = "/home/me/proj";
const RESERVED = ["/home/me/.pi/agent/file-guard.json", "/home/me/.pi/agent/file-guard"];

function ctx(workspace: string = WS, reserved: string[] = RESERVED): PolicyContext {
	return { workspace, reservedDenyPaths: reserved };
}

function rule(path: string, mode: AccessMode.Deny | AccessMode.Read, logicalPath?: string): GuardRule {
	return { path, mode, logicalPath: logicalPath ?? path };
}

test("baseline: workspace file → WRITE", () => {
	assert.equal(resolveAccess("/home/me/proj/src/a.ts", ctx(), []), AccessMode.Write);
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), []), AccessMode.Write);
});

test("baseline: outside workspace → READ", () => {
	assert.equal(resolveAccess("/etc/hosts", ctx(), []), AccessMode.Read);
	assert.equal(resolveAccess("/home/me/other/file", ctx(), []), AccessMode.Read);
});

test("reserved paths are DENY regardless of workspace", () => {
	for (const p of RESERVED) {
		assert.equal(resolveAccess(p, ctx(), []), AccessMode.Deny);
	}
	assert.equal(resolveAccess("/home/me/.pi/agent/file-guard.json", ctx(), []), AccessMode.Deny);
	assert.equal(resolveAccess("/home/me/.pi/agent/file-guard/deny-x.mask", ctx(), []), AccessMode.Deny);
	// The agent dir above them is listable (pathname visibility), not protected.
	assert.equal(resolveAccess("/home/me/.pi/agent", ctx(), []), AccessMode.Read);
});

test("reserved paths beat user rules", () => {
	const rules = [rule("/home/me/.pi/agent", AccessMode.Read)]; // attempted downgrade
	assert.equal(resolveAccess("/home/me/.pi/agent/file-guard.json", ctx(), rules), AccessMode.Deny);
});

test("lock file → READ (readable, not writable)", () => {
	const rules = [rule("/home/me/proj/prod.json", AccessMode.Read)];
	assert.equal(resolveAccess("/home/me/proj/prod.json", ctx(), rules), AccessMode.Read);
	assert.equal(resolveAccess("/home/me/proj/other", ctx(), rules), AccessMode.Write);
});

test("hide file → DENY", () => {
	const rules = [rule("/home/me/proj/.env", AccessMode.Deny)];
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), rules), AccessMode.Deny);
});

test("hide dir → descendants DENY (AC7 recursion)", () => {
	const rules = [rule("/home/me/proj/secrets", AccessMode.Deny)];
	assert.equal(resolveAccess("/home/me/proj/secrets", ctx(), rules), AccessMode.Deny);
	assert.equal(resolveAccess("/home/me/proj/secrets/a", ctx(), rules), AccessMode.Deny);
	assert.equal(resolveAccess("/home/me/proj/secrets/foo/bar/baz", ctx(), rules), AccessMode.Deny);
	// sibling unaffected
	assert.equal(resolveAccess("/home/me/proj/secrets2", ctx(), rules), AccessMode.Write);
});

test("lock dir → descendants READ", () => {
	const rules = [rule("/home/me/proj/config", AccessMode.Read)];
	assert.equal(resolveAccess("/home/me/proj/config/x.json", ctx(), rules), AccessMode.Read);
});

test("DENY ancestor dominates READ descendant (no child reopen in v1)", () => {
	const rules = [rule("/home/me/proj/a", AccessMode.Deny), rule("/home/me/proj/a/b", AccessMode.Read)];
	assert.equal(resolveAccess("/home/me/proj/a/b/c", ctx(), rules), AccessMode.Deny);
});

test("... traversal normalization is handled before resolveAccess (input forms)", () => {
	const rules = [rule("/home/me/proj/.env", AccessMode.Deny)];
	// Callers normalize input first (paths.ts), so candidate forms are already
	// dot-free; a raw ./.. form is a different string and not an ancestor
	// match, which is exactly why normalization precedes evaluation.
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), rules, ["/home/me/proj/.env"]), AccessMode.Deny);
	const raw = "/home/me/proj/./.env";
	const form = normalizeForTest(raw);
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), rules, [form]), AccessMode.Deny);
});

/** Stand-in for paths.normalizeInputPath used by enforcement callers. */
function normalizeForTest(p: string): string {
	return p.replace(/\/\.\//g, "/");
}

test("symlink logical path matches rule on canonical path", () => {
	const rules = [rule("/tmp/real-secret", AccessMode.Deny)];
	// Accessing the alias /home/me/proj/link that resolves to /tmp/real-secret
	assert.equal(
		resolveAccess("/tmp/real-secret", ctx(), rules, ["/home/me/proj/link", "/tmp/real-secret"]),
		AccessMode.Deny,
	);
	// And the direct path too (Gate 5 reverse direction)
	assert.equal(
		resolveAccess("/home/me/proj/link", ctx(), rules, ["/home/me/proj/link", "/tmp/real-secret"]),
		AccessMode.Deny,
	);
});

test("rule on the symlink's logical path protects the canonical target", () => {
	// /hide workspace/link where link -> /tmp/real-secret
	const rules = [rule("/tmp/real-secret", AccessMode.Deny, "/home/me/proj/link")];
	assert.equal(resolveAccess("/tmp/real-secret", ctx(), rules, ["/tmp/real-secret"]), AccessMode.Deny);
	assert.equal(resolveAccess("/home/me/proj/link", ctx(), rules, ["/home/me/proj/link"]), AccessMode.Deny);
});

test("duplicate rules: most restrictive wins", () => {
	const rules = [rule("/home/me/proj/.env", AccessMode.Read), rule("/home/me/proj/.env", AccessMode.Deny)];
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), rules), AccessMode.Deny);
});

test("removing a rule restores baseline", () => {
	const rules: GuardRule[] = [rule("/home/me/proj/.env", AccessMode.Deny)];
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), rules), AccessMode.Deny);
	const without = rules.filter((r) => r.path !== "/home/me/proj/.env");
	assert.equal(resolveAccess("/home/me/proj/.env", ctx(), without), AccessMode.Write);
});

test("root workspace path itself is WRITE; its parent is READ", () => {
	assert.equal(resolveAccess("/home/me/proj", ctx(), []), AccessMode.Write);
	assert.equal(resolveAccess("/home/me", ctx(), []), AccessMode.Read);
});

test("paths with trailing slashes and siblings are handled", () => {
	const rules = [rule("/home/me/proj/secrets", AccessMode.Deny)];
	assert.equal(resolveAccess("/home/me/proj/secrets/", ctx(), rules, ["/home/me/proj/secrets/"]), AccessMode.Deny);
	assert.equal(resolveAccess("/home/me/proj/secre", ctx(), rules), AccessMode.Write); // prefix sibling
});

test("isSameOrAncestor edge cases", () => {
	assert.equal(isSameOrAncestor("/a/b", "/a/b"), true);
	assert.equal(isSameOrAncestor("/a/b", "/a/b/c"), true);
	assert.equal(isSameOrAncestor("/a/b", "/a/bc"), false);
	assert.equal(isSameOrAncestor("/", "/anything"), true);
	assert.equal(isSameOrAncestor("/anything", "/"), false);
});

test("describeRules lists sections and reserved paths", () => {
	const out = describeRules(WS, [rule("/home/me/proj/.env", AccessMode.Deny)], RESERVED);
	assert.match(out, /DENY:/);
	assert.match(out, /\.env/);
	assert.match(out, /Reserved deny paths/);
	assert.match(out, /file-guard\.json/);
});
