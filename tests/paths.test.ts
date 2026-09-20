/**
 * paths.test.ts — normalization and canonicalization (Gate 5, section 5.6).
 */

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { test } from "node:test";
import { buildPathForms, canonicalizePath, normalizeInputPath } from "../paths.ts";

const CWD = "/work/proj";

test("normalize: relative, .., dots, tilde, @, trailing slash", () => {
	assert.equal(normalizeInputPath("./foo", CWD), "/work/proj/foo");
	assert.equal(normalizeInputPath("foo/../bar", CWD), "/work/proj/bar");
	assert.equal(normalizeInputPath("../up", "/work/proj"), "/work/up");
	assert.equal(normalizeInputPath(".", CWD), "/work/proj");
	assert.equal(normalizeInputPath("@file", CWD), "/work/proj/file"); // @ habit (matches pi: strip then resolve)
	assert.equal(normalizeInputPath("@/file", CWD), "/file"); // matches pi semantics
	assert.equal(normalizeInputPath("~/x", "/work"), nodePath.join(process.env.HOME ?? "/root", "x"));
	assert.equal(normalizeInputPath("secrets/", CWD), "/work/proj/secrets");
	assert.equal(normalizeInputPath("", CWD), CWD);
});

test("normalize: absolute paths pass through", () => {
	assert.equal(normalizeInputPath("/etc/hosts", CWD), "/etc/hosts");
	assert.equal(normalizeInputPath("/a/b/../c/", CWD), "/a/c");
});

test("canonicalize: follows symlinks (Gate 5)", async () => {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-paths-"));
	try {
		writeFileSync(nodePath.join(dir, "real"), "secret");
		symlinkSync(nodePath.join(dir, "real"), nodePath.join(dir, "link"));
		const canon = await canonicalizePath(nodePath.join(dir, "link"));
		assert.equal(canon, nodePath.join(dir, "real"));
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("canonicalize: missing path resolves through existing ancestor", async () => {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-paths-"));
	try {
		mkdirSync(nodePath.join(dir, "existing"));
		const canon = await canonicalizePath(nodePath.join(dir, "existing", "a", "b.txt"));
		assert.equal(canon, nodePath.join(dir, "existing", "a", "b.txt"));
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("canonicalize: workspace symlink resolves (workspace identity)", async () => {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-paths-"));
	try {
		const real = nodePath.join(dir, "realws");
		mkdirSync(real);
		const link = nodePath.join(dir, "ws-link");
		symlinkSync(real, link);
		assert.equal(await canonicalizePath(link), real);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("buildPathForms: forms + existed flag", async () => {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-paths-"));
	try {
		mkdirSync(nodePath.join(dir, "sub"));
		writeFileSync(nodePath.join(dir, "sub", "f"), "x");
		const existing = await buildPathForms("sub/f", dir);
		assert.equal(existing.logical, nodePath.join(dir, "sub", "f"));
		assert.equal(existing.existed, true);
		const missing = await buildPathForms("sub/nope.txt", dir);
		assert.equal(missing.existed, false);
		assert.equal(missing.canonical, nodePath.join(dir, "sub", "nope.txt"));
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("buildPathForms: symlink to outside workspace (Gate 5 alias)", async () => {
	const dir = mkdtempSync(nodePath.join(tmpdir(), "guard-paths-"));
	try {
		mkdirSync(nodePath.join(dir, "ws"));
		const target = nodePath.join(dir, "outside-secret");
		writeFileSync(target, "s");
		symlinkSync(target, nodePath.join(dir, "ws", "alias"));
		const forms = await buildPathForms("ws/alias", dir);
		assert.equal(forms.canonical, target);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
