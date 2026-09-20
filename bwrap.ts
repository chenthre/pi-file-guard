/**
 * bwrap.ts — bubblewrap filesystem policy compiler (v2: compiler-only).
 *
 * THE single filesystem security backend: bash, fd and rg all receive their
 * mount arguments from compileSandboxArgs(snapshot) — no per-tool security
 * rule sets exist (v2 section 5.2). Process execution lives in
 * sandbox-process.ts.
 *
 * Mount layering (order is security-critical):
 *
 *   1. --ro-bind / /            RO baseline (whole filesystem READ)
 *   2. --dev /dev --proc /proc   device/proc filesystems
 *   3. --tmpfs /tmp              writable scratch
 *   4. --bind WORKSPACE WORKSPACE   WRITE workspace
 *   5. READ (lock) overlays: --ro-bind TARGET TARGET — after the workspace
 *      bind, otherwise the RW workspace mount would cover the protection
 *   6. DENY overlays (strictest last):
 *        file -> --ro-bind <000 mask file> TARGET (open => EACCES)
 *        dir  -> --perms 000 --tmpfs TARGET      (open/list/write => EACCES)
 *   7. --cap-drop ALL so CAP_DAC_OVERRIDE cannot defeat 000 masks
 *
 * Fail closed: any error while assembling (mask build failure, unsupported
 * target, workspace unusable) throws; the caller refuses the invocation.
 */

import { type ChildProcess, spawn as nodeSpawn } from "node:child_process";
import { chmod, lstat, mkdir, stat, writeFile } from "node:fs/promises";
import nodePath from "node:path";
import { hasTrailingSeparator, normalizeAbsolute } from "./paths.ts";
import { AccessMode } from "./policy.ts";
import { ensureMaskableTarget, maskFilePath, type PermissionSnapshot, stableHash } from "./state.ts";

export const BWRAP_BIN = "bwrap";

export interface BwrapTarget {
	/** Canonical path of the protected target. */
	path: string;
	/** User-facing logical path for diagnostics. */
	logicalPath?: string;
	mode: AccessMode.Deny | AccessMode.Read;
	/** Explicit directory intent (trailing slash in the user's input). */
	asDirectory?: boolean;
}

export interface BwrapCompileOptions {
	workspace: string;
	rules: BwrapTarget[];
	/** Reserved deny paths (state file, runtime dir, extension dir). */
	reserved: BwrapTarget[];
	/** Directory that will hold the generated mask files. */
	runtimeDir: string;
}

export interface CompiledBwrap {
	/** Full bwrap mount arguments (before `--`). */
	sandboxArgs: string[];
	/** Placeholder paths created so targets could be masked. */
	createdPlaceholders: { target: string; type: "file" | "dir" }[];
}

export class BwrapError extends Error {
	constructor(
		message: string,
		readonly cause?: unknown,
	) {
		super(message);
		this.name = "BwrapError";
	}
}

/** Probe bubblewrap + user namespaces once. Throws BwrapError when unusable. */
export async function assertBwrapAvailable(): Promise<void> {
	const probe = await probeBwrap();
	if (!probe.ok) {
		throw new BwrapError(
			`bubblewrap is not available or cannot create user namespaces: ${probe.reason}\n` +
				`Pi File Guard fails closed — bash and native search tools will refuse to run unsandboxed.\n` +
				`Install bubblewrap (e.g. apt install bubblewrap) and enable unprivileged\n` +
				`user namespaces, then restart pi.`,
		);
	}
}

async function probeBwrap(): Promise<{ ok: true } | { ok: false; reason: string }> {
	try {
		const { code, error } = await runBwrapProbe();
		if (error) return { ok: false, reason: error.message };
		if (code !== 0) return { ok: false, reason: `probe exited with code ${code}` };
		return { ok: true };
	} catch (err) {
		return { ok: false, reason: (err as Error).message };
	}
}

function runBwrapProbe(): Promise<{ error?: Error; code: number | null }> {
	return new Promise((resolve) => {
		let child: ChildProcess;
		try {
			child = spawnBwrapForProbe();
		} catch (err) {
			resolve({ error: err as Error, code: null });
			return;
		}
		child.on("error", (err) => resolve({ error: err, code: null }));
		child.on("close", (code) => resolve({ code }));
	});
}

function spawnBwrapForProbe(): ChildProcess {
	return nodeSpawn(BWRAP_BIN, ["--die-with-parent", "--unshare-user", "--ro-bind", "/", "/", "--", "/bin/true"], {
		stdio: "ignore",
	});
}

async function pathKind(p: string): Promise<"file" | "dir" | "missing"> {
	try {
		const st = await lstat(p);
		if (st.isDirectory()) return "dir";
		if (st.isFile()) return "file";
		return "missing";
	} catch {
		return "missing";
	}
}

// Parallel tool invocations compile sandboxes concurrently; mask creation
// must be serialized per path or a 000-mode file created by one run makes the
// other's write fail with EACCES.
const pendingMasks = new Map<string, Promise<void>>();

function ensureMaskFile(mask: string): Promise<void> {
	const pending = pendingMasks.get(mask);
	if (pending) return pending;
	const promise = doEnsureMaskFile(mask).finally(() => pendingMasks.delete(mask));
	pendingMasks.set(mask, promise);
	return promise;
}

async function doEnsureMaskFile(mask: string): Promise<void> {
	try {
		await stat(mask);
		return;
	} catch {
		// create below
	}
	await mkdir(nodePath.dirname(mask), { recursive: true });
	await writeFile(mask, "", { mode: 0o000 });
	await chmod(mask, 0o000);
}

/**
 * Build the full bwrap argv for one process invocation from a policy
 * snapshot. Snapshot changes across invocations => always a fresh namespace.
 */
export async function compileSandboxArgs(snapshot: PermissionSnapshot): Promise<CompiledBwrap> {
	return compileBwrapArgs({
		workspace: snapshot.workspace,
		rules: snapshot.rules.map((r) => ({
			path: r.path,
			logicalPath: r.logicalPath,
			mode: r.mode as AccessMode.Deny | AccessMode.Read,
			asDirectory: r.asDirectory,
		})),
		reserved: reservedTargetsFromSnapshot(snapshot),
		runtimeDir: snapshot.runtimeDir,
	});
}

/** Reserved paths from a snapshot as compiler targets (state file = file). */
export function reservedTargetsFromSnapshot(snapshot: PermissionSnapshot): BwrapTarget[] {
	return snapshot.reservedDenyPaths.map((p) => ({
		path: p,
		mode: AccessMode.Deny as const,
		asDirectory: p !== snapshot.stateFile,
	}));
}

/** Build the full bwrap argv for one command execution from a policy snapshot. */
export async function compileBwrapArgs(options: BwrapCompileOptions): Promise<CompiledBwrap> {
	const workspace = normalizeAbsolute(options.workspace);
	if (workspace === "/") {
		throw new BwrapError("Refusing to guard a workspace that is the filesystem root");
	}

	await mkdir(options.runtimeDir, { recursive: true });

	const args: string[] = [
		"--die-with-parent",
		"--new-session",
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind",
		"/",
		"/",
		"--dev",
		"/dev",
		"--proc",
		"/proc",
		"--tmpfs",
		"/tmp",
	];

	// 4. Writable workspace.
	if ((await pathKind(workspace)) !== "dir") {
		throw new BwrapError(`Workspace is not a directory: ${workspace}`);
	}
	args.push("--bind", workspace, workspace);

	const createdPlaceholders: { target: string; type: "file" | "dir" }[] = [];

	const addReadOverlay = async (target: BwrapTarget) => {
		const kind = await pathKind(target.path);
		if (kind === "missing") {
			// Fail closed is about DENY; a READ target that does not exist yet
			// gets an empty placeholder so the name stays read-only.
			const { created, type } = await ensureMaskableTarget(
				target.path,
				target.asDirectory ?? hasTrailingSeparator(target.logicalPath ?? target.path),
				AccessMode.Read,
			);
			if (created) createdPlaceholders.push({ target: target.path, type });
		}
		// Self read-only bind: readable, and the read-only mount blocks
		// chmod/unlink/rename-over regardless of inode ownership.
		args.push("--ro-bind", target.path, target.path);
	};

	const addDenyOverlay = async (target: BwrapTarget, reserved: boolean) => {
		const kind = await pathKind(target.path);
		if (kind === "missing") {
			if (reserved) {
				// Reserved paths (state file, runtime dir, extension dir) are
				// host-managed — NEVER materialize or chmod them on the host
				// (that would break the guard's own storage). Inside the
				// sandbox their parents are read-only (outside the workspace),
				// so the agent cannot create them either: nothing to mask.
				return;
			}
			const { created, type } = await ensureMaskableTarget(
				target.path,
				target.asDirectory ?? hasTrailingSeparator(target.logicalPath ?? target.path),
				AccessMode.Deny,
			);
			if (created) createdPlaceholders.push({ target: target.path, type });
		}
		if ((await pathKind(target.path)) === "dir") {
			// Empty tmpfs with 000 perms: name visible at the parent, but
			// open/list/write/rename of the dir itself all fail (EACCES).
			args.push("--perms", "000", "--tmpfs", target.path);
		} else {
			const mask = maskFilePath(options.runtimeDir, stableHash(target.path));
			await ensureMaskFile(mask);
			args.push("--ro-bind", mask, target.path);
		}
	};

	// READ (lock) overlays.
	for (const target of sortByDepth(options.rules.filter((r) => r.mode === AccessMode.Read))) {
		await addReadOverlay(target);
	}

	// DENY overlays — strictest last.
	for (const target of sortByDepth(options.rules.filter((r) => r.mode === AccessMode.Deny))) {
		await addDenyOverlay(target, false);
	}

	// Reserved deny paths (state file, runtime dir, extension dir).
	for (const target of sortByDepth(options.reserved)) {
		await addDenyOverlay(target, true);
	}

	// 7. Drop all capabilities.
	args.push("--cap-drop", "ALL");

	return { sandboxArgs: args, createdPlaceholders };
}

export { sortByDepth };

/** Sort protected paths deepest-first so child overlays win in bwrap order. */
function sortByDepth(targets: BwrapTarget[]): BwrapTarget[] {
	return [...targets].sort((a, b) => b.path.length - a.path.length);
}
