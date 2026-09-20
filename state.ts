/**
 * state.ts — GuardState, persistence, reserved deny paths, atomic writes.
 *
 * GuardState is the control plane (section 5.4). Bash subprocesses and the
 * model never hold write authority over it; only the host extension (slash
 * commands) mutates it. Rules live in Pi process memory, with an atomic,
 * project-keyed JSON file as durable storage.
 *
 * Self-protection (section 5.5, Gate 6): the state file and the extension's
 * internal runtime directory are hard-coded reserved deny paths — never
 * derived from the state file's own contents.
 */

import { chmod, mkdir, open, readdir, readFile, rename, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import nodePath, { join } from "node:path";
import { normalizeAbsolute } from "./paths.ts";
import { AccessMode, describeRules, type GuardRule } from "./policy.ts";

// Re-export the type with the runtime flag the state layer needs.
export type { GuardRule };

/**
 * Frozen view of GuardState captured at invocation time (Gate 4 of v2).
 * Bash, fd and rg each build their sandbox from an identical snapshot so
 * every process observes the same filesystem security view.
 */
export interface PermissionSnapshot {
	workspace: string;
	reservedDenyPaths: string[];
	rules: Array<{
		path: string;
		mode: AccessMode;
		logicalPath?: string;
		asDirectory?: boolean;
		created?: boolean;
	}>;
	stateFile: string;
	runtimeDir: string;
}

/** Deep-copy the mutable state into an immutable invocation snapshot. */
export function snapshotOf(state: GuardState): PermissionSnapshot {
	return {
		workspace: state.workspace,
		reservedDenyPaths: [...state.reservedDenyPaths],
		rules: state.rules.map((r) => ({
			path: r.path,
			mode: r.mode,
			...(r.logicalPath ? { logicalPath: r.logicalPath } : {}),
			...(r.asDirectory ? { asDirectory: true } : {}),
			...(r.created ? { created: true } : {}),
		})),
		stateFile: getStateFilePath(state.agentDir),
		runtimeDir: getRuntimeDir(state.agentDir),
	};
}

export const STATE_VERSION = 1;
/** File name of the durable policy store, inside the agent dir. */
export const STATE_FILE_NAME = "file-guard.json";
/** Internal runtime dir (synthetic deny masks, scratch). */
export const RUNTIME_DIR_NAME = "file-guard";

export interface PersistedRule {
	path: string;
	mode: "deny" | "read";
	logicalPath?: string;
	asDirectory?: boolean;
	created?: boolean;
}

export interface PersistedProject {
	rules: PersistedRule[];
}

export interface PersistedState {
	version: number;
	projects: Record<string, PersistedProject>;
}

export function getStateFilePath(agentDir: string): string {
	return join(agentDir, STATE_FILE_NAME);
}

export function getRuntimeDir(agentDir: string): string {
	return join(agentDir, RUNTIME_DIR_NAME);
}

/** Synthetic 000-mode mask file path inside the runtime dir. */
export function maskFilePath(runtimeDir: string, seed: string): string {
	return join(runtimeDir, `deny-${seed}.mask`);
}

/** Simple stable hash for mask file names (non-cryptographic is fine here). */
export function stableHash(s: string): string {
	let h = 0;
	for (let i = 0; i < s.length; i++) {
		h = (h * 31 + s.charCodeAt(i)) | 0;
	}
	return (h >>> 0).toString(36);
}

const EMPTY_STATE: PersistedState = { version: STATE_VERSION, projects: {} };

export async function loadState(agentDir: string): Promise<PersistedState> {
	const file = getStateFilePath(agentDir);
	let raw: string;
	try {
		raw = await readFile(file, "utf8");
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") return structuredClone(EMPTY_STATE);
		throw err;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (err) {
		throw new Error(`Corrupt guard state file ${file}: ${(err as Error).message}`);
	}
	const state = parsed as Partial<PersistedState>;
	if (typeof state !== "object" || state === null || state.version !== STATE_VERSION) {
		throw new Error(`Unsupported guard state version in ${file}`);
	}
	const projects = state.projects ?? {};
	for (const [key, project] of Object.entries(projects)) {
		if (typeof project !== "object" || project === null || !Array.isArray(project.rules)) {
			throw new Error(`Corrupt project entry in ${file}: ${key}`);
		}
		for (const rule of project.rules) {
			if (typeof rule?.path !== "string" || (rule.mode !== "deny" && rule.mode !== "read")) {
				throw new Error(`Corrupt rule in ${file} (project ${key})`);
			}
		}
	}
	return {
		version: STATE_VERSION,
		projects: projects as PersistedState["projects"],
	};
}

/**
 * Atomic durability: write temp file in the same directory, fsync, rename.
 * Never truncate the live file in place (a crash mid-write would still lose
 * the previous good state — temp+rename avoids that window).
 */
export async function atomicWriteJson(file: string, data: unknown): Promise<void> {
	const dir = nodePath.dirname(file);
	await mkdir(dir, { recursive: true });
	const tmp = join(dir, `.${nodePath.basename(file)}.${process.pid}.${Date.now()}.tmp`);
	const handle = await open(tmp, "w");
	try {
		await handle.writeFile(JSON.stringify(data, null, 2), "utf8");
		await handle.sync();
	} finally {
		await handle.close();
	}
	await rename(tmp, file);
}

/**
 * GuardState: in-memory authority for one canonical workspace.
 */
export class GuardState {
	/** Canonical workspace path. */
	readonly workspace: string;
	/** Agent dir (reserved paths are derived from it). */
	readonly agentDir: string;
	/** User rules for this workspace (Deny or Read only). */
	rules: GuardRule[] = [];
	/** Aliased user rules that match a reserved path are rejected up front. */
	readonly reservedDenyPaths: string[];
	/** Optional extra reserved path (the extension's own directory). */
	additionalReserved: string[] = [];

	constructor(workspace: string, agentDir: string, additionalReserved: string[] = []) {
		this.workspace = workspace;
		this.agentDir = agentDir;
		this.additionalReserved = additionalReserved;
		this.reservedDenyPaths = [getStateFilePath(agentDir), getRuntimeDir(agentDir), ...additionalReserved];
	}

	get stateFile(): string {
		return getStateFilePath(this.agentDir);
	}

	/** All rules including reserved paths, as GuardRules (internal use). */
	allRules(): GuardRule[] {
		return [...this.reservedDenyPaths.map((p) => ({ path: p, mode: AccessMode.Deny }) as GuardRule), ...this.rules];
	}

	/**
	 * Set (add or upgrade) a rule. Deny upgrades Read; Read cannot downgrade
	 * Deny. Returns the affected rule or null when nothing changed.
	 * Throws for reserved paths.
	 */
	async setRule(rule: GuardRule): Promise<GuardRule | null> {
		// Rules always store normalized absolute paths — never rely on the
		// caller to have stripped trailing slashes/dot segments.
		rule = { ...rule, path: normalizeAbsolute(rule.path) };
		for (const reserved of this.reservedDenyPaths) {
			if (rule.path === reserved || isDescendantOrAlias(rule.path, reserved)) {
				throw new Error(`Refusing to protect reserved path: ${reserved}`);
			}
		}
		let changed = false;
		let existing: GuardRule | undefined;
		for (const r of this.rules) {
			if (r.path === rule.path) {
				existing = r;
				break;
			}
		}
		if (!existing) {
			this.rules.push(rule);
			changed = true;
		} else if (rule.mode === AccessMode.Deny && existing.mode === AccessMode.Read) {
			existing.mode = AccessMode.Deny;
			if (rule.logicalPath) existing.logicalPath = rule.logicalPath;
			changed = true;
		} else if (existing.logicalPath !== rule.logicalPath) {
			existing.logicalPath = rule.logicalPath;
		}
		await this.persist();
		return changed ? (existing ?? rule) : null;
	}

	/** Remove a rule matching canonical path OR logical path. Returns removed rule. */
	async removeRule(form: { path?: string; logicalPath?: string }): Promise<GuardRule | null> {
		const idx = this.rules.findIndex((r) => {
			if (form.path && r.path === form.path) return true;
			if (form.logicalPath && r.logicalPath === form.logicalPath) return true;
			return false;
		});
		if (idx < 0) return null;
		const [removed] = this.rules.splice(idx, 1);
		await this.persist();
		return removed;
	}

	/** Replace rules wholesale (used when loading persisted state). */
	replaceRules(rules: GuardRule[]): void {
		this.rules = rules;
	}

	/**
	 * Mark rules whose targets were materialized as placeholders so they get
	 * the `created` flag persisted (once — dedupes per-call work).
	 * Awaited so callers never leave dangling writes.
	 */
	async markPlaceholders(created: { target: string; type: "file" | "dir" }[]): Promise<void> {
		if (created.length === 0) return;
		let changed = false;
		for (const { target } of created) {
			const rule = this.rules.find((r) => r.path === target && !r.created);
			if (rule) {
				rule.created = true;
				changed = true;
			}
		}
		if (changed) await this.persist();
	}

	/** Atomically persist the current workspace's rules. */
	async persist(): Promise<void> {
		const persisted: PersistedState = {
			version: STATE_VERSION,
			projects: {
				[this.workspace]: {
					rules: this.rules.map((r) => ({
						path: r.path,
						mode: r.mode === AccessMode.Deny ? "deny" : "read",
						...(r.logicalPath ? { logicalPath: r.logicalPath } : {}),
						...(r.asDirectory ? { asDirectory: true } : {}),
						...(r.created ? { created: true } : {}),
					})),
				},
			},
		};
		// Merge with existing projects so different workspaces keep their rules.
		const existing = await loadStateSafe(this.agentDir);
		const merged: PersistedState = {
			version: STATE_VERSION,
			projects: {
				...existing.projects,
				[this.workspace]: persisted.projects[this.workspace],
			},
		};
		await atomicWriteJson(this.stateFile, merged);
	}

	/** Human-readable policy summary for /guard. */
	describe(): string {
		return describeRules(this.workspace, this.rules, this.reservedDenyPaths);
	}
}

function isDescendantOrAlias(path: string, reserved: string): boolean {
	if (path === reserved) return true;
	const prefix = reserved.endsWith("/") ? reserved : `${reserved}/`;
	return path.startsWith(prefix);
}

/** Wrap loadState so persist() can tolerate a corrupt file (report only). */
async function loadStateSafe(agentDir: string): Promise<PersistedState> {
	try {
		return await loadState(agentDir);
	} catch {
		return structuredClone(EMPTY_STATE);
	}
}

/** Per-target in-flight creation promises (parallel tool calls must not race). */
const pendingTargets = new Map<string, Promise<{ created: boolean; type: "file" | "dir" }>>();

/**
 * Create a placeholder file/dir so a yet-nonexistent protected target can be
 * mounted/masked. Returns the placeholder's type hint ("file" | "dir").
 * Serialized per path; idempotent when the target already exists.
 */
export function ensureMaskableTarget(
	target: string,
	asDirectory: boolean,
	mode: AccessMode.Deny | AccessMode.Read,
): Promise<{ created: boolean; type: "file" | "dir" }> {
	const pending = pendingTargets.get(target);
	if (pending) return pending;
	const promise = doEnsureMaskableTarget(target, asDirectory, mode).finally(() => {
		pendingTargets.delete(target);
	});
	pendingTargets.set(target, promise);
	return promise;
}

async function doEnsureMaskableTarget(
	target: string,
	asDirectory: boolean,
	mode: AccessMode.Deny | AccessMode.Read,
): Promise<{ created: boolean; type: "file" | "dir" }> {
	let existingType: "file" | "dir" | null = null;
	try {
		const st = await stat(target);
		existingType = st.isDirectory() ? "dir" : "file";
	} catch {
		existingType = null;
	}
	if (existingType) return { created: false, type: existingType };

	const perm = asDirectory ? 0o755 : mode === AccessMode.Deny ? 0o000 : 0o444;
	if (asDirectory) {
		await mkdir(target, { recursive: true, mode: perm });
		return { created: true, type: "dir" };
	}
	await mkdir(nodePath.dirname(target), { recursive: true });
	await writeFile(target, "", { mode: perm });
	await chmod(target, perm);
	return { created: true, type: "file" };
}

/** Remove a placeholder we created, only while it is still empty/safe. */
export async function cleanupPlaceholder(target: string, type: "file" | "dir"): Promise<void> {
	try {
		const st = await stat(target);
		if (type === "dir" && !st.isDirectory()) return;
		if (type === "file" && !st.isFile()) return;
	} catch {
		return; // already gone
	}
	try {
		if (type === "dir") {
			const entries = await readdir(target);
			if (entries.length === 0) await rmdir(target);
		} else {
			// Never remove a placeholder the user has filled with content.
			if ((await stat(target)).size > 0) return;
			await unlink(target);
		}
	} catch {
		// Non-empty or busy: leave it, never force-remove.
	}
}
