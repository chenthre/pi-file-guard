/**
 * search/tool-path.ts — resolve fd/rg binaries for sandboxed search.
 *
 * Pi resolves these via its internal tools-manager (getToolPath/ensureTool).
 * That API is not public, so we replicate the small local part: check Pi's
 * own bin dir (~/.pi/agent/bin) for a previously installed/downloaded
 * binary, else resolve through PATH. No downloads happen here — the user
 * (or Pi itself, when it runs find/grep on the host) provides the binary.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

export type SearchTool = "fd" | "rg";

const SYSTEM_NAMES: Record<SearchTool, string[]> = {
	fd: ["fd", "fdfind"],
	rg: ["rg"],
};

export function resolveSearchToolBinary(tool: SearchTool, agentDir: string): string | null {
	// 1. Pi's own tools dir (ensureTool downloads here on the host side).
	const localPath = join(agentDir, "bin", tool);
	if (existsSync(localPath)) return localPath;

	// 2. System PATH (try alternate names, e.g. fdfind).
	for (const name of SYSTEM_NAMES[tool]) {
		const result = spawnSync(name, ["--version"], { stdio: "ignore" });
		if (result.error === undefined || result.error === null) return name;
	}
	return null;
}

export function searchToolError(tool: SearchTool): string {
	const hint = tool === "fd" ? "e.g. apt install fd-find" : "e.g. apt install ripgrep";
	return (
		`${tool} is not available. Pi File Guard's sandboxed search needs the native ` +
		`binary (${hint}); install it and restart pi, or let Pi resolve it by using ` +
		`the built-in find/grep first.`
	);
}
