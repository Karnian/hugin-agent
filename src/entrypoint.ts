import { realpathSync } from "node:fs";
import { basename, extname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function basenameWithoutExtension(path: string): string {
  const base = basename(path);
  return base.slice(0, base.length - extname(base).length);
}

/** True when a module is the process entrypoint.
 *
 * Compares REAL paths so an npm `bin` symlink still counts as main. The optional
 * entry name prevents guards from firing after multiple entry modules are
 * statically bundled into a single CLI file.
 */
export function invokedAsMain(metaUrl: string, entryName?: string): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;

  let modulePath: string;
  try {
    modulePath = fileURLToPath(metaUrl);
  } catch {
    return metaUrl === pathToFileURL(argv1).href;
  }

  if (entryName !== undefined && basenameWithoutExtension(modulePath) !== entryName) {
    return false;
  }

  try {
    return realpathSync(argv1) === realpathSync(modulePath);
  } catch {
    return metaUrl === pathToFileURL(argv1).href;
  }
}
