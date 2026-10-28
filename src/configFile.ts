/** The repository settings file: policy, exceptions, links and replay options. */
export const CONFIG_FILE = '.diffseal.json';
/** Its name before the rename to Diffseal. Still read, so commits from before the rename keep their settings. */
export const LEGACY_CONFIG_FILE = '.terratrust.json';

/** The settings file a source uses, preferring the current name. */
export function configFileIn(source: { readFile(p: string): string | undefined | null }): string {
  return source.readFile(CONFIG_FILE) == null && source.readFile(LEGACY_CONFIG_FILE) != null ? LEGACY_CONFIG_FILE : CONFIG_FILE;
}

export function readConfigFile(source: { readFile(p: string): string | undefined | null }): string | undefined {
  return source.readFile(configFileIn(source)) ?? undefined;
}
