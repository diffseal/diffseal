/** Terraform-style version constraints, independent of provider installation. */
interface Version { numbers: number[]; pre: string[] }
function parse(value: string): Version {
  const match = value.match(/^(\d+(?:\.\d+){0,2})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) throw Error(`Unsupported module version: ${value}`);
  const numbers = match[1].split('.').map(Number);
  if (numbers.some((n) => !Number.isSafeInteger(n))) throw Error('Module version number is too large');
  return { numbers: [...numbers, 0, 0].slice(0, 3), pre: match[2]?.split('.') ?? [] };
}
function compare(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) if (a.numbers[i] !== b.numbers[i]) return Math.sign(a.numbers[i] - b.numbers[i]);
  if (!a.pre.length || !b.pre.length) return a.pre.length ? -1 : b.pre.length ? 1 : 0;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i]; if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    return nx && ny ? Math.sign(Number(x) - Number(y)) : nx !== ny ? nx ? -1 : 1 : x < y ? -1 : 1;
  }
  return 0;
}
export function selectModuleVersion(versions: string[], constraint: string): string {
  const rules = constraint.trim() ? constraint.split(',').map((part) => {
    const match = part.trim().match(/^(~>|>=|<=|!=|>|<|=)?\s*(\S+)$/);
    if (!match) throw Error(`Unsupported module version constraint: ${constraint}`);
    const op = match[1] ?? '=', wanted = parse(match[2]);
    let upper: Version | undefined;
    if (op === '~>') {
      const pieces = match[2].split(/[+-]/)[0].split('.').length;
      const index = pieces >= 3 ? 1 : 0, numbers = [...wanted.numbers]; numbers[index]++; for (let i = index + 1; i < 3; i++) numbers[i] = 0;
      upper = { numbers, pre: [] };
    }
    return { op, wanted, upper };
  }) : [];
  const matches = versions.filter((value) => {
    const version = parse(value);
    if (version.pre.length && !rules.some((rule) => rule.op === '=' && compare(version, rule.wanted) === 0)) return false;
    return rules.every(({ op, wanted, upper }) => {
      const c = compare(version, wanted);
      return op === '=' ? c === 0 : op === '!=' ? c !== 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : op === '<' ? c < 0 : op === '<=' ? c <= 0 : c >= 0 && compare(version, upper!) < 0;
    });
  }).sort((a, b) => compare(parse(a), parse(b)));
  if (!matches.length) throw Error(`No module version matches ${constraint || 'a stable release'}`);
  return matches.at(-1)!;
}
