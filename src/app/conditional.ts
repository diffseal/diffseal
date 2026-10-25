/** Request selectors for permissions that AWS documents as conditional. */
import { selectorsFor } from './actions.js';
import type { AccessFact } from './facts.js';
import { type Node, type Syntax } from './syntax.js';
type Presence = 'present' | 'absent' | 'unknown';
export function conditionalFacts(base: AccessFact, input: Map<string, Node>, s: Pick<Syntax, 'resolve' | 'ref'>): AccessFact[] {
  const supplied = (name: string): Presence => {
    const raw = input.get(name);
    if (!raw) return 'absent';
    const n = s.resolve(raw);
    if (['null', 'undefined', 'None', 'nil', 'false', 'False'].includes(n.text)) return 'absent';
    const ref = s.ref(n);
    if (ref.kind === 'literal') return ref.value.length ? 'present' : 'absent';
    return ['true', 'True'].includes(n.text) ? 'present' : 'unknown';
  };
  let selected = { ...base, actions: [...base.actions] };
  const possible: AccessFact[] = [];
  for (const rule of selectorsFor(base.service, base.operation)) {
    const states = rule.fields.map(supplied),
      status = states.includes('present') ? 'present' : states.includes('unknown') ? 'unknown' : 'absent';
    if (status === 'absent') continue;
    if (status === 'unknown') {
      if (rule.replaces)
        selected = {
          ...selected,
          possible: true,
          resource: {
            kind: 'unresolved',
            text: `${rule.fields.join('/')} may be absent; current-object and version permissions differ`,
          },
        };
      else possible.push({ ...base, actions: rule.actions, possible: true });
      continue;
    }
    selected.actions = selected.actions.filter((a) => !rule.replaces?.includes(a));
    selected.actions = [...new Set([...selected.actions, ...rule.actions])];
  }
  return [selected, ...possible];
}
