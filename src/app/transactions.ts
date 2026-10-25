import { actionsFor } from './actions.js';
import type { AccessFact } from './facts.js';
import { children, field, unwrapped, type Node, type Syntax } from './syntax.js';
/** A transaction is authorized per item, not by any one action from its candidate set. */
export function transactionFacts(base: AccessFact, input: Map<string, Node>, s: Syntax): AccessFact[] | undefined {
  if (base.service !== 'dynamodb' || !['TransactWriteItems', 'TransactGetItems'].includes(base.operation)) return;
  const opaque = (): AccessFact => ({
    ...base,
    possible: true,
    resource: {
      kind: 'unresolved',
      text: 'transaction item or table is not statically known',
    },
  });
  const raw = input.get('TransactItems');
  if (!raw) return [opaque()];
  const list = s.resolve(raw),
    body = list.type === 'composite_literal' ? field(list, 'body') : list;
  if (!body || !['array', 'list', 'literal_value'].includes(body.type)) return [opaque()];
  const out: AccessFact[] = [];
  for (const item of children(body).filter((n) => n.type !== 'comment')) {
    const fields = s.fields(unwrapped(item));
    let found = false;
    for (const action of actionsFor('dynamodb', base.operation)) {
      const operation = action.split(':')[1],
        key = operation === 'ConditionCheckItem' ? 'ConditionCheck' : operation.replace(/Item$/, '');
      const value = fields.get(key);
      if (!value) continue;
      const table = s.fields(value).get('TableName');
      found = true;
      out.push({
        ...base,
        operation,
        actions: [action],
        resource: table ? s.ref(table) : opaque().resource,
        via: base.via ? `${base.via} (${base.operation})` : base.operation,
      });
    }
    if (!found) out.push(opaque());
  }
  return out;
}
