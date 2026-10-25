/** Offline parser initialization. Public extraction APIs remain synchronous after module loading. */
import { readFileSync } from 'node:fs';
import { Parser, Language, type Node, type Tree } from 'web-tree-sitter';
import runtime from './grammars/tree-sitter.wasm' with { type: 'file' };
import go from './grammars/tree-sitter-go.wasm' with { type: 'file' };
import python from './grammars/tree-sitter-python.wasm' with { type: 'file' };
import typescript from './grammars/tree-sitter-typescript.wasm' with { type: 'file' };
import tsx from './grammars/tree-sitter-tsx.wasm' with { type: 'file' };
import java from './grammars/tree-sitter-java.wasm' with { type: 'file' };
import kotlin from './grammars/tree-sitter-kotlin.wasm' with { type: 'file' };
import csharp from './grammars/tree-sitter-c_sharp.wasm' with { type: 'file' };
export type AppLanguage = 'go' | 'python' | 'typescript' | 'tsx' | 'java' | 'kotlin' | 'csharp';
export type SyntaxNode = Node;
function bytes(asset: unknown): Buffer {
  if (typeof asset !== 'string') throw new Error('Parser asset import must use the file loader');
  return readFileSync(new URL(asset, import.meta.url));
}
await Parser.init({ wasmBinary: bytes(runtime) });
const languages = new Map<AppLanguage, Language>(
  await Promise.all(
    (Object.entries({ go, python, typescript, tsx, java, kotlin, csharp }) as Array<[AppLanguage, unknown]>).map(
      async ([name, asset]) => [name, await Language.load(bytes(asset))] as [AppLanguage, Language],
    ),
  ),
);
const parsers = new Map<AppLanguage, Parser>();
const valueNews = new WeakMap<Tree, Set<number>>();
export const isValueNew = (node: Node): boolean => valueNews.get(node.tree)?.has(node.startIndex) ?? false;
export function parseCode(language: AppLanguage, source: string): Tree {
  let parser = parsers.get(language);
  if (!parser) {
    parser = new Parser();
    parser.setLanguage(languages.get(language)!);
    parsers.set(language, parser);
  }
  let tree = parser.parse(source);
  if (!tree) throw new Error('Parser cancelled unexpectedly');
  // Go 0.25 treats builtin new's argument as a type. Go 1.26 also permits a value.
  // Reparse only calls identified by the grammar, using a same-width ordinary identifier.
  if (language === 'go') {
    const starts = [...walk(tree.rootNode)]
      .filter((n) => n.type === 'call_expression' && n.childForFieldName('function')?.text === 'new')
      .map((n) => n.startIndex);
    if (starts.length) {
      let compatible = source;
      for (const at of [...starts].sort((a, b) => b - a))
        compatible = compatible.slice(0, at) + 'ptr' + compatible.slice(at + 3);
      tree.delete();
      tree = parser.parse(compatible);
      if (!tree) throw new Error('Parser cancelled unexpectedly');
      valueNews.set(tree, new Set(starts));
    }
  }
  return tree;
}
export function* walk(node: Node): Generator<Node> {
  yield node;
  for (const child of children(node)) yield* walk(child);
}
export const field = (node: Node, name: string): Node | undefined => node.childForFieldName(name) ?? undefined;
export function ancestor(node: Node | undefined, predicate: (n: Node) => boolean): Node | undefined {
  for (let n = node; n; n = n.parent ?? undefined) if (predicate(n)) return n;
  return undefined;
}
export const callArgs = (node: Node): Node[] => children(field(node, 'arguments')).filter((n) => n.type !== 'comment');

export const children = (node: Node | null | undefined): Node[] =>
  node?.namedChildren.filter((n): n is Node => n !== null) ?? [];
