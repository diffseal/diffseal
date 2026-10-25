import { expect, test } from 'bun:test';
import { MemorySource } from './source.js';
import { evaluateRoot } from './expand.js';
import { discoverRoots } from './config.js';

test('Terraform JSON modules load variables, interpolation, nested blocks and count', () => {
  const source = new MemorySource({
    'root/main.tf.json': JSON.stringify({
      terraform: { backend: { s3: {} } },
      variable: { n: { default: 2, type: 'number' } },
      locals: { prefix: 'queue' },
      resource: {
        aws_sqs_queue: {
          q: { count: '${var.n}', name: '${local.prefix}-${count.index}', visibility_timeout_seconds: 30 },
        },
      },
      module: { child: { source: './child', value: '${aws_sqs_queue.q[0].name}' } },
    }),
    'root/child/main.tf.json': JSON.stringify({
      variable: { value: { type: 'string' } },
      resource: { terraform_data: { child: { input: '${var.value}', lifecycle: { prevent_destroy: true } } } },
    }),
  });
  expect(discoverRoots(source)).toEqual(['root']);
  const evaluation = evaluateRoot(source, 'root');
  expect(evaluation.diagnostics).toEqual([]);
  expect(evaluation.instances.map((i) => i.address)).toEqual([
    'aws_sqs_queue.q[0]',
    'aws_sqs_queue.q[1]',
    'module.child.terraform_data.child',
  ]);
  expect(evaluation.instances[2].attrs.input).toBe('queue-0');
  expect(evaluation.instances[2].preventDestroy).toBe(true);
});

test('JSON comments apply to block bodies and literal contexts do not interpolate strings', () => {
  const source = new MemorySource({
    'main.tf.json': JSON.stringify({
      '//': 'generated file',
      variable: { text: { type: 'string', default: '${literal}' } },
      locals: { provider: 'literal-provider', providers: { aws: 'literal-alias' } },
      resource: {
        terraform_data: {
          example: {
            '//': 'block comment',
            input: { '//': 'keep this property', value: '${var.text}', provider: '${local.provider}' },
          },
        },
      },
      output: { x: { description: '${not a template', value: '${local.providers.aws}' } },
    }),
  });
  const result = evaluateRoot(source, '.');
  expect(result.diagnostics).toEqual([]);
  expect(result.instances[0].attrs.input).toEqual({
    '//': 'keep this property',
    value: '${literal}',
    provider: 'literal-provider',
  });
});
