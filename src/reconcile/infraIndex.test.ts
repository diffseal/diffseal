import { expect, test } from 'bun:test';
import { evaluateRoot } from '../terraform/expand.js';
import { MemorySource } from '../terraform/source.js';
import { InfraIndex } from './infraIndex.js';
import { reconcile } from './reconcile.js';

test('a role ARN only matches roots deployed to its account', () => {
  const root = (account: string) => `terraform {\n  backend "s3" {}\n}\nprovider "aws" {\n  assume_role {\n    role_arn = "arn:aws:iam::${account}:role/TerraformAdminRole"\n  }\n}\nresource "aws_iam_role" "task" {\n  name = "gw-task"\n  path = "/system/ecs/"\n  assume_role_policy = "{}"\n}\n`;
  const src = new MemorySource({ 'envs/prod/gw/main.tf': root('111111111111'), 'envs/sandbox/gw/main.tf': root('222222222222') });
  const index = new InfraIndex([evaluateRoot(src, 'envs/prod/gw'), evaluateRoot(src, 'envs/sandbox/gw')]);
  expect(index.rolesNamed('arn:aws:iam::222222222222:role/system/ecs/gw-task').map((r) => r.root)).toEqual(['envs/sandbox/gw']);
  expect(index.rolesNamed('gw-task').map((r) => r.root)).toEqual(['envs/prod/gw', 'envs/sandbox/gw']);
});

test('in a root with providers for two accounts, a role ARN match is uncertain (round 7)', () => {
  const src = new MemorySource({
    'r/main.tf': `terraform {\n  backend "s3" {}\n}\nprovider "aws" {\n  allowed_account_ids = ["111111111111"]\n}\nprovider "aws" {\n  alias               = "b"\n  allowed_account_ids = ["222222222222"]\n}\nresource "aws_iam_role" "w" {\n  name               = "worker"\n  assume_role_policy = "{}"\n}\nresource "aws_iam_role_policy" "p" {\n  role   = aws_iam_role.w.name\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "sqs:SendMessage", Resource = "*" }] })\n}\n`,
  });
  const index = new InfraIndex([evaluateRoot(src, 'r')]);
  const roles = index.rolesNamed('arn:aws:iam::222222222222:role/worker');
  expect(roles.map((r) => r.accountUncertain)).toEqual([true]);
  const links = reconcile(
    [{ service: 'sqs', operation: 'SendMessage', actions: ['sqs:SendMessage'], resource: { kind: 'literal', value: 'q' }, file: 'a.go', line: 1 }],
    [],
    index,
    { roleNames: ['arn:aws:iam::222222222222:role/worker'] }
  );
  expect(links.map((l) => l.status)).toEqual(['UNRESOLVED']);
});

test('a role ARN with a path only matches a role with that path (round 6)', () => {
  const role = (name: string, path: string) => `resource "aws_iam_role" "${name.replace(/\W/g, '_')}_${path.replace(/\W/g, '_')}" {\n  name = "${name}"\n  ${path ? `path = "${path}"` : ''}\n  assume_role_policy = "{}"\n}\n`;
  const src = new MemorySource({
    'r/main.tf': `terraform {\n  backend "s3" {}\n}\nvariable "p" {}\n${role('worker', '/prod/')}${role('api', '')}resource "aws_iam_role" "dyn" {\n  name = "dyn"\n  path = var.p\n  assume_role_policy = "{}"\n}\n`,
  });
  const index = new InfraIndex([evaluateRoot(src, 'r')]);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/dev/worker')).toEqual([]);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/prod/worker').map((r) => r.name)).toEqual(['worker']);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/api').map((r) => r.name)).toEqual(['api']);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/x/api')).toEqual([]);
  // A path not known statically may be any path.
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/any/dyn').map((r) => r.name)).toEqual(['dyn']);
  expect(index.rolesNamed('worker').map((r) => r.name)).toEqual(['worker']);
});
