import { expect, test } from 'bun:test';
import { evaluateRoot } from '../terraform/expand.js';
import { MemorySource } from '../terraform/source.js';
import { InfraIndex } from './infraIndex.js';
import { reconcile } from './reconcile.js';
const policy = (action: string) =>
  JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: '*' }] });

test('resource providers distinguish namesake roles and policies within a multi-account root', () => {
  const src = new MemorySource({
    'main.tf': `
 provider "aws" { allowed_account_ids = ["111111111111"] }
 provider "aws" { alias = "other"
 allowed_account_ids = ["222222222222"] }
 resource "aws_iam_role" "one" {name="worker"
 assume_role_policy="{}"}
 resource "aws_iam_role" "two" {provider=aws.other
 name="worker"
 assume_role_policy="{}"}
 resource "aws_iam_role_policy" "one" {role="worker"
 policy=${JSON.stringify(policy('s3:GetObject'))}}
 resource "aws_iam_role_policy" "two" {provider=aws.other
 role="worker"
 policy=${JSON.stringify(policy('s3:PutObject'))}}
 `,
  });
  const index = new InfraIndex([evaluateRoot(src, '.')]);
  const roles = index.rolesNamed('arn:aws:iam::222222222222:role/worker');
  expect(roles.map((r) => r.instance)).toEqual(['aws_iam_role.two']);
  expect(roles[0].accountUncertain).not.toBe(true);
  const grants = index.grants(roles[0]);
  expect(grants.statements.flatMap((s) => s.actions)).toEqual(['s3:PutObject']);
  expect(grants.uncertainRoots).toEqual([]);
});

test('module provider mappings carry default and aliased accounts through nested modules', () => {
  const source = new MemorySource({
    'main.tf': `provider "aws" {allowed_account_ids=["111111111111"]}
 provider "aws" {
 alias="other"
 assume_role {role_arn="arn:aws:iam::222222222222:role/deploy"}
 }
 module "child" {
 source="./child"
 providers={aws=aws.other,aws.replica=aws}
 }`,
    'child/main.tf': `resource "aws_iam_role" "selected" {
 name="selected"
 assume_role_policy="{}"
 }
 module "nested" {
 source="../nested"
 providers={aws=aws.replica}
 }`,
    'nested/main.tf': `resource "aws_iam_role" "selected" {
 name="nested"
 assume_role_policy="{}"
 }`,
  });
  const index = new InfraIndex([evaluateRoot(source, '.')]);
  expect(index.rolesNamed('arn:aws:iam::222222222222:role/selected').map((r) => r.instance)).toEqual([
    'module.child.aws_iam_role.selected',
  ]);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/selected')).toEqual([]);
  expect(index.rolesNamed('arn:aws:iam::111111111111:role/nested').map((r) => r.instance)).toEqual([
    'module.child.module.nested.aws_iam_role.selected',
  ]);
});

test('managed_policy_arns keeps the selected for_each customer policy instance', () => {
  const source = new MemorySource({
    'main.tf': `resource "aws_iam_policy" "p" {
 for_each={read="s3:GetObject",write="s3:PutObject"}
 name=each.key
 policy=jsonencode({Statement=[{Effect="Allow",Action=each.value,Resource="*"}]})
 }
 resource "aws_iam_role" "r" {
 name="worker"
 assume_role_policy="{}"
 managed_policy_arns=[aws_iam_policy.p["write"].arn]
 }`,
  });
  const index = new InfraIndex([evaluateRoot(source, '.')]);
  const grants = index.grants(index.rolesNamed('worker')[0]);
  expect(grants.statements.flatMap((s) => s.actions)).toEqual(['s3:PutObject']);
  expect(grants.opaque).toEqual([]);
});

test('an unresolved aliased provider cannot prove an externally supplied role ARN', () => {
  const source = new MemorySource({
    'main.tf': `provider "aws" {allowed_account_ids=["111111111111"]}
 provider "aws" {alias="unknown"}
 resource "aws_iam_role" "r" {
 provider=aws.unknown
 name="worker"
 assume_role_policy="{}"
 }`,
  });
  const index = new InfraIndex([evaluateRoot(source, '.')]);
  expect(index.rolesNamed('arn:aws:iam::222222222222:role/worker')[0].accountUncertain).toBe(true);
});

test('resource ARNs from a different alias do not grant a same-name resource in the role account', () => {
  const source = new MemorySource({
    'main.tf': `provider "aws" {allowed_account_ids=["111111111111"]}
 provider "aws" {
 alias="other"
 allowed_account_ids=["222222222222"]
 }
 resource "aws_secretsmanager_secret" "other" {
 provider=aws.other
 name="shared"
 }
 resource "aws_iam_role" "r" {
 name="worker"
 assume_role_policy="{}"
 }
 resource "aws_iam_role_policy" "p" {
 role=aws_iam_role.r.name
 policy=jsonencode({Statement=[{Effect="Allow",Action="secretsmanager:GetSecretValue",Resource=aws_secretsmanager_secret.other.arn}]})
 }`,
  });
  const index = new InfraIndex([evaluateRoot(source, '.')]);
  const links = reconcile(
    [
      {
        service: 'secretsmanager',
        operation: 'GetSecretValue',
        actions: ['secretsmanager:GetSecretValue'],
        resource: { kind: 'literal', value: 'shared' },
        file: 'app.ts',
        line: 1,
      },
    ],
    [],
    index,
    { roleNames: ['worker'] },
  );
  expect(links.map((l) => l.status)).toEqual(['NOT_GRANTED']);
});
