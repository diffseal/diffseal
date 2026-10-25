import { expect, test } from 'bun:test';
import { MemorySource } from '../terraform/source.js';
import { discoverLink } from './link.js';

test('task definitions in the app repository name the role and the env vars set outside Terraform', () => {
  const app = new MemorySource({
    'cmd/taskdef_prod.json': JSON.stringify({
      family: 'gw',
      taskRoleArn: 'arn:aws:iam::123:role/system/ecs/gw-task',
      containerDefinitions: [{ name: 'gw', environment: [{ name: 'APP_ENV', value: 'prod' }], secrets: [{ name: 'DB_PASSWORD', valueFrom: 'arn' }] }],
    }),
    '.terratrust.json': JSON.stringify({ infra: { repo: '../infra', rootsUnder: 'envs/prod' }, roles: ['extra-role'] }),
  });
  const link = discoverLink(app);
  expect(link.roles).toEqual(['extra-role', 'arn:aws:iam::123:role/system/ecs/gw-task']);
  expect(link.env).toEqual(['APP_ENV', 'DB_PASSWORD']);
  expect(link.infra).toEqual({ repo: '../infra', rootsUnder: 'envs/prod' });
});

test('Kubernetes service accounts and Helm values name the IAM role through the IRSA annotation', () => {
  const app = new MemorySource({
    'deploy/k8s/serviceaccount.yaml': `apiVersion: v1
kind: ServiceAccount
metadata:
  name: orders
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/orders-irsa
`,
    'charts/orders/values.yaml': `serviceAccount:
  annotations:
    "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/orders-irsa-sandbox"
env:
  - name: ORDERS_TABLE
    value: orders
`,
  });
  const link = discoverLink(app);
  expect(link.roles).toEqual(['arn:aws:iam::123456789012:role/orders-irsa-sandbox', 'arn:aws:iam::123456789012:role/orders-irsa']);
  expect(link.sources.some((s) => s.includes('eks.amazonaws.com/role-arn'))).toBe(true);
  expect(link.env).toEqual(['ORDERS_TABLE']);
});

test('EKS discovery ignores CI workflows, comments and env lists outside workloads (round 2)', () => {
  const app = new MemorySource({
    '.github/workflows/deploy.yml': 'env:\n  - name: DEPLOY_TOKEN\n# eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/ci\n',
    'k8s/sa.yaml': 'kind: ServiceAccount\nmetadata:\n  annotations:\n    # eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/old\n    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/app\n',
    'k8s/config.yaml': 'kind: ConfigMap\ndata:\n  env:\n  - name: NOT_ENV\n',
    'k8s/deploy.yaml': 'kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - env:\n            - name: QUEUE_URL\n',
  });
  const link = discoverLink(app);
  expect(link.roles).toEqual(['arn:aws:iam::123456789012:role/app']);
  expect(link.env).toEqual(['QUEUE_URL']);
});
