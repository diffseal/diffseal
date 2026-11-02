import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { artifactName, artifactPlace, writeReports, REPORT_FILES } from './report.js';
import { plan, rc } from '../testing/planFixtures.js';

test('the artifact is named after the commit reviewed', () => {
  expect(artifactName('0123456789abcdef0123456789abcdef01234567')).toBe('diffseal-0123456');
  for (const sha of [undefined, '', 'HEAD', 'not/a sha']) expect(artifactName(sha)).toBe('diffseal-report');
});

test('the place of the full list names the artifact, and the run when its URL is known', () => {
  const env = { GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'octo/infra', GITHUB_RUN_ID: '42' };
  expect(artifactPlace('diffseal-0123456', env)).toBe('the diffseal-0123456 artifact of this run (https://github.com/octo/infra/actions/runs/42)');
  expect(artifactPlace('diffseal-0123456', {})).toBe('the diffseal-0123456 artifact of this run');
  for (const bad of [{ GITHUB_RUN_ID: '42\nx' }, { GITHUB_REPOSITORY: 'octo/infra) [x](y' }, { GITHUB_SERVER_URL: 'javascript:alert(1)' }]) {
    expect(artifactPlace('diffseal-0123456', { ...env, ...bad })).toBe('the diffseal-0123456 artifact of this run');
  }
});

test('reports go to a new directory of their own, the record only when there is one', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-report-test-'));
  try {
    const a = writeReports(parent, { json: { gate: 'pass' }, markdown: '# Report\n' });
    const b = writeReports(parent, { json: { gate: 'block' }, markdown: '# Other\n', record: '{"schema":"diffseal.change-record/v1"}\n' });
    expect(a).not.toBe(b);
    expect(path.dirname(a)).toBe(parent);
    expect(fs.readdirSync(a).sort()).toEqual([REPORT_FILES.markdown, REPORT_FILES.json].sort());
    expect(fs.readdirSync(b).sort()).toEqual([REPORT_FILES.record, REPORT_FILES.markdown, REPORT_FILES.json].sort());
    expect(JSON.parse(fs.readFileSync(path.join(a, REPORT_FILES.json), 'utf8'))).toEqual({ gate: 'pass' });
    expect(fs.readFileSync(path.join(a, REPORT_FILES.markdown), 'utf8')).toBe('# Report\n');
    // Written byte for byte, so the digest in the uploaded record matches the file.
    expect(fs.readFileSync(path.join(b, REPORT_FILES.record), 'utf8')).toBe('{"schema":"diffseal.change-record/v1"}\n');
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

function actionRun(dir: string, env: Record<string, string>) {
  return spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=async(url,init)=>{if(!init.method)return Response.json({value:"oidc"});throw new Error("offline upload failure")}', path.resolve(import.meta.dirname, '../../dist/action.js')], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, INPUT_MODE: 'pr', INPUT_COMMENT: 'false', GITHUB_WORKSPACE: dir, GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_EVENT_NAME: 'push', GITHUB_OUTPUT: path.join(dir, 'outputs'), GITHUB_STEP_SUMMARY: path.join(dir, 'summary'), RUNNER_TEMP: path.join(dir, 'tmp'), ...env },
  });
}

test('the Action writes the full reports and names the artifact in its outputs', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-action-report-'));
  try {
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
      if (r.status) throw new Error(r.stderr);
      return r.stdout.trim();
    };
    git('init', '-q'); git('commit', '--allow-empty', '-qm', 'base'); git('commit', '--allow-empty', '-qm', 'head');
    const head = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(dir, 'event.json'), '{}');
    fs.mkdirSync(path.join(dir, 'tmp'));
    const outputs = () => Object.fromEntries(fs.readFileSync(path.join(dir, 'outputs'), 'utf8').trim().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));

    // An upload that built a record and then failed: the untrimmed record is kept with the reports.
    const uploaded = actionRun(dir, { INPUT_UPLOAD: 'true', 'INPUT_REPORT-ARTIFACT': 'true', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example/token', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token' });
    expect(uploaded.status).toBe(0);
    const out = outputs();
    expect(out.gate).toBe('pass');
    expect(out['artifact-name']).toBe(`diffseal-${head.slice(0, 7)}`);
    expect(path.dirname(out['report-dir'])).toBe(path.join(dir, 'tmp'));
    expect(fs.readdirSync(out['report-dir']).sort()).toEqual(['change-record.json', 'report.json', 'report.md']);
    const report = JSON.parse(fs.readFileSync(path.join(out['report-dir'], 'report.json'), 'utf8'));
    expect(report.commit.sha).toBe(head);
    expect(report.combined.gate.result).toBe('pass');
    expect(report).not.toHaveProperty('headSource');
    expect(fs.readFileSync(path.join(dir, 'summary'), 'utf8')).toBe(fs.readFileSync(path.join(out['report-dir'], 'report.md'), 'utf8') + '\n');
    expect(JSON.parse(fs.readFileSync(path.join(out['report-dir'], 'change-record.json'), 'utf8')).change.commit).toBe(head);

    // No upload, no record.
    fs.rmSync(path.join(dir, 'outputs'));
    expect(actionRun(dir, {}).status).toBe(0);
    expect(fs.readdirSync(outputs()['report-dir']).sort()).toEqual(['report.json', 'report.md']);

    // A run that did not review anything names no report, so nothing is uploaded.
    fs.rmSync(path.join(dir, 'outputs'));
    fs.writeFileSync(path.join(dir, 'outputs'), '');
    expect(actionRun(dir, { INPUT_MODE: 'app' }).status).toBe(1);
    expect(fs.readFileSync(path.join(dir, 'outputs'), 'utf8')).toBe('');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the report file keeps every row that the job summary leaves out', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-action-full-'));
  try {
    fs.mkdirSync(path.join(dir, 'tmp'));
    fs.writeFileSync(path.join(dir, 'event.json'), '{}');
    fs.writeFileSync(path.join(dir, 'tfplan.json'), JSON.stringify(plan(Array.from({ length: 50 }, (_, i) => rc(`aws_sqs_queue.q${i}`, 'aws_sqs_queue', ['delete'], {})))));
    const r = actionRun(dir, { INPUT_MODE: 'plan', INPUT_ADVISORY: 'true', GITHUB_SHA: 'a'.repeat(40) });
    expect(r.status).toBe(0);
    const outputs = fs.readFileSync(path.join(dir, 'outputs'), 'utf8');
    expect(outputs).toContain(`artifact-name=diffseal-${'a'.repeat(7)}\n`);
    const reportDir = /^report-dir=(.*)$/m.exec(outputs)![1];
    const summary = fs.readFileSync(path.join(dir, 'summary'), 'utf8');
    const full = fs.readFileSync(path.join(reportDir, 'report.md'), 'utf8');
    expect(summary).toContain('...and 10 more');
    expect(full).not.toContain('more |');
    for (let i = 0; i < 50; i++) expect(full).toContain(`\`aws_sqs_queue.q${i}\``);
    expect(JSON.parse(fs.readFileSync(path.join(reportDir, 'report.json'), 'utf8')).changes).toHaveLength(50);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
