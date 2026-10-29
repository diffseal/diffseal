import { verifyPack } from './verify.js';
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
const cli = path.resolve(import.meta.dirname, '../cli.ts');
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-evidence-')),
    repo = path.join(dir, 'repo');
  fs.mkdirSync(repo);
  const git = (args: string[], date?: string) => {
    const r = spawnSync('git', ['-C', repo, '-c', 'core.hooksPath=/dev/null', ...args], {
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Synthetic author',
        GIT_AUTHOR_EMAIL: 'test@example.invalid',
        GIT_COMMITTER_NAME: 'Synthetic author',
        GIT_COMMITTER_EMAIL: 'test@example.invalid',
        ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}),
      },
    });
    if (r.status !== 0) throw new Error(r.stderr);
    return r.stdout.trim();
  };
  git(['init', '-q']);
  const fixture = JSON.parse(
    fs.readFileSync(path.resolve(import.meta.dirname, '../../fixtures/evidence/period.fixture'), 'utf8'),
  );
  const shas: string[] = [];
  for (const c of fixture.commits) {
    for (const [name, text] of Object.entries(c.files)) {
      const file = path.join(repo, name);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, text as string);
    }
    git(['add', '.']);
    git(['commit', '-qm', c.subject], c.date);
    shas.push(git(['rev-parse', 'HEAD']));
  }
  const run = (args: string[]) => spawnSync('bun', [cli, 'evidence', '--repo', repo, ...args], { encoding: 'utf8' });
  return { dir, repo, shas, run, git };
}
test('evidence CLI writes an unsigned complete period with controls, exceptions and approval coverage', () => {
  const f = setup();
  try {
    const approvals = path.join(f.dir, 'approvals.json');
    fs.writeFileSync(
      approvals,
      JSON.stringify({ [f.shas[1]]: { pr: 1, approvedBy: [{ login: 'reviewer', at: '2026-10-01T11:00:00Z' }] } }),
    );
    const out = path.join(f.dir, 'pack');
    const r = f.run(['--since', '2026-10-01', '--until', '2026-10-03', '--out-dir', out, '--approvals', approvals]);
    expect(r.status).toBe(0);
    const index = fs.readFileSync(path.join(out, 'index.md'), 'utf8');
    expect(index).toContain('Selected commits: 2');
    expect(index).toContain('BLOCK');
    expect(index).toContain('ISO27001:');
    expect(index).toContain('Platform');
    expect(index).toContain('2026-11-01');
    expect(index).toContain('1 / 2');
    const records = fs.readdirSync(path.join(out, 'records'));
    expect(records).toHaveLength(2);
    expect(records).toContain(f.shas[1] + '.json');
    expect(records).not.toContain(f.shas[3] + '.json');
    const scope = JSON.parse(fs.readFileSync(path.join(out, 'pack.json'), 'utf8'));
    expect(scope.complete).toBe(true);
    expect(verifyPack(out, { allowUnsigned: true }).ok).toBe(true);
    expect(scope.signing.status).toBe('unsigned');
    const manifest = fs.readFileSync(path.join(out, 'MANIFEST.sha256'), 'utf8');
    for (const line of manifest.trim().split('\n')) {
      const [hash, name] = line.split('  ');
      expect(
        createHash('sha256')
          .update(fs.readFileSync(path.join(out, name)))
          .digest('hex'),
      ).toBe(hash);
    }
    expect(fs.readFileSync(path.join(out, 'summary.csv'), 'utf8').split('\n')).toHaveLength(4);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
}, 30000);

test('evidence labels ISO 27001 and SOC 2 control findings while preserving v1 records', () => {
  const f = setup();
  try {
    fs.writeFileSync(
      path.join(f.repo, 'infra/prod/logging.tf'),
      'resource "aws_cloudwatch_log_group" "audit" {\n  retention_in_days = 90\n}\n',
    );
    f.git(['add', '.']);
    f.git(['commit', '-qm', 'Add audit log retention'], '2026-10-04T12:00:00Z');
    const sha = f.git(['rev-parse', 'HEAD']);
    const out = path.join(f.dir, 'pack');
    expect(f.run(['--since', '2026-10-01', '--until', '2026-10-05', '--out-dir', out]).status).toBe(0);
    const index = fs.readFileSync(path.join(out, 'index.md'), 'utf8');
    expect(index).toContain('## Findings by control (ISO 27001 and SOC 2)');
    expect(index).toContain('| ISO27001:A.8.24 |');
    expect(index).toContain('| SOC2:CC7.2 | 1 | 0 | 0 | 0 | 0 | 0 |');
    const scope = JSON.parse(fs.readFileSync(path.join(out, 'pack.json'), 'utf8'));
    expect(scope.schema).toBe('diffseal.evidence-pack/v1');
    const record = JSON.parse(fs.readFileSync(path.join(out, 'records', `${sha}.json`), 'utf8'));
    expect(record.schema).toBe('diffseal.change-record/v1');
    expect(record.controls).toContainEqual(expect.objectContaining({
      control: 'SOC2:CC7.2',
      rule: 'cloudwatch.log-retention',
      resource: 'aws_cloudwatch_log_group.audit',
      status: 'PASS',
      frameworks: expect.objectContaining({ soc2_tsc: [{ ref: 'CC7.2', fit: 'supporting' }] }),
    }));
    expect(verifyPack(out, { allowUnsigned: true }).ok).toBe(true);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
}, 30000);

test('evidence rejects normalized invalid calendar dates before writing a pack', () => {
  const f = setup();
  try {
    const out = path.join(f.dir, 'pack');
    const r = f.run(['--since', '2026-02-30', '--until', '2026-10-03', '--out-dir', out]);
    expect(r.status).toBe(1);
    expect(fs.existsSync(out)).toBe(false);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('invalid approvals do not produce a complete evidence pack', () => {
  const f = setup();
  try {
    const out = path.join(f.dir, 'pack'),
      a = path.join(f.dir, 'approvals.json');
    fs.writeFileSync(a, JSON.stringify({ [f.shas[1]]: { approvedBy: 'someone' } }));
    const r = f.run(['--since', '2026-10-01', '--until', '2026-10-03', '--out-dir', out, '--approvals', a]);
    expect(r.status).toBe(1);
    expect(fs.existsSync(out)).toBe(false);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('a replay failure remains visible in an incomplete pack and exits one', () => {
  const f = setup();
  try {
    const out = path.join(f.dir, 'pack');
    const r = f.run(['--since', '2026-09-30', '--until', '2026-10-01', '--out-dir', out]);
    expect(r.status).toBe(1);
    const scope = JSON.parse(fs.readFileSync(path.join(out, 'pack.json'), 'utf8'));
    expect(scope.complete).toBe(false);
    expect(scope.failures).toBe(1);
    expect(fs.readFileSync(path.join(out, 'index.md'), 'utf8')).toContain('INCOMPLETE');
    expect(fs.readFileSync(path.join(out, 'errors.json'), 'utf8')).toContain(f.shas[0]);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('evidence refuses output inside the analyzed repository and leaves it unchanged', () => {
  const f = setup();
  try {
    const before = f.git(['status', '--porcelain']);
    const r = f.run(['--since', '2026-10-01', '--until', '2026-10-03', '--out-dir', path.join(f.repo, 'evidence')]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('only reads');
    expect(f.git(['status', '--porcelain'])).toBe(before);
    expect(fs.existsSync(path.join(f.repo, 'evidence'))).toBe(false);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('evidence refuses an existing nonempty folder and preserves its manifest', () => {
  const f = setup();
  try {
    const out = path.join(f.dir, 'pack');
    fs.mkdirSync(out);
    fs.writeFileSync(path.join(out, 'MANIFEST.sha256'), 'keep');
    const r = f.run(['--since', '2026-10-01', '--until', '2026-10-03', '--out-dir', out]);
    expect(r.status).toBe(1);
    expect(fs.readFileSync(path.join(out, 'MANIFEST.sha256'), 'utf8')).toBe('keep');
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('an empty period still has a complete unsigned pack and an empty records folder', () => {
  const f = setup();
  try {
    const out = path.join(f.dir, 'pack');
    const r = f.run(['--since', '2027-01-01', '--until', '2027-02-01', '--out-dir', out]);
    expect(r.status).toBe(0);
    expect(fs.readdirSync(path.join(out, 'records'))).toHaveLength(0);
    const scope = JSON.parse(fs.readFileSync(path.join(out, 'pack.json'), 'utf8'));
    expect(scope.selected).toBe(0);
    expect(scope.complete).toBe(true);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('CSV subjects that start with spreadsheet formulas are exported as text', () => {
  const f = setup();
  try {
    fs.writeFileSync(path.join(f.repo, 'README.md'), 'extra');
    f.git(['add', '.']);
    f.git(['commit', '-qm', '=1+1'], '2026-10-02T13:00:00Z');
    const out = path.join(f.dir, 'pack');
    const r = f.run(['--since', '2026-10-01', '--until', '2026-10-03', '--out-dir', out]);
    expect(r.status).toBe(0);
    expect(fs.readFileSync(path.join(out, 'summary.csv'), 'utf8')).toContain("'=1+1");
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('the control summary includes unknown and informational findings',()=>{
 const f=setup();try{const out=path.join(f.dir,'pack');expect(f.run(['--since','2026-10-01','--until','2026-10-03','--out-dir',out]).status).toBe(0);const index=fs.readFileSync(path.join(out,'index.md'),'utf8');expect(index).toContain('| UNKNOWN | INFO |');}finally{fs.rmSync(f.dir,{recursive:true,force:true});}
});

test('approval coverage counts supplied metadata even when that commit cannot be replayed',()=>{
 const f=setup();try{const out=path.join(f.dir,'pack'),file=path.join(f.dir,'approvals.json');fs.writeFileSync(file,JSON.stringify({[f.shas[0]]:{approvedBy:[{login:'reviewer'}]}}));expect(f.run(['--since','2026-09-30','--until','2026-10-01','--approvals',file,'--out-dir',out]).status).toBe(1);const scope=JSON.parse(fs.readFileSync(path.join(out,'pack.json'),'utf8'));expect(scope.approvals.supplied).toBe(1);expect(scope.approvals.withReviewers).toBe(1);}finally{fs.rmSync(f.dir,{recursive:true,force:true});}
});
