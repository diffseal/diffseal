import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

interface Snapshot {
  name: string;
  files: Record<string, string>;
  gate: string;
  exit: number;
  finding: string;
}
const fixture = path.resolve(
  import.meta.dirname,
  "../fixtures/demo/snapshots.fixture",
);
for (const name of [
  "replace-database",
  "missing-iam-permission",
  "harmless-change",
])
  test(`bundled Action reviews the synthetic demo: ${name}`, () => {
    const snapshots = JSON.parse(fs.readFileSync(fixture, "utf8")) as {
      base: Record<string, string>;
      heads: Snapshot[];
    };
    const scenario = snapshots.heads.find((s) => s.name === name)!;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-demo-"));
    const git = (args: string[]) => {
      const r = spawnSync(
        "git",
        ["-C", dir, "-c", "core.hooksPath=/dev/null", ...args],
        { encoding: "utf8" },
      );
      if (r.status !== 0) throw new Error(r.stderr);
      return r.stdout.trim();
    };
    const write = (files: Record<string, string>) => {
      for (const [p, text] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true });
        fs.writeFileSync(path.join(dir, p), text);
      }
    };
    try {
      git(["init", "-q"]);
      git(["config", "user.name", "Test"]);
      git(["config", "user.email", "test@example.invalid"]);
      write(snapshots.base);
      git(["add", "."]);
      git(["commit", "-qm", "base"]);
      const base = git(["rev-parse", "HEAD"]);
      for (const p of Object.keys(snapshots.base))
        if (!(p in scenario.files)) fs.rmSync(path.join(dir, p));
      write(scenario.files);
      git(["add", "."]);
      git(["commit", "-qm", scenario.name]);
      const output = path.join(dir, "action-output"),
        summary = path.join(dir, "summary.md");
      const result = spawnSync(
        "node",
        [path.resolve(import.meta.dirname, "../dist/action.js")],
        {
          cwd: dir,
          encoding: "utf8",
          env: {
            ...process.env,
            GITHUB_WORKSPACE: dir,
            GITHUB_OUTPUT: output,
            GITHUB_STEP_SUMMARY: summary,
            INPUT_MODE: "pr",
            INPUT_BASE: base,
            INPUT_COMMENT: "false",
            INPUT_ADVISORY: "false",
            INPUT_STRICT: "false",
            GITHUB_EVENT_PATH: "",
            INPUT_POLICY: "",
            INPUT_ROOTS_UNDER: "infra/envs/prod",
          },
        },
      );
      expect(result.status).toBe(scenario.exit);
      expect(fs.readFileSync(output, "utf8")).toContain(
        `gate=${scenario.gate}`,
      );
      const markdown = fs.readFileSync(summary, "utf8");
      expect(markdown).toContain(scenario.finding);
      // A PR comment names the verdict, not the temporary merge commit GitHub checks out.
      expect(markdown.split("\n")[0]).toBe(
        `## TerraTrust: ${scenario.gate.toUpperCase()}`,
      );
      expect(markdown).not.toContain(scenario.name);
      // The footer carries only facts about this pull request; the explanations live in the FAQ.
      const footer = markdown.split("\n").filter((l) => l.startsWith("<sub>"));
      expect(footer).toHaveLength(1);
      expect(footer[0]).toMatch(
        /^<sub>TerraTrust [0-9][^ ]*\. Compared `[0-9a-f]{9}` with `[0-9a-f]{9}`\. \[How it works\]\(https:\/\/github\.com\/TerraTrust\/terratrust\/blob\/main\/docs\/guide\/faq\.md\)<\/sub>$/,
      );
      if (name === "missing-iam-permission") {
        expect(markdown).toContain("dynamodb:Query");
        expect(markdown).toContain("statement {");
        expect(markdown).toContain("aws_dynamodb_table.shipments.arn");
        expect(markdown).toContain("> [!WARNING]");
      }
      if (name === "replace-database") {
        expect(markdown).toContain("hash_key");
        expect(markdown).toContain("loses the items");
        expect(markdown).toContain("> [!CAUTION]");
        // A change whose action depends on apply-time values says so on its own row.
        expect(markdown).toContain("| `module.fulfillment.aws_iam_role_policy.lambda` | update (likely) |");
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30000);
