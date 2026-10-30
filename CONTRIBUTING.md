# Contributing to Diffseal

Issues and bug reports are welcome in the [GitHub issue tracker](https://github.com/diffseal/diffseal/issues). When reporting a false positive, false negative, or parser error, include a minimal `.tf` snippet or plan JSON that reproduces it.

Code contributions require a contributor license agreement. That agreement is not set up yet, so pull requests cannot be merged for now.

## Releasing

Use Bun 1.4.4, the version CI pins. Update the version in `package.json`, run `bun install --frozen-lockfile`, `bun run typecheck`, `bun run build` and `bun test`, then commit the source and the generated `dist/action.js`, `dist/cli.js` and `dist/mcp.js`. CI checks pull requests and pushes to main, including whether the committed bundle matches the source.

Create an annotated `v*` tag on the reviewed commit with the release notes in its message, for example `git tag -a v0.2.1 -F release-notes.md`. Push that tag when ready to publish. The release workflow verifies the tagged build, runs the tests and publishes a GitHub release using the tag message. It attaches an archive containing the CLI, MCP server, Action, licence and README. Tags with a hyphen are marked as prereleases. Lightweight tags are rejected.
