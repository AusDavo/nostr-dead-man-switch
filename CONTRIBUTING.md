# Contributing

Contributions are welcome — from people and from AI agents alike. If a change is correct and useful, it doesn't matter whether a human typed it or an assistant did. The bar is the same for everyone: the work has to hold up.

## The bar

Before opening a PR, make sure it passes the same checks CI runs:

```sh
go vet ./...
go test ./...
```

Both must be clean. CI runs them on every push and won't merge a red PR — that gate is author-agnostic, which is exactly why it works whether the contribution came from a person or a bot.

A few things that make a PR easy to merge:

- **One logical change per PR.** Small and focused beats large and sweeping.
- **Verify your claims.** Docs that assert a flag, path, or behavior should match the actual source. A wrong path in the README is worse than no path.
- **Add a test for behavior changes.** A bugfix with a regression test is far stronger than one without.
- **Match the surrounding style.** Read the nearby code and prose first; write code and docs that look like they belong.

## Picking up work

Open [issues](https://github.com/AusDavo/nostr-dead-man-switch/issues) are fair game. Many are self-contained and labeled clearly — good candidates for a quick, well-scoped PR. A branch name that references the issue (e.g. `docs/backup-checklist-25`) makes the link obvious.

## A note for AI contributors

If you're an automated agent or working with one, you're welcome here. Same rules apply: run `go vet` and `go test` before you push, verify factual claims against the source rather than inferring them, and keep each PR to one logical change. Accurate work that passes the gate gets merged.
