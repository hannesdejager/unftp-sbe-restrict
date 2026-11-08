# AGENTS.md

## Repository overview

`unftp-sbe-restrict` wraps a `unftp-core` storage backend and checks the user's
`VfsOperations` permissions before selected FTP operations. The implementation is in `src/lib.rs`.

## Development

- Keep the permission check on every operation that is meant to be restricted.
- Treat `UserWithPermissions`, `VfsOperations`, and `RestrictingVfs` as public APIs.
- Follow the existing async trait and storage error conventions; avoid blocking work in async methods.
- Keep public API documentation and README examples accurate and compilable.
- Run `cargo fmt --all`, the relevant tests, and `make pr-prep` before submitting changes.

## Release conventions

- Run `cargo upgrade -v`, review incompatible updates separately, and check the resulting lockfile.
- Review changes since the last published version before choosing a version. For `0.y.z` with
  `y > 0`, increment `z` for compatible changes and `y` for breaking changes.
- Update the package version, dependency examples, `html_root_url`, and release notes together.
- Run `make pr-prep` and `cargo publish --dry-run` before publishing.
- Run doctests and build every example with `cargo build --examples`. If runnable examples are
  added, start them and verify the permissions they demonstrate through an FTP client.
- Use a release commit naming the crate and version. Tags use `v{version}`.
- Do not publish, tag, push, or create a GitHub release without the user's explicit request.

## Git commit messages

- Do not use conventional commits.
- Separate the subject from the body with a blank line.
- Keep the subject around 50 characters, capitalize it, use the imperative mood, and omit
  the final period.
- Wrap the body at 72 characters. Explain what changed and why for the next reader of `git log`.
