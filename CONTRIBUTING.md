# Contributing

Thanks for taking the time to improve RustHound-CE. Small, focused pull requests are easier to review and make it safer for new contributors to learn the codebase.

## Before you start

Check the [roadmap](ROADMAP.md), existing pull requests, and recent commits before choosing a task. You can also browse the issues containing `[Feature Request]` to see actions requested by the community in addition to the roadmap items. If the change is large, affects several object types, or changes the output contract, open an issue or discussion first.

Please do not include credentials, domain data, collection output, private certificates, or other sensitive information in commits, tests, screenshots, or pull requests.

## Development setup

RustHound-CE requires a current Rust toolchain. Clone your fork and create a branch from the latest `main`:

```bash
git clone https://github.com/<your-user>/RustHound-CE.git
cd RustHound-CE
git remote add upstream https://github.com/g0h4n/RustHound-CE.git
git fetch upstream
git switch -c fix/short-description upstream/main
```

Build and test the project with:

```bash
make debug
cargo test --all-targets
cargo clippy --all-targets -- -A warnings
```

The `Makefile` is also the reference for release and cross-compilation targets. Use `make help` to list the supported targets. On Windows, run these targets through WSL or another environment that provides GNU Make; the Cargo commands above can be used directly when Make is unavailable.

## Code changes

Keep one bug fix, feature, test improvement, or documentation change per pull request. Match the surrounding Rust style and avoid reformatting unrelated files. Keep new modules focused; split a change when a file starts mixing unrelated responsibilities.

Add tests for non-trivial parsing and conversion logic. The project keeps unit tests inline at the bottom of the relevant Rust module:

```rust
#[cfg(test)]
mod tests {
    // focused tests go here
}
```

Comments should explain intent or an unusual constraint. Keep informal comments sparse and tied to the code they describe.

## Pull requests

Before opening a pull request, update your branch from `upstream/main`, run the relevant tests, and inspect the complete diff:

```bash
git fetch upstream
git rebase upstream/main
git diff upstream/main...HEAD --check
git status --short
```

The pull request description should explain the problem, the chosen approach, the scope, and the commands used for validation. If the change addresses a roadmap item or issue, link it directly.

Please respond to review comments with focused commits and keep unrelated cleanup in a separate pull request.

## Commit messages

Use short English commit messages in imperative form. Conventional prefixes are preferred:

```text
fix: handle missing LDAP attribute
feat: collect a new domain property
test: cover SID conversion
docs: clarify local development
```

## Security reports

Do not disclose security-sensitive findings in a public issue. Follow the project maintainer's preferred private reporting channel and include only the information needed to reproduce and fix the problem.
