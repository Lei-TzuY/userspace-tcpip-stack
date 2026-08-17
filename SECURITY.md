# Security policy

This is an educational packet parser, not a hardened network-security product. It processes attacker-controlled bytes, so memory-safety and denial-of-service findings are still taken seriously.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting flow under the repository's **Security** tab when it is available. If private reporting is unavailable, open a minimal issue asking the maintainer for a private contact channel; do not include exploit details, private captures, credentials, or a working proof of concept in a public issue.

Please include:

- affected commit and platform;
- compiler and sanitizer configuration;
- smallest synthetic input that reproduces the issue;
- expected and observed behavior;
- crash trace or sanitizer output with secrets removed.

## Supported versions

Only the current default branch is maintained. There are no production-support or backport guarantees.

## Scope

Useful reports include out-of-bounds access, use-after-free, integer-overflow paths that affect memory access, unbounded resource consumption, and parser behavior that can be triggered by a capture file.

Protocol-analysis disagreements without a security impact should use the normal bug-report template.
