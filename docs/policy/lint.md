# Policy Linter

The linter runs during **Validate** and **Reload** and returns structured findings:

- **Errors** (block in `block` mode): invalid schema, duplicate rule IDs, regex compile failures.
- **Warnings**: duplicate regex text across rules, greedy `.*`, nested quantifiers that may backtrack.
- **Info**: suggestions like adding `\b` to common PII patterns.

Each finding includes: `severity`, `code`, `message`, `path`, and (optionally) `rule_id`.

> Heuristics are conservative and static — they do not execute regexes on user data.
