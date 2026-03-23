---
globs: CLAUDE.md,README.md,.claude/**/*.md
---

# Documentation Framing

README.md and CLAUDE.md cover the same project facts but serve different audiences:

- **README.md** targets human readers (contributors, users, evaluators). It *persuades* — explaining why choices were made, selling the tool's value, and providing onboarding context. It should be comprehensive and welcoming.
- **CLAUDE.md** and `.claude/rules/*.md` target AI agents. They *instruct* — giving direct, imperative rules with no justification needed. "Use thiserror with `#[from]`" not "we chose thiserror because...".

When editing either file:

- Keep both files up to date with the same underlying facts (commands, architecture, conventions).
- Do not merge their styles. README explains; CLAUDE.md commands.
- Do not import README.md into CLAUDE.md via `@README.md` — the persuasive framing wastes agent context.
- Scoped rules (`.claude/rules/*.md`) are preferred over CLAUDE.md for file-specific instructions. CLAUDE.md holds cross-cutting project context only.
- Rules use `globs:` frontmatter to activate only when editing matching files — this is more context-efficient than putting everything in CLAUDE.md.
