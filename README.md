# AI-Skill

A backup of the 28 existing agentic cyber skills currently used for certification exams, pentests, and CTFs.

This is not a mirror of local desktop/browser skills or general Codex/Claude provider plugins. No new skills were created; the original cyber workflows are preserved as-is.

## Layout

```text
skills/
  agentic-cyber/  # existing exam, pentest, CTF, and security-research skills
catalog/
  categories.md       # category navigation without duplicated skills
  certifications.md   # certification/exam routing
  skill-index.tsv     # one row per existing skill
  exclusions.md       # deliberately omitted material
```

See [the catalog](catalog/README.md) to browse by category or certification.

## Safety

- Private CPENT reports and evidence are excluded.
- Credential-style files and local environment files are ignored.
- Review any skill before running it; many contain lab-specific tool or path assumptions.
