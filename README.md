# AI-Skill

A backup of the existing agentic security skills currently used for certification exams, pentests, and CTFs.

No new skills were created. The repository contains only the existing security workflows, with their original files preserved.

## Included

| Source | Skill folders |
| --- | ---: |
| OpenCode security library | 27 |
| Shared agent security skill | 1 |
| **Total** | **28** |

```text
skills/
  opencode/      # existing exam, pentest, CTF, and research skills
  shared-agent/  # existing maldev-academy skill
catalog/
  categories.md       # category navigation without duplicated skills
  certifications.md   # certification/exam routing
  skill-index.tsv     # one row per existing skill
  exclusions.md       # deliberately omitted content
```

See [the catalog](catalog/README.md) to browse by category or certification.

## Safety

- Private CPENT reports and evidence are excluded.
- Credential-style files and local environment files are ignored.
- Review any skill before running it; many contain lab-specific tool or path assumptions.
