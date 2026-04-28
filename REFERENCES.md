# References

Background material for building VyberSecurity. Read but do not copy verbatim unless explicitly noted.

## Source repos to mine

| Repo | License | What to take | Notes |
|---|---|---|---|
| [mahsumaktas/vibe-guard](https://github.com/mahsumaktas/vibe-guard) | MIT | Regex patterns, AI-pattern checks, .cursorrules generator | Primary source. Their patterns cover 80% of what we need. Attribute in ATTRIBUTION.md |
| [firetix/vibe-coding-penetration-tester](https://github.com/firetix/vibe-coding-penetration-tester) | Apache 2.0 | Multi-agent orchestration, report templates | Apache requires NOTICE file. Add it before importing anything |
| [abenstirling/VibeSecurity](https://github.com/abenstirling/VibeSecurity) | MIT | Web vulnerability checks | Attribute in ATTRIBUTION.md |
| [iris-sast/iris](https://github.com/iris-sast/iris) | MIT | Whole-repo cross-file data flow approach | Adapt the methodology, do not copy code wholesale |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | The SAST engine itself | Subprocess only. Never import as library, never modify Semgrep source. Clean LGPL boundary |
| [anshumanbh/securevibes](https://github.com/anshumanbh/securevibes) | AGPL-3.0 | DO NOT COPY | Read for STRIDE inspiration only. Write our STRIDE template clean-room from scratch |
| VibeDoctor (vibedoctor.io) | No public license | DO NOT COPY | All rights reserved by default |

## Antigravity-specific patterns to add

These are not in any OSS scanner. Russell's stack-specific patterns to detect (Antigravity = Russell's project umbrella, distinct from the VyberSecurity tool name):

- Telegram bot tokens: `\d{8,10}:[A-Za-z0-9_-]{35}` format
- Webhook HMAC patterns Russell uses (see voice-agent/scripts for examples)
- Expo `EXPO_PUBLIC_` misuse (catching backend-only secrets behind public prefix)
- Antigravity .env structure inconsistencies (bare keys without variable names)
- Supabase service_role exposed to client (catch via NEXT_PUBLIC_SUPABASE_SERVICE_ROLE)
- Telegram per-agent config path leaks (see Russell's reference_telegram_per_agent_config memory)

## Russell's known security baseline (April 2026)

Tool MUST flag these on first scan of his projects. They are the canary tests:

1. Callitin: Google refresh tokens stored unencrypted in `google_tokens` table
2. Spoon Admin: Cookie auth uses literal string "granted", trivially forgeable
3. Voice Agent: `/admin` route unauthenticated, exempt in middleware with TODO
4. Lead Gen: Zero authentication on all endpoints, CORS set to *
5. `pokemon iphone theme/generate-icons.py:12` hardcoded Gemini key
6. `PodcastPipeline/src/utils.py:134` hardcoded API key
7. API key reuse: same OpenAI/Anthropic keys in 3+ project .env files
8. `.env.vercel` not gitignored in spoon-admin
9. No `.gitignore` in Lead Gen backend directory
10. Malformed .env in Callitin agent-server (bare OpenAI key without variable name)

If the scanner misses any of these, Phase 2 is not done.

## Architecture (reference)

Four-layer pipeline:

```
project files
    |
    v
[Layer 1] Pattern scan (seconds)
  Vibe-Guard regex + Antigravity patterns + Semgrep subprocess
    |
    v
[Layer 2] LLM triage (1-2 min)
  Claude Sonnet 4.6 classifies findings, filters via project_security_audit
    |
    v
[Layer 3] STRIDE threat model (on demand, clean-room)
    |
    v
[Layer 4] DAST (quarterly, Playwright-based)
```

## Tech stack

- Python 3.11+
- Click (CLI)
- Pydantic (config + result schemas)
- Anthropic SDK with prompt caching
- Semgrep CLI as subprocess
- pytest + ruff
- Husky for git hooks
- GitHub Actions for CI

## Russell's standards (always apply)

- No em-dashes in any output, docs, or comments. Russell hates them
- Security: every commit must pass security-reviewer agent before push
- TDD: write tests first per his global testing.md rules
- Coding style: immutability, small files (<800 lines), explicit error handling
- See his global rules at `C:/Users/Russell/.claude/rules/common/` for the full set

## Russell's contact

- Telegram chat_id: 1606798823
- Use plugin:telegram:telegram reply tool to ping him with progress or blockers
