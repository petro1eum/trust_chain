# apatch manifests (consumer project)

Run apatch from your venv or PATH:

```bash
apatch doctor
npm run apatch:strip-dry -- --file src/pages/YourPage.tsx \
  --manifest manifests/apatch.example.json --out-dir src/features/extracted
npm run apatch:phase -- \
  --manifest manifests/apatch.example.json --file src/pages/YourPage.tsx \
  --module-out-dir src/features/hooks --to-module hook
```

Agent playbook: `AGENTS.md` (from apatch `docs/AGENTS.template.md`).  
Refresh: `apatch init-consumer --refresh-agents` (preserves `<!-- apatch:project:* -->`).
