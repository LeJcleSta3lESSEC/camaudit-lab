# Contributing

Contributions must preserve CamAudit's defensive scope.

Before opening a PR:

```bash
pytest
ruff check .
mypy src
```

Do not contribute features that brute force, exploit, bypass authentication, alter camera settings, capture feeds, or scan unauthorized targets.
