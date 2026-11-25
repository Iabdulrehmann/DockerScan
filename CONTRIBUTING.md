# Contributing

Thanks for considering a contribution to DockerScan.

## Before opening a pull request

1. Open an issue for a significant feature or behavior change.
2. Keep changes focused and explain the security impact.
3. Never commit real credentials, private image layers, or scan reports containing sensitive data.
4. Add or update a small reproducible test fixture when practical.
5. Update the README when changing supported inputs, checks, or command-line options.

## Local setup

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Pull requests

Include a concise summary, steps to reproduce or test, and screenshots for visible GUI changes. Do not claim a security check is complete unless its behavior has been tested against an appropriate fixture.
