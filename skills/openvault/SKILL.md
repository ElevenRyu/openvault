---
name: openvault
description: Find and use the user's secrets (API keys, tokens, passwords) without ever seeing them. Use whenever a command needs a credential — GITHUB_TOKEN, OPENAI_API_KEY, DATABASE_URL, cloud keys — or when the user mentions openvault, `ov`, `.openvault.toml` or a `secret://` ref.
---

# Using secrets with openvault

openvault (`openvault`, alias `ov`) is the user's secrets vault. You can **discover**
secrets and **use** them in commands, but you never see their values — and you
must not try to.

## Rules

1. **Never ask the user to paste a secret** into the chat, a file, or a command.
   If a secret is missing, ask the user to run `openvault add <name> --env VAR`
   themselves (it prompts with hidden input).
2. **Never use `openvault get`, `--reveal` or `--no-redact`.** They are for humans
   at a terminal and will refuse you anyway.
3. **Never write secret values to files**, `.env` files, logs or commit messages,
   and never try to decode `[REDACTED:…]` output.
4. Do not edit `.openvault.toml` to widen access unless the user asked you to.
5. A Touch ID prompt on the user's Mac is expected when you run a command that
   uses secrets — tell the user why you need it.

## Discover

```sh
openvault env --json                 # env vars this project can use (from .openvault.toml + scoped secrets)
openvault search github --json       # fuzzy search names, env vars, descriptions, tags
openvault ls                         # all secret names
```

Results contain refs like `secret://github/token` and env var names — never values.

## Use

```sh
# By env var name (resolved via .openvault.toml and secret metadata):
openvault run --env GITHUB_TOKEN -- gh api user

# By ref (VAR=ref to choose the variable name):
openvault run --only secret://github/token -- gh api user
openvault run --only GH_TOKEN=github/token -- gh pr list

# A project with .openvault.toml [env] mappings needs no flags:
openvault run -- npm test

# Env values that are refs get resolved:
DATABASE_URL=secret://myapp/database_url openvault run -- ./migrate
```

Output is redacted: any injected value (and its base64/hex/URL encodings)
appears as `[REDACTED:<name>]`. That is normal — do not work around it.

## MCP

If the `openvault` MCP server is configured (`openvault mcp`), prefer its tools:
`search`, `list_env`, and `run` (argv array + `env` names or `refs`). They follow
the same rules and never return values.

## Project setup (when the user asks)

```toml
# .openvault.toml — commit this; it contains refs, never values
[env]
GITHUB_TOKEN = "secret://github/token"
OPENAI_API_KEY = "secret://openai/key"
```

Existing `.env` file? Ask the user to run
`openvault import --from-env-file .env --shred` — keys become discoverable env vars.
