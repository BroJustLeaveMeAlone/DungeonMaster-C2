# DungeonMaster — Project Rules

Inherits all rules from the workspace CLAUDE.md. Additional project-specific rules:

## No AI attribution
Never add `Co-Authored-By`, `Generated with Claude`, or any AI authorship marker to commits, comments, or documentation in this repo.

## Secrets
All credentials and secrets must live in `.env` (gitignored). Never hardcode passwords, API keys, or tokens in `docker-compose.yml`, source files, or any committed file. Use `.env.example` as the committed template with placeholder values only.

## Sensitive operations
This repo contains offensive security tooling. Do not push to public repositories without explicit instruction. Confirm before any `git push`.
