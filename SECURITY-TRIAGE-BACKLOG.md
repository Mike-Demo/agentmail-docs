# Security audit remediation backlog

Issue creation is not available in this session, so this document contains the prioritized, paste-ready issues requested by [parent issue #1](https://github.com/Mike-Demo/agentmail-docs/issues/1).

## Priority order

1. **Medium: Verify signatures in copy-paste webhook examples.** Public webhook handlers accept forged requests and use the operator's API key to reply or apply labels, making this the most directly reachable finding.
2. **Medium: Remove shell interpolation of changed filenames.** A pull-request author can control filenames expanded into a shell script in a workflow with write permissions; exploitation requires a crafted PR and workflow run.
3. **Low: Harden the GitHub-star agent's prompt and reply handling.** Its public handler trusts email content, sends model output as HTML, and shares history across senders. Its impact depends on the example being deployed and reached.
4. **Informational: Pin Fern CLI in PR workflows.** This is a supply-chain exposure in workflows with secrets or write permissions, but the audit found no evidence of a malicious Fern CLI version.

The auto-reply and smart-labeling examples are grouped together because the confirmed root cause and smallest fix are the same: both parse and act on an unverified webhook payload. The GitHub-star example remains a separate issue because prompt injection, HTML output, and cross-sender history are additional root causes.

## Confirmed findings

### `[security][medium] Verify signatures in copy-paste webhook examples`

**Body**

Parent: [Security audit 2026-10-21 — prioritize findings and create remediation issues](https://github.com/Mike-Demo/agentmail-docs/issues/1)

**Evidence:** `fern/pages/examples/auto-reply-agent.mdx` and `fern/pages/examples/smart-labeling-agent.mdx` parse webhook payloads directly from `request.json` and act on payload fields without importing Svix or calling `Webhook.verify`. The auto-reply example uses the parsed sender and message details to call `messages.reply` with the operator's AgentMail client. The smart-labeling example classifies the submitted email and applies labels using submitted identifiers. In contrast, `fern/pages/webhooks/webhook-verification.mdx` documents verifying the raw body with `Webhook.verify` before processing it.

**Root cause:** Both example webhook handlers trust parsed request JSON without verifying the Svix signature before using message, inbox, and sender fields.

**Smallest fix:** In both examples, read the raw body, instantiate `svix.webhooks.Webhook` with `os.environ["AGENTMAIL_WEBHOOK_SECRET"]`, and call `verify(body, request.headers)` before parsing or acting on the payload. Return HTTP 400 on `WebhookVerificationError`, following `fern/pages/webhooks/webhook-verification.mdx`.

**Fingerprint:** `example-webhook-receivers-no-svix-verification`

### `[security][medium] Prevent changed-filename injection in update workflow`

**Body**

Parent: [Security audit 2026-10-21 — prioritize findings and create remediation issues](https://github.com/Mike-Demo/agentmail-docs/issues/1)

**Evidence:** `.github/workflows/update-last-updated.yml` runs on pull request opened/synchronize events, grants `contents: write` and `pull-requests: write`, checks out the PR head with the persisted `GITHUB_TOKEN`, and inserts `steps.changed-files.outputs.all_changed_files` unquoted into the `run` script's `for` loop. The workflow later runs `git add -A` and pushes to the PR branch. Since the Actions expression is expanded before Bash parses the script, a PR-controlled filename containing shell syntax can be interpreted as commands.

**Root cause:** PR-controlled changed-file names are textually interpolated into a Bash script in a job holding a `contents: write` token.

**Smallest fix:** Pass the changed-file output through an environment variable, then iterate over it without placing the expression in the script and quote `$file` at every use. Alternatively, use a checked-in script that reads the environment variable.

**Fingerprint:** `update-last-updated-workflow-filename-injection`

### `[security][low] Isolate and safely render GitHub-star agent email content`

**Body**

Parent: [Security audit 2026-10-21 — prioritize findings and create remediation issues](https://github.com/Mike-Demo/agentmail-docs/issues/1)

**Evidence:** `fern/pages/examples/github-star-agent.mdx` has an unverified `/webhooks` handler that passes `request.json` to `process_webhook`. That function interpolates the email sender, subject, and text into a user-role prompt, runs the agent with one global accumulated message history shared across senders, and sends `response.final_output` directly as the `html` reply body without escaping, sanitization, or an allowlist. The reply has no `to=` override, so it goes to the thread sender.

**Root cause:** Untrusted email content is used as model instructions without instruction/data separation; model output is sent as unsanitized HTML; and conversation history is shared across senders.

**Smallest fix:** Clearly delimit email content as untrusted data and add an explicit system instruction not to follow instructions inside it. Send the reply as text, or sanitize HTML using a tag allowlist. Scope conversation history per thread, and verify the raw webhook body with Svix before processing it, following `fern/pages/webhooks/webhook-verification.mdx`.

**Fingerprint:** `github-star-agent-prompt-injection-html-reply`

### `[security][informational] Pin Fern CLI in pull-request workflows`

**Body**

Parent: [Security audit 2026-10-21 — prioritize findings and create remediation issues](https://github.com/Mike-Demo/agentmail-docs/issues/1)

**Evidence:** `.github/workflows/preview-docs.yml`, `.github/workflows/check.yml`, and `.github/workflows/api-changelog.yml` install `fern-api` with `npm install -g fern-api`, without a version, lockfile, or integrity hash, and execute the installed CLI in later steps. The preview workflow runs Fern while `FERN_TOKEN` and `POSTHOG_PROJECT_API_KEY` are present. `.github/workflows/publish-docs.yml` and `.github/workflows/release-sdks.yml` instead pin the CLI to the version in `fern/fern.config.json` (currently `5.44.8`). The audit found no evidence that a malicious Fern CLI version exists; this is an informational supply-chain exposure.

**Root cause:** Three PR-triggered workflows install an unpinned Fern CLI, inconsistently with the pinned installation in the release workflows.

**Smallest fix:** Use the pinned install pattern from `.github/workflows/publish-docs.yml` in `preview-docs.yml`, `check.yml`, and `api-changelog.yml`.

**Fingerprint:** `ci-unpinned-fern-api-executed-with-secrets`

## Needs-validation leads

### `[security][needs-validation] Audit leads to validate`

**Body**

Parent: [Security audit 2026-10-21 — prioritize findings and create remediation issues](https://github.com/Mike-Demo/agentmail-docs/issues/1)

Please validate each lead and report the missing fact listed below. These are unconfirmed leads and intentionally have no severity.

- [ ] **Agent sign-up key rotation keyed on human email** (`agent-signup-key-rotation-keyed-on-human-email`): The AgentMail server implementation (not in this repo): whether an unauthenticated repeat `POST /v0/agent/sign-up` with an existing `human_email` (a) invalidates the victim organization's existing API key, and (b) returns a working new `api_key` to that unauthenticated caller, versus requiring the same username or OTP verification first.
- [ ] **MCP manifest rendering in published MDX** (`mcp-manifest-fetch-unpinned-unsanitised-mdx-render`): Whether Fern's MDX compiler honours MDX/JSX-significant content (angle brackets, braces, component tags) inside a table cell of `fern/snippets/mcp-tool-catalog.mdx` as live MDX/JSX on the published docs site, or renders it as inert text.
