# Repo-Aware Step 1 Intake

Use this reference before `First-Planner.md` when CodexQB starts a normal Step 1 planning run.

The goal is to ask the same four required fields, but make the questions active, evidence-backed, and useful for an existing repository.

## Boundaries

- Ask in the user's language.
- Ask one question at a time.
- Use plain text only. Do not use pop-ups, forms, or multiple-choice UI.
- Do not write files during intake.
- Do not run networked, destructive, install, commit, push, deploy, or PR commands.
- Treat the current working directory as the project repository.
- Make it clear when a statement is inferred from repo evidence.
- If evidence is weak, say that repo evidence is limited and ask the concise generic version of the question.

## Pre-Intake Scan

Before asking `PROJECT_NAME`, inspect the repository with the bounded `intake`
profile:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller repository-io -- request-stdin
```

Invoke that fixed command once per request and send each bounded JSON object
directly through the host process API to the child process's stdin:

```json
{"schema":"codexqb.controller-argv/v1","argv":["--root",".","inspect","--profile","intake"]}
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["--root",".","search","--profile","intake"]}
```

Do not materialize these requests with echo, printf, a pipe, redirection, a
heredoc, command substitution, environment variables, shell interpolation, or
a temporary/repository file. If direct host-to-child stdin is unavailable,
stop as `BLOCKED`.

Retain both RepositoryIO receipts. They are the only pre-intake repository
inventory/search evidence. Branch, dirty-state, and workspace posture may be
taken only from controller-owned workspace evidence already bound to the
current Goal/Apply run. If that evidence is unavailable, record the workspace
posture as unknown; do not fall back to Git or shell commands.

Read likely evidence files when they exist:

- `README.md`
- `AGENTS.md`
- `Makefile`
- `package.json`
- `pyproject.toml`
- `Cargo.toml`
- `go.mod`
- `docker-compose.yml` or `compose.yml`
- `.github/workflows/*.yml`
- `docs/` index, architecture, roadmap, runbook, deployment, security, or testing files
- top-level service, package, app, config, script, test, and infra directories

The named search profile returns only signal labels, counts, paths, and line
locations; it never returns matching source lines. Do not substitute arbitrary
repository-content search commands.

Keep this pass brief. Its purpose is to make the intake questions smarter, not to replace the full repository analysis in `First-Planner.md`.

## What To Infer

Infer a draft answer only when there is evidence.

- `PROJECT_NAME`: prefer README title, package/app name, repository directory name, product docs, or manifest names.
- `PROJECT_INTENT`: infer what the project does, its target users, main components, integrations, and what it seems to be trying to become.
- `TARGET_END_STATE`: draft the "done" state across product, engineering, operations, security, and user value.
- `KNOWN_CONSTRAINTS`: infer stack, deployment model, test commands, CI, compliance/security boundaries, must-use tools, must-not-use tools, timeline hints, desired autonomy, human review cadence, token/usage budget if present, and unknown constraints that need user confirmation.

Do not treat inferred values as final until the user confirms or edits them.

## Question Style

Start with a short setup sentence:

```text
I will ask four short questions one by one. I will enrich the questions with evidence I saw in the repository; after your answers, I will generate the main plan.
```

Translate this sentence to the user's language when the user is not writing in English.

### Question 1 / 4 - PROJECT_NAME

Use this shape:

```text
Question 1 / 4 - PROJECT_NAME (Project Name)

Let's clarify which project this plan is for.

Based on what I saw in the repository, this project appears to be "<inferred name>". Evidence: <short evidence such as README title, package name, or repo folder>.

Should I use "<inferred name>" as the project name, or should I use a different official name?
```

If evidence is weak:

```text
Question 1 / 4 - PROJECT_NAME (Project Name)

Repository evidence is limited, so I need you to clarify the project name.

Which project name should this plan use?
```

After the answer, confirm:

```text
PROJECT_NAME = "<final value>" has been saved.
```

### Question 2 / 4 - PROJECT_INTENT

Use this shape:

```text
Question 2 / 4 - PROJECT_INTENT (Project Purpose)

This field explains why the project exists and what it is trying to become.

Here is the draft I inferred from the repository:

<1-2 concise paragraphs describing inferred intent, components, target users, and direction.>

Questions:

1. Is this description correct, or are there points you want to correct or add?
2. What is the final target this project is trying to reach?

You can answer in a few short sentences; I will turn it into professional plan text.
```

After the answer, confirm the stored value in one sentence:

```text
PROJECT_INTENT saved: <brief normalized summary>.
```

### Question 3 / 4 - TARGET_END_STATE

Use this shape:

```text
Question 3 / 4 - TARGET_END_STATE (Target End State / Definition of Done)

I want to clarify the definition of done from five angles. Here is the draft I prepared from repository evidence:

- Product: <product outcome>
- Engineering: <engineering outcome>
- Operations: <operations outcome>
- Security: <security outcome>
- User value: <user-value outcome>

Do these five dimensions reflect your definition of done? Is there anything you want to add, remove, or change?
```

After the answer, confirm:

```text
TARGET_END_STATE saved: <brief normalized summary>.
```

### Question 4 / 4 - KNOWN_CONSTRAINTS

Use this shape:

```text
Question 4 / 4 - KNOWN_CONSTRAINTS (Known Constraints)

Here is the constraint draft I saw in the repository or could not yet confirm:

- Stack/tools: <detected stack or unknown>
- Operations/infra: <detected deployment/runtime or unknown>
- Test/validation: <detected commands or unknown>
- Security/compliance: <detected boundaries or unknown>
- Time/team/budget: <known if present, otherwise unknown>
- Autonomy/review cadence: <desired automation level or unknown>
- Token/usage budget: <known if present, otherwise unknown; do not invent exact spend>
- Must-use / must-not-use: <known if present, otherwise unknown>

Is there anything I should add, correct, or specifically avoid in this list? If you have a weekly/monthly Codex or token budget, share it so I can describe rough Goal-mode usage risk as low/medium/high instead of guessing exact spend.
```

After the answer, confirm:

```text
KNOWN_CONSTRAINTS saved: <brief normalized summary>.
```

## After Intake

When all four fields are confirmed:

1. Read `references/First-Planner.md`.
2. Substitute the confirmed field values.
3. Treat user-confirmed field values as source of truth.
4. Treat repo-inferred intake notes as supporting context only.
5. Continue with the full Step 1 repository analysis required by `First-Planner.md`.


## Vibecoding and Continuity Note

When prior `Planner-docs/Planing-Ledger.md`, `Planner-docs/Project-Ontology.md`, or `Planner-docs/Project-Comprehension.md` exists, summarize their relevance briefly in the intake. Do not treat them as final truth; use them to ask better questions and to avoid losing prior implementation context.
