# CodexQB Project Comprehension Methods

Use this reference when an existing project needs a durable evidence-backed mental model, not just an autopsy finding list.

## Purpose

`Planner-docs/Project-Comprehension.md` captures what CodexQB believes about a project, why it believes it, how confident it is, and what still needs validation.

The artifact is optional. Create it for non-trivial existing projects with distributed domain behavior, unclear architecture boundaries, stale plans, repeated replanning, lifecycle complexity, or runtime behavior that is not obvious from static files.

New generated artifacts should include this schema marker near the top:

```text
codexqb_schema_version: 2
```

## Question-Driven Comprehension

Start with 8-15 question-driven comprehension prompts. Use IDs such as `CQ-01`.

Good questions ask:

- which domain concept maps to which type, module, or data store;
- which entrypoint starts a behavior;
- which path data or control follows at runtime;
- which tests prove the behavior;
- which invariant must hold through the workflow;
- which documented architecture relation differs from source reality.

## Hypothesis Model

Use why/how/what hypotheses before asserting conclusions.

Each hypothesis should include:

- ID, such as `HYP-01`;
- Type: `why`, `how`, or `what`;
- Claim;
- Supporting evidence;
- Contradicting evidence;
- Confidence: `confirmed`, `probable`, `tentative`, or `contradicted`;
- Next validation probe.

Do not treat `tentative` or `probable` claims as implementation facts. Step 2 should convert them into validation work, and Step 4 should verify them before code changes.

If no unresolved hypotheses remain, write:

```text
NO_UNRESOLVED_HYPOTHESES: <evidence-based explanation>
```

## Evidence Register

Use an Evidence Register table:

```markdown
| Evidence ID | Claim Type | Claim | Evidence source | Evidence type | Confidence | Freshness | Contradiction | Next probe |
|---|---|---|---|---|---|---|---|---|
```

Allowed claim types:

- `structural`
- `behavioral`
- `historical`
- `configuration`
- `user_intent`
- `architectural`

Allowed evidence types:

- `source`
- `test`
- `runtime`
- `history`
- `configuration`
- `documentation`
- `user-confirmed`

Confirmed evidence rules:

- `structural`: one direct `source` locator can be enough.
- `configuration`: one direct `configuration` locator can be enough.
- `behavioral`: use `test`/`runtime` evidence, or at least two independent evidence types with different locators.
- `historical`: requires `history` evidence.
- `user_intent`: requires `user-confirmed` evidence.
- `architectural`: requires source/configuration relation evidence, or multiple supporting evidence types with different locators.

Independent evidence must use different evidence types and different locators. Two documentation rows alone are not independent proof.

## Domain-to-Code Trace Map

Use a Domain-to-Code Trace Map to link user/product language to implementation anchors:

```markdown
| Trace ID | Domain concept / feature | Entry points | Core implementation | State/data | Tests | Docs | Confidence |
|---|---|---|---|---|---|---|---|
```

Every major concept should have code/test anchors or an explicit marker. Missing anchors are planning inputs, not facts to smooth over.

Allowed explicit markers:

```text
NOT_APPLICABLE: <reason>
UNKNOWN: <reason and next probe>
```

## Architecture Reflexion

Architecture Reflexion compares intended architecture with implemented source/config relations.

```markdown
| Relation ID | Intended relation | Source evidence | Status | Impact |
|---|---|---|---|---|
```

Allowed statuses:

- `convergent`
- `divergent`
- `absent`
- `unmodeled`
- `uncertain`

Use `ARC-*` IDs in Step 2/3/4 when architecture drift affects planning or implementation.

If architecture reflexion is not applicable, write:

```text
NOT_APPLICABLE: <reason>
```

If the architecture relation is unknown, write:

```text
UNKNOWN: <reason and next probe>
```

## Semantic, Behavioral, And Evolutionary Evidence

Combine evidence types, but keep their limits clear:

- Static source evidence shows structure, names, contracts, and dependencies.
- Behavioral evidence from tests, smoke runs, or runtime probes shows executed behavior.
- Semantic evidence maps domain language to code concepts.
- Evolutionary metadata from named RepositoryIO/controller receipts may show churn, co-change, and possible hidden coupling; if absent, keep those claims unknown instead of querying Git directly.

Receipt-provided history metadata is an evolutionary signal, not proof of ownership or architecture.

## Competency Questions

Ontology competency questions test whether `Project-Ontology.md` can answer the questions future planning depends on.

Use statuses:

- `answered`
- `partially_answered`
- `open`
- `contradicted`

## QAW/ATAM-Lite Scenarios

Use QAW/ATAM-lite only as a lightweight scenario table. Do not claim a full formal ATAM review.

```markdown
| Scenario ID | Source | Stimulus | Environment | Artifact | Expected response | Response measure | Tradeoff/Risk |
|---|---|---|---|---|---|---|---|
```

Prefer 3-5 important scenarios such as modifiability, security, availability, performance, or operability.

## Goal/Question/Evidence

Use a GQM-style Goal/Question/Evidence structure for acceptance criteria:

- Goal: the outcome to evaluate.
- Question: what must be answered to know the goal is met.
- Evidence: the validation command, artifact, metric, or repo fact that answers the question.

This prevents plans from collecting easy metrics that do not prove the intended outcome.
