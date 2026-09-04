# demo Specification

## Purpose
TBD - created by archiving change add-llm-driven-demo. Update Purpose after archive.

## Requirements

### Requirement: Live agent mode
`toolgate demo --live` SHALL run the scenario with tool selection decided by a real LLM through the standard integrations dispatch, printing the model's tool calls and the gate's decisions in the existing transcript format.

#### Scenario: Live run
- **WHEN** `toolgate demo --live` runs with ANTHROPIC_API_KEY set
- **THEN** the six acts execute with model-chosen calls and end with a VALID chain verification

### Requirement: Prompt-injection containment act
The live demo SHALL include an act where browsed content contains an injection instructing data exfiltration via an allowed side-effecting tool, and the taint policy SHALL park or deny the attempt on stage.

#### Scenario: Injection attempt
- **WHEN** the model ingests the hostile page and attempts send_email with exfiltrated content
- **THEN** the gate parks it under the tainted-task rule and the transcript shows the containment

### Requirement: Hermetic default
Without `--live` (or without an API key) the demo SHALL run fully offline exactly as today; CI SHALL NOT require network or API keys.

#### Scenario: No key
- **WHEN** `toolgate demo --live` runs without a key
- **THEN** it exits non-zero with a one-line explanation and the offline command suggestion
