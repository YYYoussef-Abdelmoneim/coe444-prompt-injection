# Threat model: how the attacker reaches the agent

Written 8 Nov 2026 in answer to the instructor's question at the progress presentation:
*"How would the attacker get in to change the documents or the recipients? Think like the
attacker."* This file is the project's answer; the v0.3 corpus (`advanced_v03.json`) is the
executable version of it.

## Assets, adversary, trust boundary

| | |
|---|---|
| **Asset** | The employee's outbound mail (who receives it, what it contains) and the confidentiality of what the assistant can read (policy documents, inbox). |
| **Agent** | An LLM assistant acting as the employee (Layla), with four tools: `read_inbox`, `search_documents`, `lookup_contact`, `send_email`. It holds exactly the employee's permissions, no more. |
| **Adversary** | An outsider with **no account** on the company systems and no access to the agent's chat. Their only capability is to get text in front of the agent. |
| **Trust boundary** | The line between *information the agent reads* and *instructions the agent may act on*. The attack crosses it when retrieved text changes an action. |

## Entry channels, cheapest first

| # | Channel | What the attacker needs | Real-world precedent | Covered by |
|---|---|---|---|---|
| 1 | **Inbound email** to the employee | Nothing. Anyone can email anyone. The agent reads the inbox because the user asked. | EchoLeak (Microsoft 365 Copilot, 2025, zero-click via email); Gmail/Gemini summary injections | v0.3 families `inbound_email_*`, `impersonation`, `multi_stage` (agent-v3 `read_inbox`) |
| 2 | **Documents the agent retrieves** | One low-privilege insider or compromised account that can edit a wiki/shared drive; or a *vendor-supplied document* (contract, PDF, onboarding pack) ingested into the index | ConfusedPilot (RAG poisoning); Bing Chat web-page injections | v0.2.1 corpus (all document payloads), v0.3 `hidden_text`, `conditional_trigger`, `url_exfil` |
| 3 | Calendar invites, tickets, CRM notes, chat messages the agent is later given tools for | As 1 | Zapier / Slack assistant injections | Not in this environment; same mechanism and same defenses as 1 (every tool result is EXTERNAL) |

Channels 1 and 2 are the ones we evaluate. Channel 3 is a scope statement.

## What the attacker does once the text is in front of the agent

| Goal | Shape | v0.2.1 | v0.3 |
|---|---|---|---|
| Add themselves to the recipients of mail the user is already sending | ride-along CC/BCC | `ride_along_cc` | `inbound_email_cc`, `hidden_text`, `detector_targeted`, `conditional_trigger`, `lookalike_domain`, `multi_stage` |
| Redirect the user's mail to themselves | recipient swap | `ride_along_swap` | `inbound_email_swap`, `impersonation` |
| Get document content out while the recipient stays legitimate | body / reply / URL exfiltration | `content_exfiltration`, `reply_channel_exfil` | `url_exfil`, `hidden_text` (HTML comment), `conditional_trigger` (topic) |
| Stop the user getting what they asked for | availability | `goal_hijack` | — |
| Make the agent act on no user action at all | standalone | `naive_standalone` | — (kept at near-zero on purpose) |

## How the attacker hides (evasions)

- **From the human reviewer**: zero-width characters inside key words; Unicode tag characters
  ("ASCII smuggling"); HTML comments; fullwidth homoglyphs; lookalike domains (`northvvind`,
  `northwind-records.example`).
- **From the classifier**: text that asserts it is not an instruction; descriptive prose with no
  imperative; conditions that only fire for the real target (recipient or topic).
- **From spot-checking**: multi-stage (rule planted earlier, triggered later); conditional triggers.
- **By borrowing authority**: forged internal `From:` lines (IT Security, the manager) — BEC
  aimed at the assistant instead of the human.

## What we assume the attacker cannot do

- Talk to the agent directly. A direct-chat attacker already holds the employee's session; the
  agent obeying them is an authentication/authorisation failure (CLO2), not injection. Our gate
  still refuses to launder a recipient through planted text, and the review step still shows the
  human the exact recipients, but neither claims to stop a user who approves their own attack.
- Change what the search index ranks. The payload is inserted after ranking (limitation, stated).
- Modify the agent's code, tools or system prompt.

## Where each defense sits against this model

```
attacker text ──> [sanitize-v1: hidden text made visible] ──> [detector-v3a: span removed] ──> agent reads
agent proposes send_email ──> [gate-v2: recipients must trace to user or directory] ──> [human review] ──> MailSink
```

- **sanitize-v1** defeats the *human-review* evasions by making them visible to the detector.
- **detector-v3a** is the only layer that acts on content (body/reply/URL exfiltration, goal hijack).
- **gate-v2** is deterministic on recipients and is the backstop when the detector wobbles
  (PI-120 case, 8 Nov).
- **review** is the last line against anything that reaches a protected send; the lookalike
  warning exists because the reviewer is the target of that family.

**Residual risk, stated:** an exfiltration payload that the detector scores below threshold and
that uses only legitimate recipients passes every layer. Only detection covers it, and detection
is probabilistic.
