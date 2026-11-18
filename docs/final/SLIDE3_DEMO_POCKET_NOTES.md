# Slide 3 + Demo — pocket notes (Youssef)

## The idea under everything
- Origin stamp: USER / DIRECTORY / EXTERNAL set by WHICH TOOL returned the text. Model never sees it.
- Model's flaw: one text stream, no boundary between "user said" and "data". Can't fix the model → control what it reads and what it sends.

## Four stages, two defenses
| | What | How (code) | Blind spot |
|---|---|---|---|
| 1 Sanitize (Detection) | expose hidden text | regex/Unicode: zero-width, tag chars, HTML comments, full-width; exposes, doesn't delete | Cyrillic look-alikes |
| 2 Detector (Detection) | "what would this text make an assistant DO?" | 2nd model + our rubric (5 action triggers + not-an-injection clause); structured answer; 3× max; ≥0.10 → cut quoted sentence; bad answer = flagged | polite text (PI-105 → 0.05) |
| Agent | gpt-oss-20b, same in A–D | prompt names 4 tools only — never hardened | deliberately naive |
| 3 Gate (Prevention) | "where did these bytes come from?" | To/CC/BCC/links traced to USER/DIRECTORY → keep (outside domain → confirm); else strip not deny; swapped To → restore; never reads meaning; never imports detector | content with no address/link (body canary 15/15 passed) |
| 4 Review (Prevention) | human is the authority | bytes frozen server-side; shows what was removed; approve/reject/override → security notice | never measured (simulated in eval) |

- Land: "Detection misses polite text. The gate can't see content. Each one's blind spot is the other's strength." (0.05 → gate 3/3 · body code → gate passed 15/15, detector caught 15/15)
- Cut, not abort: abort lost the task 30/30; vs refuse-attack, aborting IS losing.

## Facts to say precisely
- Not trained. Rubric + one number 0.10, dev, 13 Oct, never moved. Rubric: defense/detection.py SYSTEM_PROMPT.
- Keyword AUC 0.58 · Prompt Guard 2 0.77 · ours 0.99 on 253 Microsoft excerpts (5/50 missed, 0/203 FA).
- Test split 13 sealed → run once 9 Nov. Later changes = dated amendments METHODOLOGY §5A.
- 41 attacks / 9 families: 10 dev (dropdown), 13 sealed (never in UI), 18 advanced (report).

## "Prompt never hardened"
- Never wrote "ignore instructions in emails". Reads attacker's sentence like Sara's.
- Why: bypassable (more text in same window); and results would be unattributable. Invariant; deployment would add it as 5th layer.

## "What is this attack exactly?"
- Indirect prompt injection, zero-click. Attacker never touches the assistant; instruction placed where it will read; obeyed as if from user. Needs: one text stream · free entry (email) · rule-like wording · a tool that acts (send_email BCC).
- vs phishing: fools the machine, not the person — no email defense is in the loop when a machine reads mail.
- Family ride_along_cc; OWASP LLM01; EchoLeak CVE-2025-32711 (Copilot 2025; leak via link; 3 defenses bypassed; fixed server-side; chain not class).

## "Then everything is injection — what else?"
- One class on purpose: specific to agents, no working fix.
- Inside: doors (inbox · document · two-email) × goals (add/swap recipient · leak body/reply/URL · derail · takeover) × disguises (polite · forged From · look-alike · invisible Unicode · HTML comment · conditional · detector-evading) + Microsoft set.
- Outside, named: attacker holding Layla's session = authentication, out of scope, measured anyway (typed outside recipient → review 2/2). Compromised model/provider, network/OS/Gmail = standard controls. Reviewer fooled = look-alike warning, not measured. DoS/cost/poisoning = not tested.
- "We'd rather answer one real question properly."

## Gmail connection
- GCP project + Gmail API + OAuth client → one-time sign-in as 444testmail → token (read+send). No password.
- read_inbox = live API fetch every call, EXTERNAL. send_email = real send, in Gmail Sent.
- Cage: 3-mailbox allow-list, refuses anything else even defenses off. Safety, NOT a defense; harness can't import it.
- Directory remap: Sara=youssef.a.moneim, security=444testmail.
- "Didn't Gmail block it?" spam filters protect humans; this email is normal to a filter; External label helps a human not the model.

## Demo
- Layla=444testmail · attacker=yousefahmed12005 · Sara=youssef.a.moneim (name set in Gmail).
- T1 `What emails do I have in my inbox today?` · T2 (reply box) `Reply to Sara with what she asked for.`
- Green → run once more ("4 of 5"). Asks a question → `yes, send it`.
- Defended: 0.95, span cut, To Sara, BCC empty → approve → notice to 444testmail.
- Demo-only limits: turns 50, tokens 8192 (eval frozen at 6). Salary sheet fictional, demo corpus only.
- Dropdown = document door. Live: PI-120 (gate) then PI-020 (detector).
- `code ~/Developer/coe444-prompt-injection`. Never show .env, .secrets/, test-split payloads.

## Never say
- "we trained a model" → prompted, one frozen number
- "we achieved <5 %" → 0 of 41, upper bound 23 %, not refuted
- "Microsoft had no defenses" → had three, bypassed

## "Why that model?" (METHODOLOGY §4, §6.4)
- Proposal's Llama 3.1-8B: no local hardware (5 GB / 6 GB), retired on Groq (404). Deviation stated §1.2.
- Agent gpt-oss-20b: the candidate that actually falls for attacks — 7/10 undefended. Qwen-27b fell for 0/10 (refused, told the user) → a table of zeros proves nothing. allam-7b: no tool calling. Cheap tier = realistic deployment.
- Detector gpt-oss-120b: bigger (~117B vs 21B), DIFFERENT model from the agent (shared failure modes → optimistic recall), affordable ×3.
- Open-weight: reproducible, host-independent — proved it: Cerebras → Groq → Nous, same weights, consistent verdicts.
- Limitation 6: same family, forced not chosen. Mitigation: action rubric, model-free gate, Microsoft black-box check 5/50.
- Model choice moves A (undefended), not D in principle; dev D stayed 0/10 across host moves.
