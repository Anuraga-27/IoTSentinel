# IoTSentinel — who does what

Meeting: **24 Nov 2026, 1:00 pm**. Team 2, five members.
Fourteen slides, one live demo, then questions.

Swap sections freely — this is a starting split, not a rule. What matters
is that every slide has exactly one owner and nobody is surprised.

## Before the meeting

| What | Who | Time | Notes |
|---|---|---|---|
| Make the four deck corrections | **one person only** | 20 min | See the table below. One owner, or you will end up with two versions of the deck |
| Drop the refreshed test screenshot into the report | Anuraga | 10 min | `docs/report/figures/out_tests.png`, already regenerated for 21 tests |
| Read `docs/presentation_notes.md` | **everyone** | 20 min | Speaker notes per slide, plus ten likely viva questions with answers |
| Rehearse once end to end, out loud | **everyone** | 30 min | Time it. Most teams overrun |
| Check the laptop: dashboard starts, Reset works | Anuraga | 5 min | Do this again an hour before, not at 12:58 |

### The four deck corrections

| Slide | Change |
|---|---|
| 3 | "five attacks, each loud and slow" → only **four** have slow variants; a single forged ARP frame cannot be slowed |
| 9 | "18/18 unit tests" → **21/21** |
| 11 | add that the port-scan fix slowed real-scan detection from **9 s to 42 s** |
| 14 | no change on screen, but know that **182k** came from `validation/benchmark.py` |

## Speaking split

| Slides | Owner | Content | Target |
|---|---|---|---|
| 1–3 | **Sabaresh** | Title and team, the problem, goal and objectives | 3 min |
| 4–6 | **Sri Pranay J** | Scope in/out, three-layer architecture, data flow | 3 min |
| 7–8 | **M Steve Anderson** | The five detection rules, ARP grace period, incident grouping | 3 min |
| 9–11 | **Surapureddy Likhitha Sri** | Four layers of testing, threshold trade-offs, the real-traffic flaw | 4 min |
| 12–14 | **Anuraga Sahu** | Live demo, lessons learned, conclusion | 5 min |

Roughly 18 minutes. Cut slide 10 first if you are short on time.

### Why this split

- **Sabaresh** opens, so needs the most confident delivery — the first
  90 seconds set the tone.
- **Sri Pranay** explains the shape of the system, which makes everything
  after it understandable. Mostly diagrams, so the least memorisation.
- **Steve** has the technical core. Two slides, but the densest. He should
  know all five thresholds without looking.
- **Likhitha** has the strongest material: real packet captures found a
  real flaw and the team fixed it. Deliver this as a result, not an
  apology.
- **Anuraga** drives the laptop and demos, having built and deployed it.

## Demo (slide 12) — Anuraga

Follow the script in `CLAUDE.md`. In short: **Reset**, Start monitoring,
pick an attack and an explicit device, Launch, then show the alert log —
**~11,600 violations, 1 incident**. Say both numbers out loud.

Have the hosted app open in a second tab as a fallback:
https://iotsentinel-rreqchtfym3hsndfg9zrfw.streamlit.app/

## Questions — who takes what

Whoever owns the slide takes questions on it. Agree this in advance so
you are not all looking at each other.

| Question | Who answers |
|---|---|
| Why rules and not machine learning? | Steve |
| Why keep a flood threshold of 500 when the sweep shows 5000 is better? | Likhitha |
| Why was Mirai missed? | Likhitha |
| How is brute force detected when logins are encrypted? | Likhitha |
| What are the 8 remaining false alarms? | Steve |
| Could an attacker stay under the threshold? | Steve |
| How fast is it? Does it block attacks? | Anuraga |
| What would you do next? | Sabaresh |

Answers to all of these are in `docs/presentation_notes.md`.

## Three things to volunteer, not hide

Examiners mark honesty about limitations well.

1. **Mirai was missed**, and the reason is a category mismatch, not a
   broken rule.
2. **Slide 13's "12k records/s"** describes code that no longer exists.
3. **Cloud deployment was out of scope** in the proposal, but the app was
   deployed anyway. Either present it as going beyond the proposal, or
   leave it out — do not let an examiner spot the contradiction first.
