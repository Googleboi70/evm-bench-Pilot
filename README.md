# evmbench-pilot

**Does proof-of-concept (PoC) verification actually cut false alarms in AI smart-contract auditing, and what does each verified finding cost?**

An independent, open, small-budget pilot. **Status: Phase 0 (free-model-only pilot).** Started November 2026.

## Why this exists
- AI cyber capability is a tracked risk area. Benchmarks such as EVMbench and its re-evaluation (arXiv:2603.10795) mostly score *recall on vulnerable code*.
- Few evaluations I found report **false alarms on fixed code** or **cost per verified finding**, especially for cheap/open-weight models, where capability spreads fastest.
- This repo tests both with paired vulnerable/fixed controls and publishes everything so anyone can rerun it.

## Phase 0: free-only pilot (this repo, now)
**Goal:** show the method works, measure tokens, and project the cost of a full study. No money is spent.

| Item | Pilot choice |
|---|---|
| Tasks | 2 custom Foundry tasks (`ctf-poly-network`, `ctf-verus-bridge`), each with a `vuln/` and a `fixed/` version. Optional: 2 small EVMbench audits via the ReEVMBench harness (needs Docker/Codespaces) |
| Model | One free-tier model, ID and date logged per run (`[model-id]`). One model isolates the scaffold effect |
| Scaffold variants | **v0**: read code, report findings as JSON. **v1**: v0 + PoC gate, so only findings backed by a Foundry test the agent wrote are reported |
| Runs | 2 repeats per task x version x variant, spread across days (fewer if rate-limited) |
| Grading | Manual, blinded (see below) |

### Definitions
- **Verified (agent-side):** the agent's own PoC test passes on the code it was given.
- **Confirmed (grader-side):** the same PoC fails on the `fixed/` version and matches the target bug.
- **Detection:** target bug reported on `vuln/` (yes/no).
- **False alarm (strict):** original bug reported as present on `fixed/`.
- **False alarm (loose):** any reported finding that fails manual verification on either version.
- **Cost:** tokens in/out, steps and wall time per run. USD is *projected* = tokens x provider list price (dated in `results/prices.md`), not money spent.

### Hypotheses (written before running)
1. v1 produces fewer false alarms than v0 on `fixed/`, with equal or lower detection on `vuln/`.
2. v1 uses more tokens per run than v0; I will measure the overhead.
3. If both are run, scores are lower on my custom tasks than on public EVMbench tasks (possible memorisation).

n is tiny, so the pilot reports raw counts only and makes no significance claims.

### Grading protocol
- Runs are saved under random IDs; the arm mapping lives in a separate file that I do not open until grading is finished (blinded grading).
- One fixed rubric (`results/grading_notes.md`); every judgement call is logged there.
- Single grader (me). This is a known limitation.

### Done when
- [ ] Both custom tasks pass/fail correctly via `forge test` on `vuln/` and `fixed/`
- [ ] Scaffold v0 completes a toy task end to end
- [ ] At least 8 pilot runs logged with token counts
- [ ] Blinded manual grading complete, `results/pilot.csv` filled
- [ ] Full-study cost projection written
- [ ] Limitations and deviations updated

## Phase 1: funded study (planned, not started)
- **Arms:** A = reference frontier model + off-the-shelf open-source scaffold (subset only); B = cheap open-weight model + same scaffold; C = same cheap model + my scaffold with PoC verification.
- **Tasks:** about 25-40 (public EVMbench audits, post-cutoff incidents, my custom tasks), each with a fixed-version control.
- **Repeats:** about 3 per task and arm; 95% bootstrap confidence intervals.
- **Metrics:** recall, false alarms, cost per verified finding, tokens, time, failure taxonomy.
- Pre-registered hypotheses for Phase 1 will be committed before any funded run.

## Safeguards
- Local sandboxed forks only. No live targets, no mainnet interaction.
- Only public benchmark tasks and my own custom tasks are sent to third-party APIs. Free tiers may retain prompts, so no private or NDA code, ever.
- No exploit tooling beyond what the benchmarks already publish. Any new finding in third-party code is disclosed responsibly before anything is published.
- No keys in this repo (`.env` is git-ignored).

## Repo layout
```
README.md  LOG.md  .env.example  .gitignore
tasks/        ctf-poly-network/{vuln,fixed}  ctf-verus-bridge/{vuln,fixed}  evmbench/ (notes only)
scaffold/     agent.py  tools.py  prompts/{v0.md,v1.md}
runs/         raw JSONL logs (random run IDs)
results/      pilot.csv  grading_notes.md  prices.md
analysis/     summarize.py
```

## Reproduce (planned interface; updated as the scaffold lands)
```bash
git clone https://github.com/Googleboi70/evmbench-pilot && cd evmbench-pilot
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cp .env.example .env        # set LLM_BASE_URL, LLM_MODEL, LLM_API_KEY
python3 scaffold/agent.py --task tasks/ctf-poly-network/vuln --variant v1 --out runs/
python3 analysis/summarize.py
```
Requires Python 3.11+ and Foundry. The optional EVMbench track uses the ReEVMBench harness (github.com/blocksecteam/ReEVMBench); benchmark code is referenced, not copied.

## Limitations
- Tiny sample, one free model, rate limits, and possible silent model changes on free tiers.
- Manual single-grader scoring. Blinding reduces but does not remove bias.
- Custom tasks are based on well-known incidents, so memorisation is possible.
- PoC verification adds token cost; the pilot only measures it.
- Results test the method, not general model capability.

## Related work
EVMbench; BlockSec's re-evaluation (arXiv:2603.10795); CyberChainBench; SCONE-bench; Heimdallr; SmartPoC.

## Deviations log
|    Date  |   Change |   Reason |
|    ---   |    ---   |   ---    |

## Status log
| Date | What I did | Result | Cost (USD) |
|---|---|---|---|

## License
Code: MIT. Benchmark tasks are not redistributed.