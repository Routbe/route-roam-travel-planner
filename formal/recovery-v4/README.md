# Recovery v4 — formal model (TLA+ / TLC)

`RecoveryV4.tla` models one member's recovery vault as seen by the database,
any number of browser sessions, an unreliable network/pooler and the physical
ROUT Card. Step 6 (dynamic recovery v4, rewritten 0268/0269) must implement
exactly these transitions; the SQL follows the model, not the other way round.

## Levels and transitions

| From  | Kind      | To    | Needs                                                          |
|-------|-----------|-------|----------------------------------------------------------------|
| none  | setup     | 2of3 / 3of4 | step-up at begin; 3of4 also a proven card tap            |
| 2of3  | upgrade   | 3of4  | step-up at begin, card share written + tap proof (db/0267)      |
| 3of4  | downgrade | 2of3  | step-up at begin **and a second fresh step-up in the commit**   |
| any   | rotate    | same  | as setup for that level                                          |
| any   | remove    | none  | fresh step-up in the same transaction                            |

Shares: 2of3 = passkey PRF (or OPAQUE seed, step 3) + server + paper;
3of4 = the same plus ROUT Card `#rk1`.

## Server steps (one transaction each)

Every step is a single, self-contained transaction: `SELECT … FOR UPDATE` on
the member's recovery master row, idempotency key, version compare-and-swap,
then the write. No session variables, advisory locks or temp tables survive a
step, so a pooled (PgBouncer/HTTP) connection can be dropped after every step.

| Model action | Planned SQL (step 6)                         | Effect                                                    |
|--------------|----------------------------------------------|-----------------------------------------------------------|
| `SBegin`     | `rout_recovery_v4_begin(idem, ver, kind, policy, proof, …)` | refuses if a pending ceremony exists; stages a pending ceremony wrapping a **fresh master generation**; consumes the step-up |
| `SConfirm`   | `rout_recovery_v4_confirm_card(idem, ver, ceremony, tap)` | linked card + SDM tap that binds the new share → card confirmed |
| `SCommit`    | `rout_recovery_v4_commit(idem, ver, ceremony, proof)` | atomically: pending → active, old active → revoked, level/generation swapped |
| `SAbort`     | `rout_recovery_v4_abort(idem, ceremony)`      | pending → aborted; the active ceremony is never touched   |
| `SRemove`    | `rout_recovery_v4_remove(idem, ver, proof)`   | active → revoked, pending → aborted, level none           |
| `ExpirePending` | TTL on the pending row (database clock)   | pending → aborted                                          |
| `Replay`     | idempotency table                             | a repeated key returns the stored answer, changes nothing |

Faults modelled: dropped request or answer (before/after its transaction),
session expiry / logout / crypto-worker teardown at any point, late execution
of a dead session's request, the card pulled mid-write (torn NDEF record), a
certified card unlink and a new blank card, step-up proofs expiring, and a
client that skips the card step. A transaction cut off mid-way never happened
(atomicity), so only drops between transactions need modelling.

## What TLC proves (within the bounds of each model)

Invariants: `Exclusivity` (≤ 1 active and ≤ 1 pending ceremony),
`LevelConsistent`, `StrictThreshold` (the current master generation opens only
with ≥ K(level) shares, counting revoked/aborted ceremonies and an attacker
holding the same factor of every ceremony), `NoHalfOpen` (an active 3of4
ceremony had its card share proven), `NoSplitBrain`, `NoFalseFailure`,
`Recoverable` (card loss never locks the owner out). Action properties:
`AuthorizedDowngrade` (every step that lowers the level consumes a fresh
step-up in that same step), `CardNeverDegrades`, `ActiveOnlyByCommit`.
Liveness (weak fairness on server, clock and client progress):
`CeremonyTerminates` (every pending ceremony ends committed or rolled back) and
`ClientsSettle` (every session comes back to rest). TLC also checks there is
no deadlock.

Non-vacuity: each mutant in `mutants/` switches one protection off and TLC
must then report the named violation; each `W_*` witness must be reached
(upgrade, downgrade, rotation, removal, rollback, card lost at 3of4, torn
card, a dead session's late request, a replayed answer, two sessions racing).

## Findings that bind step 6

1. **Fresh master generation per ceremony.** With the same Master Key
   re-wrapped (`mutants/NoRotation.cfg`) TLC finds two counterexamples:
   from 3of4, merely *staging* a downgrade (3 steps, before the commit and
   before its second step-up) lets 2 shares open the live vault; from 2of3,
   after a committed upgrade (10 steps) the revoked 2-of-3 shares plus an
   earlier copy of the sealed master still open it. Each ceremony therefore
   wraps a new master generation, the data keys are re-wrapped under it while
   pending, and the commit swaps the generation atomically.
2. **Idempotency keys are required.** Without them a lost commit answer plus a
   retry reports "gone" for a commit that did happen
   (`mutants/NoIdempotency.cfg`).
3. **Downgrade = second step-up inside the commit.** The step-up from begin may
   be older than 300 s by commit time.
4. **Card unlink resets a pending card confirmation** and never changes the
   level; a lost card at 3of4 leaves exactly 3 shares, so recovery still works.
5. **Pending ceremonies need a TTL**: a crashed session leaves a pending row
   that only the clock (or another session's abort) can end.
6. **The server checks the card proof itself** — a client that skips the card
   step must be refused (`mutants/NoCardConfirm.cfg`).

## Limits

Bounded model checking: results hold for the constants in each `.cfg`
(2 sessions, 3 ceremonies, 3–4 requests per session, 2 step-ups, up to 2
faults), not for every size. The model is about the protocol; whether the SQL
and TypeScript follow it is checked by tests in step 6. Cryptography is
abstracted to share counting.

## Run

```sh
TLA_JAR=/path/to/tla2tools.jar ./formal/recovery-v4/run-tlc.sh
```

CI: `.github/workflows/tla-recovery-v4.yml` (tla2tools v1.7.4 / TLC 2.19,
pinned by SHA-256) on every pull request and push to main.
