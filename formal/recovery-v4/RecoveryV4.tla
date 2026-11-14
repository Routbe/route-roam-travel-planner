------------------------------- MODULE RecoveryV4 -------------------------------
(***************************************************************************)
(* Recovery v4: the state machine of one member's recovery vault.          *)
(*                                                                         *)
(*   none ──setup──▶ 2of3 ◀──downgrade (fresh step-up)── 3of4              *)
(*                    │ ▲                                  ▲ │             *)
(*                    │ └────────── rotate ────────────────┘ │             *)
(*                    └──────────── upgrade ─────────────────┘             *)
(*                                                                         *)
(* Every level change is a ceremony: BEGIN stages a pending ceremony that  *)
(* wraps a FRESH master generation, the card share (3of4 only) is written  *)
(* and proven with a card tap, COMMIT atomically activates the pending     *)
(* ceremony and revokes the old one. ABORT, the database TTL (expiry) or   *)
(* REMOVE end a pending ceremony without touching the active one.          *)
(*                                                                         *)
(* Stateless by construction (Neon/PgBouncer): the only state shared       *)
(* between steps is the database row and the request message. Every       *)
(* server action is ONE atomic transaction computed from (database,        *)
(* request) alone, i.e. SELECT .. FOR UPDATE on the recovery master row,   *)
(* compare-and-swap on `ver`, an idempotency key <<client, n>>, and no     *)
(* session variables, advisory locks or temp tables. The network may drop  *)
(* any request or answer, a session may expire / a worker may be torn down *)
(* at any point, the card may be pulled mid-write and may be unlinked.     *)
(* A transaction interrupted by a dropped connection simply never happened *)
(* (atomicity), so only drops BETWEEN transactions need modelling.         *)
(*                                                                         *)
(* The five boolean constants switch individual protections off. The main *)
(* models run with all of them TRUE; each mutant model switches one off    *)
(* and TLC must then find a counterexample (see run-tlc.sh), which proves  *)
(* that every invariant really guards something.                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Clients,               \* sessions/devices of the SAME member
          MaxCeremonies,         \* ceremony ids that may be created
          MaxReq,                \* requests per client (idempotency key space)
          MaxStepUps,            \* passkey step-up proofs that may be registered
          MaxFaults,             \* drops, crashes, card pulls, card unlinks
          UseCAS,                \* FOR UPDATE + version CAS inside each transaction
          RotateGen,             \* every ceremony wraps a fresh master generation
          RequireDowngradeStepUp,\* commit that lowers the level consumes a fresh step-up
          RequireCardConfirm,    \* a 3of4 commit needs the card tap proof
          UseIdempotency         \* a repeated idempotency key replays the stored answer

ASSUME /\ Clients # {}
       /\ MaxCeremonies \in Nat \ {0} /\ MaxReq \in Nat \ {0}
       /\ MaxStepUps \in Nat /\ MaxFaults \in Nat
       /\ {UseCAS, RotateGen, RequireDowngradeStepUp, RequireCardConfirm, UseIdempotency} \subseteq BOOLEAN

Factors == {"prf", "server", "paper", "card"}
Pols    == {"2of3", "3of4"}
Levels  == {"none"} \cup Pols
F(p)    == IF p = "3of4" THEN Factors ELSE Factors \ {"card"}   \* shares of a ceremony
K(l)    == IF l = "3of4" THEN 3 ELSE IF l = "2of3" THEN 2 ELSE 0 \* threshold of a level
Ids     == 1..MaxCeremonies
Steps   == 1..MaxStepUps
Keys    == Clients \X (1..MaxReq)

\* Which ceremonies a client may start from the level it last saw.
BeginKinds(l) ==
  IF l = "none" THEN {<<"setup", "2of3">>, <<"setup", "3of4">>}
  ELSE IF l = "2of3" THEN {<<"upgrade", "3of4">>, <<"rotate", "2of3">>}
  ELSE {<<"downgrade", "2of3">>, <<"rotate", "3of4">>}

NoReq  == [c |-> "none", n |-> 0, op |-> "none", kind |-> "none", pol |-> "none", cid |-> 0,
           ev |-> 0, sl |-> "none", sp |-> 0, sa |-> 0, pf |-> 0, tap |-> 0]
NoResp == [c |-> "none", n |-> 0, op |-> "none", ok |-> FALSE, why |-> "none", cid |-> 0,
           ver |-> 0, level |-> "none", pend |-> 0, act |-> 0]

VARIABLES
  \* database: the recovery master row and its ceremonies
  cer,        \* set of ceremony records ever created (shares outlive revocation)
  level,      \* active threshold level on the master row
  ver,        \* CAS version on the master row
  gen,        \* master generation the vault data is currently wrapped with (0 = none)
  card,       \* "linked" / "unlinked" (certified revocation)
  proofs,     \* step-up proofs, registered and consumed on the database clock
  idem,       \* idempotency table: key -> stored answer
  nextId,     \* next ceremony id
  \* physical card
  cardHolds,  \* ceremony id whose share the card holds; -1 = torn write
  \* clients (browser + crypto worker; volatile)
  pc, seen, cur, pol, nreq, outReq,
  \* network (HTTP over the pooler)
  msgs, resps,
  \* bookkeeping
  faults

dbVars  == <<cer, level, ver, gen, card, proofs, idem, nextId>>
cliVars == <<pc, seen, cur, pol, nreq, outReq>>
vars    == <<dbVars, cardHolds, cliVars, msgs, resps, faults>>

Pending == {x \in cer : x.status = "pending"}
Active  == {x \in cer : x.status = "active"}
IdOf(S) == IF S = {} THEN 0 ELSE (CHOOSE x \in S : TRUE).id
Cer(i)  == CHOOSE x \in cer : x.id = i
IsPend(i) == \E x \in Pending : x.id = i
Key(m)  == <<m.c, m.n>>
Fresh(p) == p # 0 /\ proofs[p] = "fresh"
Consume(p) == IF Fresh(p) THEN [proofs EXCEPT ![p] = "used"] ELSE proofs

\* Idempotency keys that can still be presented: a request in flight or the
\* current request of a waiting session. Keys are never reused, so a stored
\* answer for any other key can never be read again; it is pruned (in the
\* database such rows age out). This keeps the state space canonical.
Live(ms, p) == {Key(x) : x \in ms} \cup {<<c, nreq[c]>> : c \in {d \in Clients : p[d] = "wait"}}
Prune(t, ms, p) == [k \in Keys |-> IF k \in Live(ms, p) THEN t[k] ELSE NoResp]

\* A request whose key has not been answered yet (or no idempotency at all).
Unanswered(m) == ~UseIdempotency \/ idem[Key(m)] = NoResp

Resp(m, ok, why, cid, v, l, p, a) ==
  [c |-> m.c, n |-> m.n, op |-> m.op, ok |-> ok, why |-> why, cid |-> cid,
   ver |-> v, level |-> l, pend |-> p, act |-> a]

-----------------------------------------------------------------------------
Init ==
  /\ \E l \in Levels :
       /\ level = l
       /\ cer = IF l = "none" THEN {}
                ELSE {[id |-> 1, pol |-> l, kind |-> "setup", status |-> "active", gen |-> 1,
                       cardSt |-> IF l = "3of4" THEN "confirmed" ELSE "na"]}
       /\ gen = IF l = "none" THEN 0 ELSE 1
       /\ nextId = IF l = "none" THEN 1 ELSE 2
       /\ cardHolds = IF l = "3of4" THEN 1 ELSE 0
       /\ seen = [c \in Clients |-> [ver |-> 0, level |-> l, pend |-> 0,
                                     act |-> IF UseCAS \/ l = "none" THEN 0 ELSE 1]]
  /\ ver = 0 /\ card = "linked"
  /\ proofs = [p \in Steps |-> "unissued"]
  /\ idem = [k \in Keys |-> NoResp]
  /\ pc = [c \in Clients |-> "idle"] /\ cur = [c \in Clients |-> 0]
  /\ pol = [c \in Clients |-> "none"] /\ nreq = [c \in Clients |-> 0]
  /\ outReq = [c \in Clients |-> NoReq]
  /\ msgs = {} /\ resps = {} /\ faults = 0

-----------------------------------------------------------------------------
(* Clients. A request carries everything the server needs; nothing else    *)
(* survives between transactions.                                          *)

Send(c, op, kd, p, cid, pf, tap) ==
  LET m == [c |-> c, n |-> nreq[c] + 1, op |-> op, kind |-> kd, pol |-> p, cid |-> cid,
            ev |-> seen[c].ver, sl |-> IF UseCAS THEN "none" ELSE seen[c].level,
            sp |-> IF UseCAS THEN 0 ELSE seen[c].pend, sa |-> seen[c].act,
            pf |-> pf, tap |-> tap]
  IN /\ nreq[c] < MaxReq
     /\ msgs' = msgs \cup {m}
     /\ outReq' = [outReq EXCEPT ![c] = m]
     /\ nreq' = [nreq EXCEPT ![c] = nreq[c] + 1]
     /\ pc' = [pc EXCEPT ![c] = "wait"]

\* Passkey step-up right before a request: the proof is registered on the
\* database clock (300 s, single use) and travels inside the request.
Unissued == {p \in Steps : proofs[p] = "unissued"}
NewProof == IF Unissued = {} THEN 0 ELSE CHOOSE p \in Unissued : \A q \in Unissued : p <= q
Issue(pf) == IF pf = 0 THEN UNCHANGED proofs ELSE proofs' = [proofs EXCEPT ![pf] = "fresh"]

StartBegin(c) ==
  /\ pc[c] = "idle" /\ seen[c].pend = 0
  /\ \E kp \in BeginKinds(seen[c].level) :
       /\ Send(c, "begin", kp[1], kp[2], 0, NewProof, 0)
       /\ pol' = [pol EXCEPT ![c] = kp[2]]
  /\ Issue(NewProof)
  /\ UNCHANGED <<cer, level, ver, gen, card, idem, nextId, cardHolds, seen, cur, resps, faults>>

StartRemove(c) ==
  /\ pc[c] = "idle" /\ seen[c].level # "none"
  /\ Send(c, "remove", "remove", "none", 0, NewProof, 0)
  /\ Issue(NewProof)
  /\ UNCHANGED <<cer, level, ver, gen, card, idem, nextId, cardHolds, seen, cur, pol, resps, faults>>

\* A new session finds a pending ceremony (its own crashed one or another device's).
StartAbortStale(c) ==
  /\ pc[c] = "idle" /\ seen[c].pend # 0
  /\ Send(c, "abort", "none", "none", seen[c].pend, 0, 0)
  /\ UNCHANGED <<dbVars, cardHolds, seen, cur, pol, resps, faults>>

\* NFC write of the new #rk1 share to the card (client side, no server involved).
WriteCard(c) ==
  /\ pc[c] = "staged" /\ card = "linked"
  /\ cardHolds' = cur[c]
  /\ pc' = [pc EXCEPT ![c] = "cardOk"]
  /\ UNCHANGED <<dbVars, seen, cur, pol, nreq, outReq, msgs, resps, faults>>

\* A buggy or hostile client skips the card step and asks to commit anyway;
\* only the server's own check may stop it.
SkipCard(c) ==
  /\ pc[c] \in {"staged", "cardOk"}
  /\ pc' = [pc EXCEPT ![c] = "ready"]
  /\ UNCHANGED <<dbVars, cardHolds, seen, cur, pol, nreq, outReq, msgs, resps, faults>>

\* The card leaves the field halfway: the NDEF record is torn.
CardPulled(c) ==
  /\ pc[c] = "staged" /\ card = "linked" /\ faults < MaxFaults
  /\ cardHolds' = -1
  /\ faults' = faults + 1
  /\ UNCHANGED <<dbVars, cliVars, msgs, resps>>

\* Tap proof (SDM, purpose recovery_factor, db/0267): binds what the card really holds.
SendConfirm(c) ==
  /\ pc[c] = "cardOk"
  /\ Send(c, "confirm", "none", "none", cur[c], 0, cardHolds)
  /\ UNCHANGED <<dbVars, cardHolds, seen, cur, pol, resps, faults>>

SendCommit(c) ==
  /\ pc[c] = "ready"
  \* with or without a step-up: only a commit that lowers the level needs one
  /\ \E pf \in {0, NewProof} :
       /\ Send(c, "commit", "none", "none", cur[c], pf, 0)
       /\ Issue(pf)
  /\ UNCHANGED <<cer, level, ver, gen, card, idem, nextId, cardHolds, seen, cur, pol, resps, faults>>

SendAbort(c) ==
  /\ pc[c] \in {"staged", "cardOk", "ready"}
  /\ Send(c, "abort", "none", "none", cur[c], 0, 0)
  /\ UNCHANGED <<dbVars, cardHolds, seen, cur, pol, resps, faults>>

\* Out of requests: the user closes the tab; the database TTL cleans up.
Abandon(c) ==
  /\ pc[c] \in {"staged", "cardOk", "ready"} /\ nreq[c] = MaxReq
  /\ pc' = [pc EXCEPT ![c] = "idle"] /\ cur' = [cur EXCEPT ![c] = 0]
  /\ pol' = [pol EXCEPT ![c] = "none"]
  /\ UNCHANGED <<dbVars, cardHolds, seen, nreq, outReq, msgs, resps, faults>>

Finish(c) ==
  /\ pc[c] = "committed"
  /\ pc' = [pc EXCEPT ![c] = "idle"] /\ cur' = [cur EXCEPT ![c] = 0]
  /\ pol' = [pol EXCEPT ![c] = "none"]
  /\ UNCHANGED <<dbVars, cardHolds, seen, nreq, outReq, msgs, resps, faults>>

\* Timeout: resend the SAME request (same idempotency key).
Retry(c) ==
  /\ pc[c] = "wait" /\ outReq[c] \notin msgs
  /\ ~\E r \in resps : r.c = c /\ r.n = nreq[c]
  /\ msgs' = msgs \cup {outReq[c]}
  /\ UNCHANGED <<dbVars, cardHolds, cliVars, resps, faults>>

Recv(c) ==
  /\ pc[c] = "wait"
  /\ \E r \in resps :
       /\ r.c = c /\ r.n = nreq[c]
       /\ LET next == IF r.ok /\ r.op = "begin" THEN (IF pol[c] = "3of4" THEN "staged" ELSE "ready")
                     ELSE IF r.ok /\ r.op = "confirm" THEN "ready"
                     ELSE IF r.ok /\ r.op = "commit" THEN "committed"
                     ELSE "idle"
              pcN  == [pc EXCEPT ![c] = next]
          IN /\ pc' = pcN
             /\ cur' = [cur EXCEPT ![c] = IF next = "idle" THEN 0
                                           ELSE IF r.op = "begin" THEN r.cid ELSE cur[c]]
             /\ pol' = IF next = "idle" THEN [pol EXCEPT ![c] = "none"] ELSE pol
             /\ idem' = Prune(idem, msgs, pcN)
       /\ resps' = resps \ {r}
       /\ seen' = [seen EXCEPT ![c] = [ver |-> r.ver, level |-> r.level, pend |-> r.pend,
                                        act |-> IF UseCAS THEN 0 ELSE r.act]]
  /\ outReq' = [outReq EXCEPT ![c] = NoReq]
  /\ UNCHANGED <<cer, level, ver, gen, card, proofs, nextId, cardHolds, nreq, msgs, faults>>

\* Late or duplicate answers for an earlier request or a dead session are ignored.
Discard ==
  /\ \E r \in resps :
       /\ pc[r.c] # "wait" \/ r.n # nreq[r.c]
       /\ resps' = resps \ {r}
  /\ UNCHANGED <<dbVars, cardHolds, cliVars, msgs, faults>>

-----------------------------------------------------------------------------
(* Server: each action is ONE transaction over the master row.             *)

Answer(m, r) ==
  /\ idem' = Prune([idem EXCEPT ![Key(m)] = r], msgs \ {m}, pc)
  /\ resps' = resps \cup {r}
  /\ msgs' = msgs \ {m}

Refuse(m, why) ==
  /\ Answer(m, Resp(m, FALSE, why, m.cid, ver, level, IdOf(Pending), IdOf(Active)))
  /\ UNCHANGED <<cer, level, ver, gen, card, proofs, nextId>>

\* A key already answered returns the stored answer and changes nothing.
Replay(m) ==
  /\ UseIdempotency /\ idem[Key(m)] # NoResp
  /\ resps' = resps \cup {idem[Key(m)]}
  /\ msgs' = msgs \ {m}
  /\ idem' = Prune(idem, msgs \ {m}, pc)
  /\ UNCHANGED <<cer, level, ver, gen, card, proofs, nextId>>

SBegin(m) ==
  /\ m.op = "begin" /\ Unanswered(m)
  /\ LET lvl  == IF UseCAS THEN level ELSE m.sl
         free == IF UseCAS THEN Pending = {} ELSE m.sp = 0
         why  == IF UseCAS /\ m.ev # ver THEN "conflict"
                 ELSE IF ~free THEN "busy"
                 ELSE IF <<m.kind, m.pol>> \notin BeginKinds(lvl) THEN "invalid"
                 ELSE IF ~Fresh(m.pf) THEN "stepup"
                 ELSE IF nextId > MaxCeremonies THEN "exhausted"
                 ELSE "ok"
     IN IF why # "ok" THEN Refuse(m, why)
        ELSE LET x == [id |-> nextId, pol |-> m.pol, kind |-> m.kind, status |-> "pending",
                       gen |-> IF RotateGen \/ gen = 0 THEN nextId ELSE gen,
                       cardSt |-> IF m.pol = "3of4" THEN "unconfirmed" ELSE "na"]
             IN /\ cer' = cer \cup {x}
                /\ ver' = ver + 1 /\ nextId' = nextId + 1
                /\ proofs' = Consume(m.pf)
                /\ Answer(m, Resp(m, TRUE, "ok", nextId, ver + 1, level, nextId, IdOf(Active)))
                /\ UNCHANGED <<level, gen, card>>

SConfirm(m) ==
  /\ m.op = "confirm" /\ Unanswered(m)
  /\ LET why == IF UseCAS /\ m.ev # ver THEN "conflict"
                ELSE IF ~IsPend(m.cid) THEN "gone"
                ELSE IF Cer(m.cid).pol # "3of4" THEN "invalid"
                ELSE IF card # "linked" \/ m.tap # m.cid THEN "card"
                ELSE "ok"
     IN IF why # "ok" THEN Refuse(m, why)
        ELSE /\ cer' = {IF y.id = m.cid THEN [y EXCEPT !.cardSt = "confirmed"] ELSE y : y \in cer}
             /\ ver' = ver + 1
             /\ Answer(m, Resp(m, TRUE, "ok", m.cid, ver + 1, level, IdOf(Pending), IdOf(Active)))
             /\ UNCHANGED <<level, gen, card, proofs, nextId>>

SCommit(m) ==
  /\ m.op = "commit" /\ Unanswered(m)
  /\ LET lvl  == IF UseCAS THEN level ELSE m.sl
         why  == IF UseCAS /\ m.ev # ver THEN "conflict"
                 ELSE IF ~IsPend(m.cid) THEN "gone"
                 ELSE IF RequireCardConfirm /\ Cer(m.cid).pol = "3of4"
                         /\ Cer(m.cid).cardSt # "confirmed" THEN "card"
                 ELSE IF RequireDowngradeStepUp /\ K(Cer(m.cid).pol) < K(lvl)
                         /\ ~Fresh(m.pf) THEN "stepup"
                 ELSE "ok"
     IN IF why # "ok" THEN Refuse(m, why)
        ELSE LET x == Cer(m.cid) IN
             /\ cer' = {IF y.id = m.cid THEN [y EXCEPT !.status = "active"]
                        ELSE IF y.status = "active" /\ (UseCAS \/ y.id = m.sa)
                             THEN [y EXCEPT !.status = "revoked"]
                        ELSE y : y \in cer}
             /\ level' = x.pol /\ gen' = x.gen /\ ver' = ver + 1
             /\ proofs' = Consume(m.pf)
             /\ Answer(m, Resp(m, TRUE, "ok", m.cid, ver + 1, x.pol, IdOf(Pending \ {x}), m.cid))
             /\ UNCHANGED <<card, nextId>>

\* Always allowed for the member; it never touches the active ceremony.
SAbort(m) ==
  /\ m.op = "abort" /\ Unanswered(m)
  /\ IF ~IsPend(m.cid) THEN Refuse(m, "gone")
     ELSE /\ cer' = {IF y.id = m.cid THEN [y EXCEPT !.status = "aborted"] ELSE y : y \in cer}
          /\ ver' = ver + 1
          /\ Answer(m, Resp(m, TRUE, "ok", m.cid, ver + 1, level, 0, IdOf(Active)))
          /\ UNCHANGED <<level, gen, card, proofs, nextId>>

\* Deleting the vault lowers the level to none, so it also needs a fresh step-up.
SRemove(m) ==
  /\ m.op = "remove" /\ Unanswered(m)
  /\ LET why == IF UseCAS /\ m.ev # ver THEN "conflict"
                ELSE IF level = "none" THEN "invalid"
                ELSE IF RequireDowngradeStepUp /\ ~Fresh(m.pf) THEN "stepup"
                ELSE "ok"
     IN IF why # "ok" THEN Refuse(m, why)
        ELSE /\ cer' = {IF y.status = "active" THEN [y EXCEPT !.status = "revoked"]
                        ELSE IF y.status = "pending" THEN [y EXCEPT !.status = "aborted"]
                        ELSE y : y \in cer}
             /\ level' = "none" /\ gen' = 0 /\ ver' = ver + 1
             /\ proofs' = Consume(m.pf)
             /\ Answer(m, Resp(m, TRUE, "ok", 0, ver + 1, "none", 0, 0))
             /\ UNCHANGED <<card, nextId>>

Server ==
  \E m \in msgs :
     /\ (Replay(m) \/ SBegin(m) \/ SConfirm(m) \/ SCommit(m) \/ SAbort(m) \/ SRemove(m))
     /\ UNCHANGED <<cardHolds, cliVars, faults>>

-----------------------------------------------------------------------------
(* Environment: database clock and faults.                                 *)

\* Pending ceremonies have a TTL on the database clock.
ExpirePending ==
  /\ \E x \in Pending : cer' = (cer \ {x}) \cup {[x EXCEPT !.status = "aborted"]}
  /\ ver' = ver + 1
  /\ UNCHANGED <<level, gen, card, proofs, idem, nextId, cardHolds, cliVars, msgs, resps, faults>>

ExpireProof ==
  /\ \E p \in Steps : proofs[p] = "fresh" /\ proofs' = [proofs EXCEPT ![p] = "expired"]
  /\ UNCHANGED <<cer, level, ver, gen, card, idem, nextId, cardHolds, cliVars, msgs, resps, faults>>

\* Certified unlink (lost card). The level stays; a pending 3of4 needs a new tap.
CardUnlink ==
  /\ card = "linked" /\ faults < MaxFaults
  /\ card' = "unlinked"
  /\ cer' = {IF y.status = "pending" /\ y.cardSt = "confirmed" THEN [y EXCEPT !.cardSt = "unconfirmed"] ELSE y : y \in cer}
  /\ ver' = ver + 1 /\ faults' = faults + 1
  /\ UNCHANGED <<level, gen, proofs, idem, nextId, cardHolds, cliVars, msgs, resps>>

\* A new, blank card is linked.
CardRelink ==
  /\ card = "unlinked" /\ faults < MaxFaults
  /\ card' = "linked" /\ cardHolds' = 0
  /\ ver' = ver + 1 /\ faults' = faults + 1
  /\ UNCHANGED <<cer, level, gen, proofs, idem, nextId, cliVars, msgs, resps>>

\* Session expiry, logout, tab close or crypto-worker teardown: volatile state is gone.
Crash(c) ==
  /\ pc[c] # "idle" /\ faults < MaxFaults
  /\ pc' = [pc EXCEPT ![c] = "idle"] /\ cur' = [cur EXCEPT ![c] = 0]
  /\ outReq' = [outReq EXCEPT ![c] = NoReq] /\ pol' = [pol EXCEPT ![c] = "none"]
  /\ idem' = Prune(idem, msgs, [pc EXCEPT ![c] = "idle"])
  /\ faults' = faults + 1
  /\ UNCHANGED <<cer, level, ver, gen, card, proofs, nextId, cardHolds, seen, nreq, msgs, resps>>

\* The pooler / network drops a request before, or an answer after, its transaction.
DropMsg ==
  /\ faults < MaxFaults
  /\ \E m \in msgs : msgs' = msgs \ {m} /\ idem' = Prune(idem, msgs \ {m}, pc)
  /\ faults' = faults + 1
  /\ UNCHANGED <<cer, level, ver, gen, card, proofs, nextId, cardHolds, cliVars, resps>>

DropResp ==
  /\ faults < MaxFaults /\ \E r \in resps : resps' = resps \ {r}
  /\ faults' = faults + 1
  /\ UNCHANGED <<dbVars, cardHolds, cliVars, msgs>>

\* Nothing left to do: every session idle and out of requests, nothing in flight.
Quiescent ==
  /\ \A c \in Clients : pc[c] = "idle" /\ nreq[c] = MaxReq
  /\ msgs = {} /\ resps = {} /\ Pending = {}

Done == Quiescent /\ UNCHANGED vars

Progress(c) ==
  WriteCard(c) \/ SendConfirm(c) \/ SendCommit(c) \/ SendAbort(c) \/ Abandon(c) \/ Finish(c)

Client(c) ==
  \/ StartBegin(c) \/ StartRemove(c) \/ StartAbortStale(c)
  \/ Progress(c) \/ SkipCard(c) \/ Retry(c) \/ Recv(c)

Fault ==
  \/ \E c \in Clients : CardPulled(c) \/ Crash(c)
  \/ CardUnlink \/ CardRelink \/ DropMsg \/ DropResp

Next ==
  \/ Server \/ (\E c \in Clients : Client(c)) \/ Fault
  \/ ExpirePending \/ ExpireProof \/ Discard \/ Done

Fairness ==
  /\ WF_vars(Server) /\ WF_vars(ExpirePending) /\ WF_vars(Discard)
  /\ \A c \in Clients : WF_vars(Recv(c)) /\ WF_vars(Retry(c)) /\ WF_vars(Progress(c))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties.                                                             *)

TypeOK ==
  /\ level \in Levels /\ ver \in Nat /\ gen \in 0..MaxCeremonies
  /\ card \in {"linked", "unlinked"} /\ cardHolds \in {-1} \cup 0..MaxCeremonies
  /\ proofs \in [Steps -> {"unissued", "fresh", "used", "expired"}]
  /\ nextId \in 1..(MaxCeremonies + 1)
  /\ \A x \in cer : /\ x.id \in Ids /\ x.pol \in Pols
                    /\ x.status \in {"pending", "active", "revoked", "aborted"}
                    /\ x.cardSt \in {"na", "unconfirmed", "confirmed"}
  /\ pc \in [Clients -> {"idle", "wait", "staged", "cardOk", "ready", "committed"}]
  /\ faults \in 0..MaxFaults

\* (1) At most one active and at most one pending ceremony per member.
Exclusivity == Cardinality(Active) <= 1 /\ Cardinality(Pending) <= 1

\* The master row always agrees with the single active ceremony.
LevelConsistent ==
  /\ (level = "none") <=> (Active = {})
  /\ (level = "none") <=> (gen = 0)
  /\ \A x \in Active : x.pol = level /\ x.gen = gen

\* (2) The master generation that wraps the vault data can only be opened with
\* at least K(level) shares, even counting every revoked or aborted ceremony
\* (its shares still exist on paper, cards and old devices) and assuming the
\* attacker holds the same factor of every ceremony.
Opens(H, x) == Cardinality(H \cap F(x.pol)) >= K(x.pol)
StrictThreshold ==
  gen # 0 => \A H \in SUBSET Factors :
               (\E x \in cer : x.gen = gen /\ Opens(H, x)) => Cardinality(H) >= K(level)

\* (6) No half-open vault: an active 3of4 ceremony had its card share proven.
NoHalfOpen == \A x \in Active : x.pol = "3of4" => x.cardSt = "confirmed"

\* (6) No split brain: a session that believes it committed (or is mid-ceremony)
\* refers to a ceremony that the database agrees on.
NoSplitBrain ==
  /\ \A c \in Clients : pc[c] = "committed" => Cer(cur[c]).status \in {"active", "revoked"}
  /\ \A c \in Clients : pc[c] \in {"staged", "cardOk", "ready"} => \E x \in cer : x.id = cur[c]
  /\ \A r \in resps \cup {idem[k] : k \in Keys} :
       (r.ok /\ r.op = "commit") => Cer(r.cid).status \in {"active", "revoked"}

\* (5)/(6) A session is never told "failed" for a commit that did happen
\* (a lost answer plus a blind retry would otherwise hit "gone").
NoFalseFailure ==
  \A r \in resps : (r.op = "commit" /\ ~r.ok /\ r.cid # 0) =>
                     ~(\E x \in cer : x.id = r.cid /\ x.status \in {"active", "revoked"})

\* Card loss never makes the active vault unrecoverable for its owner.
Recoverable ==
  \A x \in Active :
     Cardinality(F(x.pol) \ (IF card = "linked" /\ cardHolds = x.id THEN {} ELSE {"card"})) >= K(x.pol)

Invariants == TypeOK /\ Exclusivity /\ LevelConsistent /\ StrictThreshold
              /\ NoHalfOpen /\ NoSplitBrain /\ NoFalseFailure /\ Recoverable

\* (4) Any step that lowers the level consumes a fresh step-up proof in that same step.
AuthorizedDowngrade ==
  [][K(level') < K(level) => \E p \in Steps : proofs[p] = "fresh" /\ proofs'[p] = "used"]_vars

\* (4) An unlinked card never degrades the vault.
CardNeverDegrades == [][(card = "linked" /\ card' = "unlinked") => level' = level]_vars

\* (3)/(6) The active ceremony changes only by commit or an authorised remove.
ActiveOnlyByCommit ==
  [][Active' # Active => \E m \in msgs : m.op \in {"commit", "remove"} /\ m \notin msgs' /\ Unanswered(m)]_vars

\* (3) Every pending ceremony ends: committed or safely rolled back.
CeremonyTerminates ==
  \A i \in Ids : IsPend(i) ~> (\E x \in cer : x.id = i /\ x.status \in {"active", "aborted"})

\* (3) Every session comes back to rest (no livelock, no stuck UI).
ClientsSettle == \A c \in Clients : (pc[c] # "idle") ~> (pc[c] = "idle")
-----------------------------------------------------------------------------
(* Reachability witnesses. Each is EXPECTED TO BE VIOLATED: TLC must find a *)
(* behaviour that reaches the situation, which proves the safety checks    *)
(* above are not vacuous (run-tlc.sh asserts every one is reached).        *)
W_Upgrade     == ~\E x \in Active : x.kind = "upgrade"
W_Downgrade   == ~\E x \in Active : x.kind = "downgrade"
W_Rotate3of4  == ~\E x \in Active : x.kind = "rotate" /\ x.pol = "3of4"
W_Removed     == ~(level = "none" /\ \E x \in cer : x.status = "revoked")
W_RolledBack  == ~\E x \in cer : x.status = "aborted"
W_CardLost3of4 == ~(card = "unlinked" /\ level = "3of4")
W_TornCard    == ~(cardHolds = -1 /\ Pending # {})
W_LateRequest == ~\E m \in msgs : pc[m.c] # "wait" \/ m.n # nreq[m.c]
W_Replayed    == ~\E c \in Clients : pc[c] = "wait" /\ outReq[c] \in msgs /\ idem[<<c, nreq[c]>>] # NoResp
W_Concurrent  == ~\E c, d \in Clients : c # d /\ pc[c] \in {"staged", "cardOk", "ready"} /\ pc[d] = "wait"
=============================================================================
