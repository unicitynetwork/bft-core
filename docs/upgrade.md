# Upgrading

Notes for upgrades which need more than replacing the binary of one node at a time.

## Strict signature rule (bft-go-base `uc-consolidation`)

The technical reasoning, the example and the full procedure are in
[bft-go-base `docs/UPGRADING.md`](https://github.com/unicitynetwork/bft-go-base/blob/uc-consolidation/docs/UPGRADING.md).
This section gives bft-core's part of it. The aggregator side is in the
[aggregator-go README](https://github.com/unicitynetwork/aggregator-go/blob/uc-consolidation/README.md#upgrading-strict-signature-rule).

Terms (the same in all three documents): **root validators** are the BFT Core root chain nodes;
**aggregators** are also the shard nodes in this stack; **shard validators** are a separately
deployed shard consensus cohort, if there is one (it is treated according to its own verification
paths). The **strict rule** is the strict secp256k1 `VerifyHash` / `VerifyBytes` rule, together
with the stricter `ShardingScheme.IsValid` (incomplete shard schemes are now rejected, complete
ones are unchanged).

### Baseline assumption: stop-all upgrade

The current binaries have no activation gate, so root consensus must not mix the two verification
rules. The release assumes a stop-all upgrade as the conservative baseline: every process (root
validators, aggregators, shard validators) is stopped, upgraded and started together. This is an
assumption about what is known to be safe, not a requirement; a gentler procedure is fine where it
is simple and safe. A rolling upgrade inside the root validator cohort is not supported.

### Gentler procedure: validator cutover, then rolling aggregators

If a full stop is unwanted, the architect's recommended alternative is:

1. A coordinated cutover of all root validators together (see the procedure of the
   [PR #27 section](#procedure) below for the steps), plus any shard consensus cohort according to
   its own verification paths.
2. Check that the network makes progress, recovers and produces fresh UCs, and that a
   still-old aggregator accepts and processes those UCs. Only then upgrade the aggregators, one at
   a time while they keep running. Strict-valid
   certificates pass the old verifier and aggregators already send strict-valid requests.

New certifications pause during the root cutover; uninterrupted writes are not promised. Do not
reverse the order: strict aggregators with legacy root validators can reject seals the root chain
finalized. This procedure has not been rehearsed in a deployment yet; rehearse it before relying
on it. A fully rolling validator upgrade (a compatibility release plus epoch-based activation) is
possible future work and is not implemented.

### Preflight and constraints

- Before the cutover verify, under the strict rule, the durable artifacts that startup, recovery
  and proof serving will check: QCs, timeout certificates, UCs and seals, trust-base history and
  persisted proofs. Also check node keys and that registered sharding schemes are complete.
  Stopping the nodes does not make a legacy-only certificate strict-valid.
- Fence the old root validators so that none of them can rejoin after the cutover.
- Back up the home directory and never erase safety (voting) records to get a node to start.
- Rollback after the network has made new progress needs a coordinated plan; do not restart
  isolated old binaries. The strict rule itself changes no message or database format, but the
  release also adds the versioned V2 certification response (legacy peers keep the old form) and
  aggregator-go stores a partition view next to the UC. Check wire and storage compatibility of
  the pinned builds separately before relying on a rollback. Rolling back one node does not undo
  certificates that were produced meanwhile.

### What can go wrong

Honest signers produce 65-byte low-S signatures that pass both rules and are unaffected. A
non-strict signature comes from a Byzantine signer, or from anyone who changes the recovery byte
of a relayed signature. Only then can old and new nodes disagree on whether a seal or QC has a
quorum, so mixed rules can stall progress. This is a liveness problem, not a fork: both rules
need a quorum of real root keys and the strict rule accepts a subset of what the old one accepts.
The affected paths are seals, QCs, timeout certificates, votes and proposals, certification
requests and trust-base signatures. Root validators verify QCs; aggregators verify only UC seals
and the root trust base.

Merge and release order: bft-go-base → bft-core → aggregator-go. bft-core must also take the
`leaderNode.NodeID` formatting fix (bft-core#38) with the bft-go-base dependency update.

## Branch-aware "change in progress" check (PR #27)

### What changes

A block may contain a change of a shard only when the shard has no uncommitted change in the
pipeline. Before this change a root node checked all the uncommitted blocks it had, after the
change it checks only the blocks of the branch the new block extends. The block of a round which
got timeout certificate is no longer deleted.

This changes which blocks are valid. Message and database formats are the same.

Only root nodes are affected. Shard nodes do not have to be upgraded or restarted.

### Why the root nodes must be upgraded together

A root node with the new rule can propose a block that a node with the old rule rejects (a shard
is changed while a block of another branch contains a change of the same shard). While the root
network runs both versions:

- the old nodes do not vote for such block, so rounds time out when the new nodes alone do not
  have quorum;
- an old node can't recover from a new node while such block is uncommitted.

This is a liveness problem, not a safety one: a block still needs votes of a quorum to be
certified, so the versions can't commit different blocks. An old node which can't follow stays
behind until it is upgraded.

### Procedure

The root network is stopped for the upgrade, so there is no time when both rules are in use. No
shard gets certificates while the root nodes are down.

1. Install the new binary on every root node, do not restart anything yet.
2. Stop all root nodes. Wait until all of them have stopped.
3. Optionally back up the node's home directory (default `$HOME/.ubft`). Do not delete or modify
   the databases (`rootchain.db`, `trustbase.db`, `orchestration.db`): the node continues from them.
4. Start the root nodes with the new binary, using the same configuration as before. Start the
   node used as bootnode first (see [bootstrapping](bootstraping.md)).
5. On every node check that the line `Starting root node. ... BuildInfo=...` in the log shows the
   new revision.
6. Check that the network makes progress: `new round start` is logged with growing round number
   and shards get certificates again.

Rules:

- Do not start a root node with the old binary after step 2. When a node can't be upgraded now,
  leave it stopped: the network works without up to `f` root nodes (1 of 4, 2 of 7) and the node
  can be upgraded and started later.
- When the network does not make progress after step 4, check first that all running root nodes
  have the new version (step 5).

### Rollback

Same procedure with the old binary: stop all root nodes, start all of them with the old binary.

The databases can be used by both versions, with one exception. After a commit which leaves a
branch out, a block of that branch can stay in `rootchain.db` for a few rounds (until the
committed round passes the round of the block). The new version skips such block on startup, the
old version fails with `cannot add block for round N, parent block M not found`. All the nodes
are stopped at about the same round, so this can happen on several nodes at once.

When a node does not start with the old binary:

1. Stop all root nodes and start all of them with the new binary again.
2. Wait until the round number in `new round start` is past `N + 10` and rounds do not time out:
   the block of round `N` is deleted from the database by then.
3. Repeat the rollback.

Do not move `rootchain.db` away for this (next section) unless only that one node is affected
and it must stay on the old version.

### Node does not start

`cannot add block for round N, parent block M not found` on startup with the new binary means the
node's `rootchain.db` was left inconsistent by a bug of the old version (the block of a timed-out
round was deleted from the database while it had a child block). The new version does not create
such database but it can't load one either.

1. Start the other root nodes and check that the network makes progress.
2. On the failing node move `rootchain.db` away (keep the other files) and start the node. It
   starts from the genesis state and recovers the current state from the peers.

`rootchain.db` contains the node's voting record too, so do this for one node at a time and
never for more than `f` nodes. When more nodes are affected do not continue, the state of the
network needs to be looked at first.
