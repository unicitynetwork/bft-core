# Upgrading root nodes

Notes for upgrades which need more than replacing the binary of one node at a time.

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
