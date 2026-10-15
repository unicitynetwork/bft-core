# UC consolidation: partition view sidecar, size and scaling measurements

Acceptance evidence for the bft-core ticket ("report encoded sidecar sizes and added serialization/certification cost at four and eight shards"),
organized as **scaling curves**: one parameter is swept at a time and the result is judged by hardware-independent counters
(encoded bytes, allocations, hashed tree nodes, counted encodes and marshals, retained arrays, bytes written to real streams) and log-log slopes
against the expected bound, not by absolute times.

> **Hardware context, read first.** All numbers were taken on a roughly ten-year-old Intel MacBook Pro (Core i7-8850H @ 2.6 GHz, 6 cores / 12 threads,
> 16 GiB, macOS 15.8.1, Go 1.27.2) with heavy background load (load average 100-200 on 12 threads) from other jobs on the same machine.
> Absolute times are slow and noisy and **must not be used to set latency or timeout gates**. Times appear only as relative information (medians
> with their spread, slopes within one run). Bytes, allocation counts, hashed nodes, encode/marshal counts and bytes written are deterministic.

- Code under measurement: `origin/uc-consolidation` @ `a52f2310` (B1/C1/C2/F1 plus base #9 and core #33), with bft-go-base pinned to `8e08f74` (sharding validation O(S)/O(S log S), indexed shard certificates).
  These curves therefore describe the current code, including the lazy legacy frame and shared sidecar bytes of #33.
- This branch adds one production line: an atomic `partitionViewEncodes` counter in `encodePartitionView` (observability for the scaling tests, like bft-go-base's `leafProbes`), so "one inner view encode per partition" is counted, not inferred.
- Tests: `rootchain/consensus/storage/{measurement,scaling}_test.go`, `network/measurement_test.go`. The scaling sweeps skip unless `UC_MEASURE=1`.

## Reproduce

```sh
# exact encoded sizes (always runs; also asserts the workloads are what they claim)
go test ./rootchain/consensus/storage -run 'Test_Measurement' -v -count=1

# scaling sweeps: shard count S, changed shards k, recipient fan-out f (real libp2p sends), LastCR retention over rounds R
UC_MEASURE=1 go test ./rootchain/consensus/storage ./network -run 'Test_Scaling' -v -count=1

# validation comparison counts (counted by bft-go-base itself through its counting hook)
go test github.com/unicitynetwork/bft-go-base/types -run 'TestShardingSchemeValidation_CountedWork|TestCanonicalShardOrder_SingleSortCounted' -v -count=1

# per-round cost (allocations are exact; times are relative only)
go test ./rootchain/consensus/storage -run '^$' -benchmem -benchtime=300ms -count=5 \
  -bench 'UnicityTree|CertificationResponses|EncodePartitionView|GenerateCertificates|ResponseSerialization'
```

A power law `y = x^a` has log-log slope `a`; a logarithm does not have slope 1 and small-x ranges are dominated by fixed costs, so asymptotic slopes are read over the upper part of each sweep (S = 16..256).

## 1. Workloads (verified before measuring)

- **typical aggregation IR**: 32 B state/previous/block hashes, empty non-nil summary value, zero fees, no `ETHash`.
- **maximum admitted IR**: summary value 256 B, `ETHash` 32 B, and `RoundNumber`, `Epoch`, `Timestamp`, `SumOfEarnedFees` at 2^64-1 (longest CBOR encodings).
  `Test_MeasurementMaximumIRIsAdmitted` asserts each field is at its limit, that generation and the strict decoder accept it, that each encoded IR is within the 1,024 B cap, and that one more byte of summary value is rejected.
- **seal**: network 5, four validator signatures of 65 B, asserted on every response (`msCertify`).
- The measured block has one partition of S shards plus three further single-shard partitions, all certified every round.

## 2. Encoded sizes (exact, bytes)

`PartitionViewV1` is encoded once per partition per round and shared by all responses. A "frame" is the unsigned-varint length prefix plus the CBOR payload.
V1 is the unchanged four-element response (`/ab/certificates/0.0.1`), V2 is `[2, [partition, shard, technical, uc], bstr(view)|null]` (`/ab/certificates/0.0.2`). Sizes do not depend on how many shards changed.

| IR | shape | view (B) | V1 frame (B) | V2 frame with view (B) | added per response (B) | V2 frame, null view (B) | UC (B) |
|---|---|---|---|---|---|---|---|
| typical aggregation IR | 1 shard | 200 | 1006 | 1210 | 204 | 1009 | 871 |
| typical aggregation IR | 4 shards | 776 | 1074 | 1855 | 781 | 1077 | 939 |
| typical aggregation IR | 4 shards, all changed | 776 | 1074 | 1855 | 781 | 1077 | 939 |
| typical aggregation IR | 8 shards | 1544 | 1108 | 2657 | 1549 | 1111 | 973 |
| typical aggregation IR | 8 shards, all changed | 1544 | 1108 | 2657 | 1549 | 1111 | 973 |
| maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1) | 1 shard | 515 | 1337 | 1857 | 520 | 1340 | 1186 |
| maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1) | 4 shards | 2036 | 1405 | 3446 | 2041 | 1408 | 1254 |
| maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1) | 4 shards, all changed | 2036 | 1405 | 3446 | 2041 | 1408 | 1254 |
| maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1) | 8 shards | 4064 | 1439 | 5508 | 4069 | 1442 | 1288 |
| maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1) | 8 shards, all changed | 4064 | 1439 | 5508 | 4069 | 1442 | 1288 |

The view is `~193 B x S` for the typical IR (`~508 B x S` for the maximum IR) and adds exactly that much to every response that carries it. At the production cap of eight shards the maximum-IR view is 4,064 B (25% of the 16 KiB limit, 0.4% of the 1 MiB frame limit).
A null view costs 3 B over V1. A single-shard partition gains nothing from a view (it is the response's own leaf) but costs 204 B, kept for a uniform contract.

## 3. Scaling sweeps

### 3.1 Shard count S (1..256; S <= 8 is the production range)

Beyond eight shards the production producer omits the view, so the sweep uses an uncapped but byte-identical encoding of the same view type
(for S <= 8 the test asserts the bytes equal the production `encodePartitionView`); S > 8 measures algorithms, not a production configuration.
"tree hash nodes" is the number of entries of the real `ShardTree` (the nodes hashed to build it), asserted to be exactly 2S-1. "view encode" times only the marshal of a prepared leaf vector (tree work excluded).
"dispatch B, k=S" is **measured**: every shard is marked changed, every response is built and framed as the sender would, and the real frames are summed.

| S | view B | tree hash nodes (2S-1) | UnicityTree allocs | UnicityTree B | view encode allocs (marshal only) | V2 frame B | dispatch B, k=1 | dispatch B, k=S (all responses summed) | IsValid time ns (median, min-max of 5) | UnicityTree time ns (median, min-max) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 200 | 1 | 216 | 13926 | 17 | 1210 | 1210 | 1210 | 17 (16-17) | 105346 (83383-133904) |
| 2 | 392 | 3 | 243 | 15997 | 31 | 1437 | 1437 | 2874 | 194 (165-227) | 141594 (131945-181937) |
| 4 | 776 | 7 | 295 | 20214 | 59 | 1855 | 1855 | 7420 | 482 (443-788) | 317084 (183966-760671) |
| 8 | 1544 | 15 | 402 | 31192 | 115 | 2657 | 2657 | 21256 | 1511 (1121-2517) | 276729 (232854-377861) |
| 16 | 3080 | 31 | 605 | 51085 | 227 | 4227 | 4227 | 67632 | 2437 (2260-5662) | 424439 (391236-704940) |
| 32 | 6153 | 63 | 1008 | 91230 | 451 | 7334 | 7334 | 234697 | 5286 (4946-5790) | 726720 (698149-808412) |
| 64 | 12297 | 127 | 1812 | 171396 | 900 | 13513 | 13513 | 864809 | 9479 (9289-9981) | 1675583 (1326120-1871346) |
| 128 | 24585 | 255 | 3415 | 332356 | 1797 | 25836 | 25836 | 3306985 | 21613 (19836-24175) | 2912184 (2587973-3668452) |
| 256 | 49418 | 511 | 7389 | 661155 | 3590 | 50705 | 50705 | 12980458 | 37261 (31796-46396) | 5149388 (4892020-5557486) |

Counter slopes over S = 1..256 (whole range): view bytes 0.99, tree hash nodes 1.09, view encode allocations 0.97.
Counter slopes over the upper range S = 16..256 (the small-S range is dominated by fixed per-round costs): view bytes 1.00 (expect 1), tree hash nodes 1.01 (expect 1), UnicityTree allocations 0.90 / bytes 0.93 (expect 1), view encode allocations 1.00 (expect 1), dispatch bytes for one response (k=1) 0.90 (expect 1: one frame carries the view) and for all S responses (k=S) 1.90 (expect 2: S frames each carry the S-leaf view).
Relative-time slopes, upper range (medians of 5, loaded host, indicative only): IsValid 0.99, UnicityTree 0.92.

| Quantity | Expected | Measured slope, S = 16..256 | Verdict |
|---|---|---|---|
| encoded view bytes | 1 | 1.00 | linear |
| tree hash nodes | 1 (2S-1 exactly) | 1.01 | linear, asserted exact |
| `UnicityTree` allocations / bytes | 1 | 0.90 / 0.93 | linear (the fixed three-partition part flattens it slightly) |
| view encode allocations | 1 | 1.00 | linear |
| dispatch bytes, one response (k=1) | 1 | 0.90 | linear |
| dispatch bytes, all S shards respond (k=S) | 2 | **1.90** | quadratic, inherent: S recipients each need the whole S-leaf view in their self-contained frame |
| `IsValid` / `UnicityTree` time (relative, medians of 5) | 1 | 0.99 / 0.92 | with bft-go-base #9 the validation time is linear (it was 1.85 before that change) |

**Validation comparisons are counted by bft-go-base's own test**, not by wall clock: `TestShardingSchemeValidation_CountedWork` asserts at most S comparisons for canonical input, at most 2 S log2 S + S for shuffled input, and
a reference pairwise algorithm with at least S(S-1)/4 pair checks (doubling S multiplies the new count by at most 3 while the reference multiplies by about 4); `TestCanonicalShardOrder_SingleSortCounted` asserts a single sort.
The two commands above reproduce it. The `IsValid` time column here is relative information with its spread, not a verdict.

### 3.2 Changed shards per round k (fixed S = 4 and 8)

The inner view must be encoded once per partition regardless of k. The count comes from the `partitionViewEncodes` counter (asserted to be exactly 1 for every k), and the test also checks all k responses share one backing array.

S = 4
| k (changed) | responses | inner view encodes (counted) | distinct view arrays | build allocs | build B | V2 dispatch B (measured over the k frames) |
|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 455 | 35036 | 1855 |
| 2 | 2 | 1 | 1 | 474 | 35954 | 3710 |
| 4 | 4 | 1 | 1 | 512 | 37798 | 7420 |

S=4 slopes over k: inner view encodes 0 (always 1), build allocs 0.09, build bytes 0.05 (both < 1: a fixed per-round cost plus a small per-response term), dispatch bytes 1.00 (expect 1)

S = 8
| k (changed) | responses | inner view encodes (counted) | distinct view arrays | build allocs | build B | V2 dispatch B (measured over the k frames) |
|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 684 | 59345 | 2657 |
| 2 | 2 | 1 | 1 | 704 | 60649 | 5314 |
| 4 | 4 | 1 | 1 | 743 | 62571 | 10628 |
| 8 | 8 | 1 | 1 | 818 | 66339 | 21256 |

S=8 slopes over k: inner view encodes 0 (always 1), build allocs 0.09, build bytes 0.05 (both < 1: a fixed per-round cost plus a small per-response term), dispatch bytes 1.00 (expect 1)

Allocations and bytes of the whole response-building step grow with slope 0.08 / 0.05 in k: a fixed per-round cost (tree, view) plus a small per-response term (certificate paths); the sidecar does **not** multiply with k.
Dispatch bytes are exactly linear in k (slope 1.00), `k x frame`.

### 3.3 Recipient fan-out f (real libp2p sends)

`SendCertificationResponse` is driven with f real libp2p recipients. Each recipient has a raw stream handler for the V2 protocol that counts the bytes the sender writes into its stream; the marshal counters are the dispatch's own
`v2Marshals` / `v1Marshals` (#33 builds the legacy frame lazily, so it is not built when every recipient speaks V2).

| recipients f | V2 marshals (counted) | V1 marshals (counted) | streams that received a frame | bytes written to the f streams | bytes per stream |
|---|---|---|---|---|---|
| 1 | 1 | 0 | 1 | 1621 | 1621 |
| 2 | 1 | 0 | 2 | 3242 | 1621 |
| 4 | 1 | 0 | 4 | 6484 | 1621 |
| 8 | 1 | 0 | 8 | 12968 | 1621 |
| 16 | 1 | 0 | 16 | 25936 | 1621 |
| 32 | 1 | 0 | 32 | 51872 | 1621 |
2026-10-15T14:52:12.406+0300	ERROR	swarm2	swarm/swarm_listen.go:164	swarm listener for /ip4/127.0.0.1/tcp/0 accept error: listener closed
2026-10-15T14:52:14.417+0300	ERROR	swarm2	swarm/swarm_listen.go:164	swarm listener for /ip4/127.0.0.1/tcp/0 accept error: listener closed

The V2 encoding happens once per dispatch whatever f (asserted), the legacy frame is never built, every stream receives the same frame, and bytes written are exactly linear in f (slope 1, the transport lower bound).

### 3.4 LastCR sidecar retention over rounds R (rotating vs synchronous updates)

`LastCR` keeps the response (and its view bytes) a shard last received. If every shard changes each round they all share one view; if one shard changes per round (rotating) each `LastCR` pins the view of the round in which it last changed
(#33 keeps each shard's own original response).

S = 4
| R rounds | rotating: distinct views | rotating: retained view B | synchronous: distinct views | synchronous: retained view B |
|---|---|---|---|---|
| 1 | 1 | 776 | 1 | 776 |
| 2 | 2 | 1552 | 1 | 776 |
| 4 | 4 | 3104 | 1 | 776 |
| 8 | 4 | 3104 | 1 | 776 |
| 16 | 4 | 3104 | 1 | 776 |
| 32 | 4 | 3104 | 1 | 776 |
| 64 | 4 | 3104 | 1 | 776 |

S=4: rotating retention grows linearly in R until it plateaus at S views (slope over R=1..S: 1.00), synchronous stays at one.

S = 8
| R rounds | rotating: distinct views | rotating: retained view B | synchronous: distinct views | synchronous: retained view B |
|---|---|---|---|---|
| 1 | 1 | 1544 | 1 | 1544 |
| 2 | 2 | 3088 | 1 | 1544 |
| 4 | 4 | 6176 | 1 | 1544 |
| 8 | 8 | 12352 | 1 | 1544 |
| 16 | 8 | 12352 | 1 | 1544 |
| 32 | 8 | 12352 | 1 | 1544 |
| 64 | 8 | 12352 | 1 | 1544 |

S=8: rotating retention grows linearly in R until it plateaus at S views (slope over R=1..S: 1.00), synchronous stays at one.

`distinct views == min(R, S)` is asserted for the rotating case: "one view per partition is retained" holds only for synchronous updates; under rotating updates up to S vectors (S x W bytes, 12,352 B at S = 8, typical IR) are pinned, then plateau. There is no growth in R beyond S.

## 4. Per-round cost added by the sidecar (S = 1, 4, 8; typical IR)

Allocation counts and bytes are exact. "Before" is a test-local copy of the pre-sidecar response loop on the same tree build (with bft-go-base #9 in both columns).

| shape | response build before (B / allocs) | with sidecar (B / allocs) | added | view encode alone (B / allocs) | full `GenerateCertificates` (B / allocs) |
|---|---|---|---|---|---|
| 1 shard | 14,776 / 235 | 18,521 / 277 | +3,745 / +42 | 3,403 / 40 | 18,615 / 278 |
| 4 shards (2 changed) | 22,104 / 334 | 35,973 / 474 | +13,869 / +140 | 13,462 / 137 | 36,071 / 475 |
| 4 shards (4 changed) | 23,948 / 372 | 37,819 / 512 | +13,871 / +140 | 13,591 / 138 | 37,903 / 513 |
| 8 shards (3 changed) | 34,088 / 461 | 61,533 / 723 | +27,445 / +262 | 27,100 / 260 | 61,645 / 724 |
| 8 shards (8 changed) | 38,854 / 556 | 66,323 / 818 | +27,469 / +262 | n/a | 66,436 / 819 |

The added work is the view encode (`~3.4 KB x S` allocated, `~33 x S` allocations), paid once per changed partition per round, independent of k; the unchanged `UnicityTree` step is the same in both columns. No extra network message is sent.

Wire (de)serialization of one response (typical IR, allocations exact): marshal V1 / V2 allocate 10.1 / 12.3 KB (1 shard), 10.8 / 14.4 KB (4), 11.0 / 15.8 KB (8) in 56 / 58 allocations (the envelope adds two allocations);
unmarshal V1 / V2 allocate 4.7 / 5.5 KB, 5.1 / 7.2 KB, 5.2 / 9.1 KB; decoding the view on the receiver allocates 3.4 KB / 37 allocations (1 shard), 12.9 KB / 130 (4), 25.6 KB / 254 (8), linear in S.

## 5. Not covered here

- Libp2p transport overhead beyond the frame bytes, signing, real root-chain round cadence; message counts are unchanged by design.
- S > 8 is an algorithm harness only: the producer, the view cap (8 leaves / 16 KiB) and `CanonicalShardOrder` reject it in production.
- Absolute latency: deliberately not reported (see the hardware context above).
