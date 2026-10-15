# UC consolidation: partition view sidecar, size and scaling measurements

Acceptance evidence for the bft-core ticket ("report encoded sidecar sizes and added serialization/certification cost at four and eight shards"),
organized as **scaling curves**: one parameter is swept at a time and the result is judged by hardware-independent counters
(encoded bytes, allocations, retained arrays) and log-log slopes against the expected bound, not by absolute times.

> **Hardware context, read first.** All numbers were taken on a roughly ten-year-old Intel MacBook Pro (Core i7-8850H @ 2.6 GHz, 6 cores / 12 threads,
> 16 GiB, macOS 15.8.1, Go 1.27.2) with heavy background load (load average 100-195 on 12 threads) from other jobs running on the same machine.
> Absolute times are therefore slow and noisy and **must not be used to set latency or timeout gates**. Times appear only as *relative*
> information (ratios, slopes within one run). Bytes, allocation counts and retained-array counts are deterministic and hardware independent.

- Base: `origin/uc-consolidation` @ `8a7ea39b` (B1/C1/C2/F1 merged) plus this branch's test files.
- Code: `rootchain/consensus/storage/{measurement,scaling}_test.go`, `network/measurement_test.go`. The scaling sweeps skip unless `UC_MEASURE=1`.

## Reproduce

```sh
# exact encoded sizes (always runs; also asserts the workloads are what they claim)
go test ./rootchain/consensus/storage -run 'Test_Measurement' -v -count=1

# scaling sweeps: shard count S, changed shards k, LastCR retention over rounds R, recipient fan-out f
UC_MEASURE=1 go test ./rootchain/consensus/storage ./network -run 'Test_Scaling' -v -count=1

# per-round cost (allocations are exact; times are relative only)
go test ./rootchain/consensus/storage -run '^$' -benchmem -benchtime=300ms -count=5 \
  -bench 'UnicityTree|CertificationResponses|EncodePartitionView|GenerateCertificates|ResponseSerialization'
```

How to read the slopes: for a power law `y = x^a` the log-log slope is `a`. A logarithmic term does not have slope 1 (its local slope tends to
zero), and small-x ranges are dominated by fixed costs, so asymptotic slopes are read over the *upper* part of each sweep (S = 16..256).

## 1. Workloads (verified before measuring)

- **typical aggregation IR**: 32 B state/previous/block hashes, empty non-nil summary value, zero fees, no `ETHash`.
- **maximum admitted IR**: summary value 256 B, `ETHash` 32 B, and `RoundNumber`, `Epoch`, `Timestamp`, `SumOfEarnedFees` all
  at 2^64-1 (longest CBOR encodings). `Test_MeasurementMaximumIRIsAdmitted` asserts every field is at its limit, that generation and the strict decoder
  accept it, that each encoded IR is within the 1,024 B cap, and that one more byte of summary value is rejected.
- **seal**: network 5, four validator signatures of 65 B. The benchmarks/report assert this witness shape on every response
  (`msCertify`): an earlier revision of the benchmarks accidentally measured a single 32 B placeholder signature (review finding), which is fixed.
- The measured block has one partition of S shards plus three further single-shard partitions, all certified every round.

## 2. Encoded sizes (exact, bytes)

`PartitionViewV1` is encoded once per partition per round and shared by all responses. A "frame" is the unsigned-varint length prefix plus
the CBOR payload. V1 is the unchanged four-element response (`/ab/certificates/0.0.1`), V2 is `[2, [partition, shard, technical, uc], bstr(view)|null]`
(`/ab/certificates/0.0.2`). Sizes do not depend on how many shards changed.

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

Reading: the view is `~190 B x S` for the typical IR (`~500 B x S` for the maximum IR) and adds exactly that much to every response that carries it.
At the production cap of eight shards the maximum-IR view is 4,064 B, 25% of the 16 KiB view limit and 0.4% of the 1 MiB frame limit. A null view costs
3 B over V1. A single-shard partition gains nothing from a view (it is the response's own leaf) but costs 204 B, kept for a uniform contract.

## 3. Scaling sweeps

### 3.1 Shard count S (1..256; S <= 8 is the production range)

Beyond eight shards the production producer omits the view, so the sweep uses an uncapped but byte-identical encoding of the same view type
(for S <= 8 the test asserts the bytes equal the production `encodePartitionView`); S > 8 measures the algorithms, not a production configuration.
One shard changes per round; `UnicityTree` includes the three further partitions (a fixed per-round cost).

| S | view B | IsValid allocs | IsValid ns | CanonicalShardOrder allocs | UnicityTree allocs | UnicityTree B | UnicityTree ns | view encode allocs | view encode ns | V2 frame B | dispatch B, k=1 | dispatch B, k=S |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 200 | 0 | 10 | 7 | 216 | 13880 | 92577 | 247 | 96081 | 1210 | 1210 | 1210 |
| 2 | 392 | 2 | 178 | 14 | 245 | 16072 | 108611 | 302 | 114755 | 1437 | 1437 | 2874 |
| 4 | 776 | 4 | 348 | 23 | 296 | 20223 | 93582 | 401 | 168550 | 1855 | 1855 | 7420 |
| 8 | 1544 | 8 | 1022 | 40 | 402 | 30771 | 140416 | 628 | 231894 | 2657 | 2657 | 21256 |
| 16 | 3080 | 16 | 2618 | 0 | 605 | 50157 | 256254 | 970 | 365177 | 4227 | 4227 | 67632 |
| 32 | 6153 | 32 | 9385 | 0 | 1008 | 89012 | 363005 | 1788 | 612733 | 7334 | 7334 | 234688 |
| 64 | 12297 | 64 | 31524 | 0 | 1812 | 166828 | 738566 | 3526 | 1280679 | 13512 | 13512 | 864768 |
| 128 | 24585 | 128 | 105230 | 0 | 3416 | 322711 | 1773734 | 7068 | 2557362 | 25835 | 25835 | 3306880 |
| 256 | 49418 | 256 | 470182 | 0 | 7388 | 642060 | 4007857 | 15469 | 8314508 | 50704 | 50704 | 12980224 |

(CanonicalShardOrder is capped at 8 shards by the production helper, its column is 0 beyond.)
Log-log slopes over S = 1..256 (whole range): view bytes 0.99 (expect 1), IsValid allocs 1.00, IsValid time 1.77 (pair checks expect 2), CanonicalShardOrder allocs (S<=8 only) 0.83, UnicityTree allocs 0.64 / bytes 0.71 / time 0.69 (expect 1 once validation is linear), view encode allocs 0.76 / time 0.77 (expect 1), dispatch bytes k=1 0.69 (expect 1: one frame carries the view), k=S 1.69 (expect 2: S frames each carry the view)
Slopes over the upper range S = 16..256: view bytes 1.00, IsValid allocs 1.00 / time 1.85, UnicityTree allocs 0.90 / bytes 0.92 / time 1.02, view encode allocs 1.00 / time 1.11, dispatch bytes k=1 0.90 / k=S 1.90

| Quantity | Expected | Measured slope, S = 16..256 | Verdict |
|---|---|---|---|
| encoded view bytes | 1 (linear in S) | 1.00 | as expected |
| view encode allocations / time | 1 | 1.00 / 1.11 | linear |
| `ShardingScheme.IsValid` allocations | 1 | 1.00 | linear |
| `ShardingScheme.IsValid` time | 2 if pairwise | **1.85** | quadratic pair check, as the audit predicts (bft-go-base `IsValid`) |
| `UnicityTree` allocations / bytes / time | 1 | 0.90 / 0.92 / 1.02 | near-linear here: the quadratic validation is not yet dominant at S <= 256 because its constant is small, but it is the term that eventually is |
| dispatch bytes, one response (k=1) | 1 | 0.90 | linear (one frame carries one view) |
| dispatch bytes, all S shards respond (k=S) | 2 | **1.90** | quadratic, inherent: S recipients each need the whole S-leaf view in their self-contained frame |

The quadratic `IsValid` time and the quadratic k=S wire volume are the two superlinear terms. The first is an implementation cost fixable with a
sorted/trie validation (audit item 3); the second is inherent to the current protocol and only a different distribution scheme would change it.
At the production cap (S <= 8) both are small: `IsValid` on 8 shards is 8 allocations and about 1 µs here.

### 3.2 Changed shards per round k (fixed S = 4 and 8)

The inner view must be encoded once per partition regardless of k. The test asserts all k responses share one backing array
(`distinct view arrays` = 1 in every row) and counts the per-round build cost and the V2 bytes dispatched.

S = 4
| k (changed) | responses | distinct view arrays | build allocs | build B | build ns | V2 dispatch B (k frames) | view B in dispatch |
|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 465 | 35133 | 142446 | 1855 | 776 |
| 2 | 2 | 1 | 484 | 36064 | 195866 | 3710 | 1552 |
| 4 | 4 | 1 | 522 | 37908 | 166955 | 7420 | 3104 |

S=4 slopes over k: build allocs 0.08, build bytes 0.05 (both < 1: a fixed per-round cost plus a per-response term), dispatch bytes 1.00 (expect 1)

S = 8
| k (changed) | responses | distinct view arrays | build allocs | build B | build ns | V2 dispatch B (k frames) | view B in dispatch |
|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 719 | 59341 | 336764 | 2657 | 1544 |
| 2 | 2 | 1 | 738 | 60307 | 314145 | 5314 | 3088 |
| 4 | 4 | 1 | 775 | 62227 | 331806 | 10628 | 6176 |
| 8 | 8 | 1 | 852 | 66032 | 270550 | 21256 | 12352 |

S=8 slopes over k: build allocs 0.08, build bytes 0.05 (both < 1: a fixed per-round cost plus a per-response term), dispatch bytes 1.00 (expect 1)

Allocations and bytes of the whole response-building step grow with slope 0.08 / 0.05 in k: a fixed per-round cost (tree, view) plus a small
per-response term (certificate paths), i.e. the sidecar does **not** multiply with k. Dispatch bytes are exactly linear in k (slope 1.00), `k x (frame)`.

### 3.3 Recipient fan-out f (network layer)

The root chain builds the framed V1 and V2 bytes once per dispatch and shares them among the recipients of that response
(`certificationFrames`). The test asserts that serving every further recipient allocates nothing.

| recipients f | allocations to build both frames (once) | allocations for the other f-1 recipients | outgoing B (V2) |
|---|---|---|---|
| 1 | 81 | 0 | 1621 |
| 2 | 81 | 0 | 3242 |
| 4 | 81 | 0 | 6484 |
| 8 | 81 | 0 | 12968 |
| 16 | 81 | 0 | 25936 |
| 32 | 81 | 0 | 51872 |
| 64 | 81 | 0 | 103744 |
| 128 | 81 | 0 | 207488 |
| 256 | 81 | 0 | 414976 |

Serialization cost is flat in f (81 allocations for both frames, 0 for each additional recipient); outgoing bytes are exactly linear in f (slope 1), which is the
transport lower bound for sending one response to f peers.

### 3.4 LastCR sidecar retention over rounds R (rotating vs synchronous updates)

`LastCR` keeps the response (and its view bytes) a shard last received. If every shard changes each round they all share one view; if one shard changes per
round (rotating) each `LastCR` pins the view of the round in which it last changed.

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

The assertion `distinct views == min(R, S)` holds for the rotating case, so the claim "one view per partition is retained" is true only for synchronous updates;
under rotating updates up to S vectors (S x W bytes, 12,352 B at S=8, typical IR) are pinned, then plateau. There is no growth in R beyond S.

## 4. Per-round cost added by the sidecar (S = 1, 4, 8; typical IR)

Allocation counts and bytes are exact; the times are relative (best of 5, loaded machine; compare rows within this table only, never across machines).

| shape | response build before (B / allocs) | with sidecar (B / allocs) | added | view encode alone (B / allocs) | full `GenerateCertificates` (B / allocs) |
|---|---|---|---|---|---|
| 1 shard | 14,776 / 235 | 18,520 / 277 | +3,744 / +42 | 3,403 / 40 | 18,614 / 278 |
| 4 shards (2 changed) | 22,105 / 336 | 36,066 / 484 | +13,961 / +148 | 13,616 / 150 | 36,159 / 485 |
| 4 shards (4 changed) | 23,946 / 374 | 37,912 / 522 | +13,966 / +148 | 13,569 / 144 | 38,006 / 523 |
| 8 shards (3 changed) | 33,674 / 461 | 61,234 / 756 | +27,560 / +295 | 27,083 / 278 | 61,360 / 757 |
| 8 shards (8 changed) | 38,437 / 556 | 66,031 / 852 | +27,594 / +296 | n/a | 66,114 / 852 |

The added work is the view encode (`~3.4 KB x S` allocated, `~35 x S` allocations), paid once per changed partition per round, independent of k; "before" is a test-local copy of the pre-sidecar
loop on the same tree build. In relative time the response step is roughly 1.2x-1.9x its pre-sidecar cost across these shapes on this loaded machine (too noisy to be more precise); the unchanged `UnicityTree`
step is the same in both and is not affected by the sidecar. No extra network message is sent.

Wire (de)serialization of one response (typical IR, allocations exact): marshal V1 / V2 allocate 10.1 / 12.3 KB (1 shard), 10.8 / 14.4 KB (4), 11.0 / 15.8 KB (8) in 56 / 58 allocations
(the envelope adds two allocations, the rest is bytes); unmarshal V1 / V2 allocate 4.7 / 5.5 KB, 5.1 / 7.2 KB, 5.2 / 9.1 KB; decoding the view on the receiver allocates 3.4 KB / 37 allocations (1 shard),
12.9 KB / 130 (4), 25.6 KB / 254 (8), i.e. linear in S.

## 5. Not covered here

- Libp2p transport, signing, real root-chain round cadence; message counts are unchanged by design.
- S > 8 is an algorithm harness only: the producer, the view cap (8 leaves / 16 KiB) and `CanonicalShardOrder` reject it in production.
- Absolute latency: deliberately not reported (see the hardware context above).
