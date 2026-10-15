# UC consolidation: sidecar size and per-round cost measurements

Acceptance evidence for the bft-core ticket ("report encoded sidecar sizes and
added serialization/certification cost at four and eight shards").

- Base: `origin/uc-consolidation` @ `77b8f7e9` (B1/C1/C2 merged).
- Machine: Intel Core i7-8850H @ 2.60 GHz, 6 cores / 12 threads, 16 GiB, macOS 15.8.1 (darwin/amd64), Go 1.27.2.
- Code: `rootchain/consensus/storage/measurement_test.go`.

## Reproduce

```sh
# exact encoded sizes (markdown table in the test log)
go test ./rootchain/consensus/storage -run Test_MeasurementReport -v -count=1

# per-round cost: tree, responses with/without sidecar, view encode, full certification step, wire (de)serialization
go test ./rootchain/consensus/storage -run '^$' \
  -bench 'UnicityTree|CertificationResponses|EncodePartitionView|GenerateCertificates|ResponseSerialization' \
  -benchmem -benchtime=500ms -count=8
```

## Inputs

The measured block has one partition with 1/4/8 shards plus three single-shard partitions, all certified every round
(the root chain builds the whole unicity tree each round). Seal: network ID 5, 4 root validator signatures of 65 B.
"Changed" shards are the ones getting a response.

- **typical aggregation IR**: 32 B state/previous/block hashes, empty non-nil summary value, zero fees, `ETHash` absent.
- **max-admission IR**: summary value 256 B (the consolidation limit), `SumOfEarnedFees` = 2^53, all other fields as above.
  This is the largest IR the producer admits, not an observed value.

## Encoded sizes (exact, bytes)

`PartitionViewV1` is one encoding per partition per round, shared by all responses. A "frame" is the unsigned-varint
length prefix plus the CBOR payload. V1 is the unchanged legacy four-element response (`/ab/certificates/0.0.1`),
V2 is `[2, [partition, shard, technical, uc], bstr(view)|null]` (`/ab/certificates/0.0.2`). "Added per response" is
V2 with view minus V1.

| IR | shape | view | V1 frame | V2 frame, view | added per response | V2 frame, null view | UC |
|---|---|---|---|---|---|---|---|
| typical | 1 shard | 200 | 1006 | 1210 | 204 | 1009 | 871 |
| typical | 4 shards | 776 | 1074 | 1855 | 781 | 1077 | 939 |
| typical | 8 shards | 1544 | 1108 | 2657 | 1549 | 1111 | 973 |
| max-admission | 1 shard | 466 | 1272 | 1743 | 471 | 1275 | 1137 |
| max-admission | 4 shards | 1840 | 1340 | 3185 | 1845 | 1343 | 1205 |
| max-admission | 8 shards | 3672 | 1374 | 5051 | 3677 | 1377 | 1239 |

Sizes do not depend on how many shards changed; the bytes added to a round are `changed shards x added per response`
(8 shards, all changed, typical IR: 8 x 1549 = 12,392 B; one changed shard: 1,549 B). The null-view V2 frame costs 3 B over V1
(envelope version and null). Every view and frame is far below the admission limits (view 16 KiB, frame 1 MiB):
8 shards at max-admission is 3,672 B (22% of the view limit). A single-shard partition gains nothing from a
view (it is the response's own leaf); it is still produced for a uniform contract and costs 204 B.

## Added per-round cost

Allocation figures are deterministic. Time figures are the **best of 8** runs: the machine was heavily loaded by other
processes while these ran (load average 145 on 12 threads), so absolute times are inflated and noisy; read the
ratios, and re-run on a quiet machine before quoting latency to the owner.

Response building before (`baseline`: the pre-sidecar loop, same tree build) and after (`withView`), typical IR:

| shape | baseline time | with view time | baseline B/op | with view B/op | baseline allocs | with view allocs |
|---|---|---|---|---|---|---|
| 1 shard | 56 µs | 70 µs | 14,776 | 18,520 | 235 | 277 |
| 4 shards (2 changed) | 98 µs | 255 µs* | 22,104 | 36,059 | 336 | 484 |
| 4 shards (4 changed) | 194 µs | 291 µs | 23,947 | 37,917 | 374 | 522 |
| 8 shards (3 changed) | 299 µs | 475 µs | 33,671 | 61,270 | 461 | 756 |
| 8 shards (8 changed) | 337 µs | 520 µs | 38,439 | 66,031 | 556 | 851 |

*outlier from machine load (the 4-changed row of the same shape is 291 µs); the allocation columns are the reliable ones.

Added work by itself, `encodePartitionView` (clone of the leaf vector + canonical CBOR, once per changed partition per round),
typical IR: 1 shard 3.4 KB / 40 allocs, 4 shards 13.6 KB / 144 allocs, 8 shards 27.2 KB / 294 allocs
(time best-of-8: 21 µs / 73-100 µs / 157 µs). Max-admission IR: 5.6 KB / 22.5 KB / 45.0 KB.

The mandatory tree build is unchanged by the sidecar (`UnicityTree`, best-of-8: 1 shard 45 µs, 4 shards 69 µs, 8 shards 127 µs;
13.9 / 20.2 / 30.8 KB; 216 / 296 / 402 allocs). The full per-round certification step
(`GenerateCertificates`, includes tree, responses, views and seal attach), best-of-3 medians: 1 shard 127 µs,
4 shards 249 µs, 8 shards 408 µs. So, at 8 shards, the sidecar adds roughly 25 KB of garbage and about 150-200 µs of CPU once per
round, and no extra network message is sent (compare against the deployment's round duration, which was not measured here).

Wire (de)serialization of one response (best-of-3 medians, typical IR; the root chain serializes once per dispatch and
shares the framed bytes among recipients):

| shape | marshal V1 | marshal V2 | unmarshal V1 | unmarshal V2 | decode view (receiver) |
|---|---|---|---|---|---|
| 1 shard | 28 µs | 34 µs | 37 µs | 42 µs | 22 µs |
| 4 shards | 32 µs | 38 µs | 35 µs | 34 µs | 57 µs |
| 8 shards | 23 µs | 33 µs | 32 µs | 38 µs | 120 µs |

V2 marshalling allocates 8.3 / 10.1 / 12.2 KB against 6.7 / 7.2 / 7.6 KB for V1 (1 / 4 / 8 shards).
The receiver-side cost is paid by the aggregator only, and only for views it keeps (`decode view`, 8 shards: 25.6 KB / 254 allocs).

## Caveats

- Times come from a shared, loaded laptop; treat as upper-bound, order-of-magnitude figures.
- The baseline is a test-local copy of the pre-sidecar response loop (identical tree build), not a build of an older commit.
- Seal signatures are 65-byte placeholders, not verified; they only affect sizes.
- Not measured here: libp2p transport, signing, real root-chain round cadence, and message count (unchanged by design).
