# Sanitized real G7 metadata excerpt

These JSON lines come from a local seven-validator go-stablenet
`740526d03` run launched by chainbench `b9e5be39` on 2026-10-13 (Asia/Seoul).
Only metadata of selected event kinds at heights 5542 and 5565 is retained;
message bytes, errors, arbitrary values and unrelated records are omitted.
This is an incomplete excerpt with new line numbers and file hashes, not
an archive of the original log sources or a complete event stream.

At height 5542, the round-zero proposer (node4) was stopped. The six
remaining nodes enter round 1; node3 correlates that entry with F+1 and
five nodes with timeout. At height 5565, consecutive proposers node5 and
node6 were stopped; five remaining nodes enter rounds 1 and 2 by timeout.
The manifest names locally generated validator identities and the local
chain's genesis hash. It contains no keys or private network material.

The full real-run import separately checks all original seven files
(about 1.7 GB), source hashes, original line pointers and 38,302 events in
the scenario window. It is not replaced by this small fixture.
