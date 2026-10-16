These hand-authored R-01 records use synthetic addresses and timestamps.
They exercise dump/restore provenance, unknown peer/payload and gap metadata.
They are not evidence of a physical consensus run.

`scheduler-source/frames-scheduler-fixture.jsonl` is a public synthetic R01
export with one declaration, eight measured operations and four original
steps. A retry expiry queues during the next step, before its cancellation
request, and is dequeued later. The declaration's clock is explicitly
unavailable; operation and step-entry clocks are distinct. This fixture is a
finite scheduler snapshot, not a replay of a complete consensus chain.
