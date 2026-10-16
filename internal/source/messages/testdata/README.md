These hand-authored R-01 records use synthetic addresses and timestamps.
They exercise dump/restore provenance, unknown peer/payload and gap metadata.
They are not evidence of a physical consensus run.

`scheduler-source/frames-scheduler-fixture.jsonl` is a public synthetic R01
export with one declaration, eight measured operations and four original
steps. A retry expiry queues during the next step, before its cancellation
request, and is dequeued later. The declaration's clock is explicitly
unavailable; operation and step-entry clocks are distinct. This fixture is a
finite scheduler snapshot, not a replay of a complete consensus chain.


`cache-source/frames-cache-fixture.jsonl` is a synthetic finite cache snapshot.
A retry target decision precedes a later relay suppression, while the original
retry write callback appears last. Its enqueue identity links it to operation
one, rather than the physically adjacent suppression. `cache-source-combined/`
uses one shared scheduler/cache declaration at the same original source row.
These fixtures contain no captured chain material and prove no delivery.
