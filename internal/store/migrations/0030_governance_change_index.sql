-- Exact-index reverse source lookup across a network's governance captures.
CREATE INDEX gov_validator_changes_header_lookup
 ON gov_validator_changes(number,dataset_id,call_ordinal,ordinal);
