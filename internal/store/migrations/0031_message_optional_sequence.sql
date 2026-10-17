-- Typed notification headers and footers have no original source sequence.
-- Keep their absence instead of assigning a canonical or invented sequence.
ALTER TABLE message_records ALTER COLUMN seq DROP NOT NULL;
ALTER TABLE message_records ADD CONSTRAINT message_records_sequence_presence
 CHECK (seq IS NOT NULL OR type = 'sync_notification_source');
