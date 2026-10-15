-- One build class owns a deployment; private overlays never share a public store.
CREATE TABLE deployment_scope (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 visibility text NOT NULL CHECK(visibility IN ('public','private'))
);
ALTER TABLE reports ADD COLUMN inspector_build text NOT NULL DEFAULT 'public';
-- Older reports did not own a dataset. Preserve their rows and give each a
-- stable, independently exportable owner. A name conflict aborts the migration.
INSERT INTO datasets(network_id,name,kind,visibility,status)
 SELECT r.network_id,'report:'||r.id,'reports',COALESCE(n.visibility,'public'),'complete'
 FROM reports r LEFT JOIN networks n ON n.id=r.network_id WHERE r.dataset_id IS NULL;
UPDATE reports r SET dataset_id=d.id FROM datasets d WHERE r.dataset_id IS NULL AND d.name='report:'||r.id;
ALTER TABLE reports ALTER COLUMN dataset_id SET NOT NULL;
