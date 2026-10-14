-- Original receive evidence is independent of counterfactual output positions.
CREATE TABLE whatif_network_bindings (
 run_id bigint NOT NULL REFERENCES whatif_runs(id) ON DELETE CASCADE,
 id bigint NOT NULL CHECK(id>0),
 writer_run text NOT NULL,
 engine_run numeric(20,0) NOT NULL,
 step numeric(20,0) NOT NULL,
 ordinal numeric(20,0) NOT NULL,
 output numeric(20,0) NOT NULL,
 record jsonb NOT NULL,
 PRIMARY KEY(run_id,id)
);
CREATE INDEX whatif_network_bindings_source ON whatif_network_bindings(run_id,writer_run,engine_run,step,output);
CREATE TABLE whatif_network_effects (
 run_id bigint NOT NULL REFERENCES whatif_runs(id) ON DELETE CASCADE,
 id bigint NOT NULL CHECK(id>0),
 execution_step bigint,
 output numeric(20,0),
 kind text NOT NULL,
 record jsonb NOT NULL,
 PRIMARY KEY(run_id,id)
);
CREATE INDEX whatif_network_effects_execution ON whatif_network_effects(run_id,execution_step,id);
