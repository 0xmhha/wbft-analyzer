-- Explicit input-loss experiments never claim reproduced closed execution.
ALTER TABLE reexec_runs DROP CONSTRAINT reexec_runs_status_check;
ALTER TABLE reexec_runs ADD CONSTRAINT reexec_runs_status_check
 CHECK(status IN ('running','failed','not_possible','partial','regression','diverged','reproduced','counterfactual'));
