// Command wbft-analyzer loads what WBFT networks record (headers, node
// logs, event streams, message journals, inspector reports) into a store,
// derives analyses from it, and serves them to a web front end.
//
// Usage:
//
//	wbft-analyzer serve   --db DSN [--listen 127.0.0.1:8080] [--auth token]
//	wbft-analyzer ingest  reports --db DSN FILE ...
//	wbft-analyzer ingest  run --manifest FILE [--report FILE ...]
//	wbft-analyzer ingest  range --rpc URL --from N --to M
//	wbft-analyzer follow  --rpc URL --from N
//	wbft-analyzer reindex --dataset NAME
//	wbft-analyzer export  --dataset NAME --out DIR
//	wbft-analyzer version
//
// Exit codes: 0 success, 64 usage error, 65 input data refused or invalid,
// 69 not available, 70 internal error.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes (sysexits).
const (
	exitOK          = 0
	exitUsage       = 64
	exitUnavailable = 69
)

// version is the analyzer's version; releases set it with -ldflags.
var version = "dev"

const usage = `wbft-analyzer loads WBFT network records and inspector reports and analyzes them.

Commands:
  serve     serve the REST API and the web front end
  ingest    load a dataset: inspector reports, a chainbench run, or a range of blocks
  follow    load the blocks of a network as they come
  dataset   adopt retained inputs, delete a dataset, or inspect deletion
  reexec    compare recorded journal steps with the actual WBFT core
  reconstruct assess fixed log and frame sources before core input reconstruction
  whatif    run a counterfactual timer policy on complete retained input
  scenario  inspect a recorded network scenario and its fitting coverage
  reindex   rebuild the derived tables of a dataset
  export    write a dataset to a directory
  version   print the version

Run "wbft-analyzer <command> -h" for the flags of a command.
`

// commands dispatches the supported command handlers.
var commands = map[string]func(args []string, stdout, stderr io.Writer) int{
	"serve":         runServe,
	"dataset":       runDataset,
	"ingest":        runIngest,
	"follow":        runFollow,
	"reindex":       runReindex,
	"reexec":        runReexec,
	"reconstruct":   runReconstruct,
	"whatif":        runWhatif,
	"scenario":      runScenario,
	"reexec-helper": runReexecHelper,
	"export":        runExport,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "wbft-analyzer %s\n", version)
		return exitOK
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	if cmd, ok := commands[args[0]]; ok {
		return cmd(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}
