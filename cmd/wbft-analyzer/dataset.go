package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func runDataset(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "delete" && args[0] != "adopt-inputs" && args[0] != "deletion") {
		fmt.Fprintln(stderr, "Usage: wbft-analyzer dataset delete|adopt-inputs|deletion --db DSN --network N --dataset N [--confirm-name NAME] [--inputs-dir DIR]")
		return exitUsage
	}
	operation := args[0]
	fs := flag.NewFlagSet("dataset "+operation, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	network := fs.Int64("network", 0, "network ID")
	dataset := fs.Int64("dataset", 0, "dataset ID")
	confirm := fs.String("confirm-name", "", "exact dataset name required for deletion")
	directory := fs.String("inputs-dir", "", "private input root for verified adoption")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *dsn == "" || *network < 1 || *dataset < 1 || operation == "delete" && (*confirm == "" || len(*confirm) > 256) || operation == "adopt-inputs" && *directory == "" {
		return exitUsage
	}
	ctx := context.Background()
	s, e := store.Open(ctx, *dsn)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitUnavailable
	}
	defer s.Close()
	if _, e = s.Migrate(ctx); e != nil {
		fmt.Fprintln(stderr, e)
		return exitInternal
	}
	switch operation {
	case "adopt-inputs":
		e = s.AdoptDatasetInputs(ctx, *network, *dataset, *directory)
		if e == nil {
			e = json.NewEncoder(stdout).Encode(map[string]any{"dataset_id": *dataset, "status": "adopted"})
		}
	case "delete":
		var out store.DatasetDeletion
		out, e = s.DeleteDataset(ctx, *network, *dataset, *confirm)
		if e == nil {
			e = json.NewEncoder(stdout).Encode(out)
		}
	case "deletion":
		var out store.DatasetDeletion
		out, e = s.DatasetDeletion(ctx, *network, *dataset)
		if e == nil {
			e = json.NewEncoder(stdout).Encode(out)
		}
	}
	if e != nil {
		fmt.Fprintln(stderr, e)
		return exitDataErr
	}
	return exitOK
}
