package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

func linkedOrigin() (Origin, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Origin{}, ErrInput
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/ethereum/go-ethereum" && d.Replace != nil && d.Replace.Path == OriginPath && d.Replace.Version == OriginVersion && d.Replace.Sum == OriginSum {
			return Origin{Path: OriginPath, Version: OriginVersion, Sum: OriginSum}, nil
		}
	}
	return Origin{}, ErrInput
}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wbft-execution-witness", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "checksummed original source manifest")
	directory := fs.String("root", "", "directory containing relative source files")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stderr, "Usage: wbft-execution-witness --manifest FILE --root DIR")
			return 0
		}
		fmt.Fprintln(stderr, "invalid execution witness arguments")
		return 64
	}
	if fs.NArg() != 0 || *manifest == "" || *directory == "" {
		fmt.Fprintln(stderr, "execution witness requires original sources")
		return 64
	}
	origin, err := linkedOrigin()
	if err != nil {
		fmt.Fprintln(stderr, "execution witness implementation unavailable")
		return 69
	}
	f, err := os.Open(*manifest)
	if err != nil {
		fmt.Fprintln(stderr, "execution witness manifest unavailable")
		return 65
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	_ = f.Close()
	if err != nil || len(raw) > MaxManifestBytes {
		fmt.Fprintln(stderr, "invalid execution witness manifest")
		return 65
	}
	root, err := os.OpenRoot(*directory)
	if err != nil {
		fmt.Fprintln(stderr, "execution witness source directory unavailable")
		return 65
	}
	defer root.Close()
	report, err := verify(ctx, raw, root)
	if err != nil {
		fmt.Fprintln(stderr, "execution witness sources could not be verified")
		if ctx.Err() != nil {
			return 130
		}
		return 65
	}
	report.Origin = origin
	if json.NewEncoder(stdout).Encode(report) != nil {
		fmt.Fprintln(stderr, "execution witness result could not be written")
		return 70
	}
	return 0
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
