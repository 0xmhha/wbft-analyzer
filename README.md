# wbft-analyzer

wbft-analyzer loads what WBFT networks record and shows how consensus ran.
Its inputs come from the other WBFT repositories:

- block headers (participation, proposers, epochs) over RPC;
- node logs, the consensus event streams and the message journals of
  [wbft](https://github.com/0xmhha/wbft) nodes;
- the JSON reports of [wbft-inspector](https://github.com/0xmhha/wbft-inspector),
  the only source of verdicts: the analyzer does not decide requirements
  itself, it places the inspector's verdicts and observations on the
  timelines it derives.

The data goes into PostgreSQL; derived tables (participation matrix, round
timelines, message latency, observation trends) are served over a REST API
to a static web front end.

## Status

The analyzer is built in stages; this repository is at the start of the
first one (A0):

| Stage | Content | State |
|---|---|---|
| A0 | command skeleton, inspector report loader with the public-build checks, PostgreSQL store, observation trends and alerts, API and front-end skeleton | started |
| A1 | header analysis: participation, proposers, epochs | not started |
| A2 | node logs and chainbench runs | not started |
| A3 | wbft event streams and mixed networks | not started |
| A4 | governance history | not started |

Every command is listed by `wbft-analyzer help`; a command that is not built
yet says so and exits with code 69.

Built so far:

- `wbft-analyzer ingest reports --db DSN FILE ...` loads inspector reports:
  the public-build checks, one copy per file, and the observation rates of
  each report added to the trends of its network, with the network's alert
  rules evaluated and their webhooks told of state changes.
- `wbft-analyzer serve --db DSN` serves the REST API under `/v1`: networks,
  reports with their results and observations (and `POST /v1/reports`,
  the same loader), observation trends, alert rules (`PUT` replaces a
  network's set) and alert states. It listens on `127.0.0.1:8080` and
  then answers only to a loopback host name; another address needs
  `--auth token`, a bearer token taken from `$WBFT_ANALYZER_TOKEN`. The
  server speaks plain HTTP: reach it over a network through a TLS proxy.
- The API is described by an OpenAPI 3.1 document, built from the route
  table and the Go types of the answers. It is served at
  `GET /v1/openapi.json` and committed as `api/openapi.json` for the front
  end's type generation. After changing the API, rewrite the committed copy
  with `go test ./internal/api -run TestOpenAPIDocument -update`. The tests
  check every answer they receive against the document.

A local PostgreSQL for development and the integration tests:

```
docker compose -f deploy/postgres/compose.yaml up -d
WBFT_ANALYZER_TEST_DSN='postgres://analyzer:analyzer@127.0.0.1:5433/analyzer?sslmode=disable' go test ./...
```

`scripts/dump-check.sh SOURCE_DSN TARGET_DSN OUT_DIR` loads a set of
reports, saves the database with `pg_dump`, restores the dump into another
database and checks that the API answers the same from both; CI runs it
on two PostgreSQL servers and keeps the dump as the `analyzer-dump`
artifact. A dump restores with
`pg_restore --no-owner --dbname=DSN analyzer.dump` and opens with `serve`.

## Web front end

`web/` is a static React/d3 page that `serve` delivers at `/`. It
shows the loaded networks, the inspector's verdicts across reports, and
observation trends with their alert rules. Its API types are generated from
`api/openapi.json` (`npm run gen`). `npm run build` writes it to
`internal/web/dist/app`, which `go build` embeds. A binary built without
that step (for example by `go install`) serves the API only, and answers its
pages with 503.

```
cd web && npm ci && npm run build && cd ..
go build ./cmd/wbft-analyzer
```

For development, `npm run dev` serves the page with hot reload and sends
`/v1` to a `wbft-analyzer serve` on `127.0.0.1:8080`.

## Build and test

```
go build ./...
go test ./...
```

Go 1.26.8 or later.

## Public scope

The analyzer only accepts reports of the public inspector build for the
requirements of the public specification; a report naming anything else is
refused as a whole. It shows improvement IDs as given and carries no
description of them.

## License

LGPL-3.0-or-later. See `LICENSE` and `COPYING`.
