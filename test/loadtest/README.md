# NetP2P load and scale harness

This package benchmarks the protocol shapes required by global load balancing:

- five flow classes, including realtime;
- routing-domain and path-family authorization;
- a deterministic global optimizer;
- compact routing epochs;
- a sharded client flow table;
- a durable SQLite sharded peer registry;
- scoped bootstrap and delta measurements.

The fixtures are synthetic, but they use the real Go protocol types, real maps,
real SQLite storage, and real authorization lookups. No mock sender, mock
store, or mock policy engine is used as acceptance evidence.

## Run

```powershell
./test/loadtest/run.ps1 quick
./test/loadtest/run.ps1 production
./test/loadtest/run.ps1 architecture
```

On POSIX:

```bash
./test/loadtest/run.sh quick
./test/loadtest/run.sh production
./test/loadtest/run.sh architecture
```

The command writes a JSON verification manifest to a local, untracked
verification directory; use `--output` to choose an explicit path. Manifests
include sizes, durations, p99 values, memory use, storage use, and pass/fail
thresholds.

## Scenarios

- `quick`: 10,000 peers, 100,000 flows, 1,000 domains, and a 10,000-peer registry.
- `production`: 100,000 peers, 1,000,000 flows, 10,000 domains, and a 1,000,000-peer registry.
- `architecture`: 1,000,000 peers, 10,000 domains, and a 1,000,000-peer durable registry.

Override any count with the command flags, for example:

```bash
go run ./test/loadtest/cmd --scenario production --flows 1000000 --registry-peers 1000000
```

## Acceptance thresholds

- optimizer at 100,000 peers: less than 250ms;
- routing epoch: less than 5MB;
- one million flow entries: less than 512MB;
- path-family authorization p99: less than 20us;
- scoped bootstrap: less than 10MB;
- typical scoped delta: less than 1MB;
- registry query p99 at one million peers: less than 20ms.

The production network E2E, throughput, and soak tests remain in the existing
userspace, TUN, exit-node, multihop, quota, and chaos suites. This harness
covers the protocol and scale dimensions that those suites cannot reach
without creating a million real machines.
