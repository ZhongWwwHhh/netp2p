# Performance baseline

Collected on 2026-10-10 with Go 1.25.7, Windows 11, amd64, and an Intel
i7-11800H (16 logical CPUs). Values are one `go test -bench` run with the
default one-second bench time and `-benchmem`; they establish the first local
baseline rather than a service-level SLO.

| Benchmark | Result |
| --- | ---: |
| `BenchmarkSnapshotClientViewHash` | 540,578 ns/op; 755,719 B/op; 3,058 allocs/op |
| `BenchmarkSnapshotSyncPath` | 1,667,607 ns/op; 54.91 MB/s |
| `BenchmarkSnapshotJSONSize` | 393,645 ns/op; 518.05 MB/s |
| `BenchmarkConntrackObserve` | 10,168 ns/op; 3 B/op; 0 allocs/op |
| `BenchmarkConntrackReplyAllowed` | 69.31 ns/op; 0 B/op; 0 allocs/op |
| `BenchmarkDNSOverlayQuery` | 271,200 ns/op; 4,034 B/op; 51 allocs/op |
| `BenchmarkForwardTableReplace` | 87.54 ns/op; 0 B/op; 0 allocs/op |
| `BenchmarkForwardTableSend` | 6,428 ns/op; 186.67 MB/s |
| `BenchmarkForwardTableAccept` | 4,484 ns/op; 267.59 MB/s |
| `BenchmarkPolicyAuthorize` | 30,426 ns/op; 46,024 B/op; 267 allocs/op |
| `BenchmarkPolicyCompile` | 94,018 ns/op; 185,816 B/op; 1,043 allocs/op |
| `BenchmarkTransportDirectThroughput` | 46,588 ns/op; 25.76 MB/s |
| `BenchmarkTransportViaManagerThroughput` | 127,948 ns/op; 9.38 MB/s |
| `BenchmarkTUNPacketIO` | 8,897 ns/op; 134.88 MB/s |
| `BenchmarkTUNRouteReconcile512Peers` | 39,463 ns/op; 64,128 B/op; 8 allocs/op |

The Linux-only exit-node reconcile benchmark compiles under `GOOS=linux go
vet`, but its numeric baseline must be collected on a Linux runner. Do not
compare Windows and GitHub-hosted Linux results directly.

Regression policy: once two runs from the same CI runner class exist, reject a
median slowdown greater than 10% for allocation-free hot paths and investigate
any new allocation in `ConntrackReplyAllowed`, `ForwardTableReplace`, or the
TUN packet loop. Network throughput benchmarks are directional because loopback
timing varies with host power management and scheduler load.
