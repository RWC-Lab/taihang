# Hash-to-Curve Benchmark

This benchmark compares Taihang's two P-256 APIs using the same 8,192
preconstructed messages over six alternating measurement rounds (49,152 calls
per mapping). Group construction, message construction, and result
serialization are outside the timed region. The build uses Taihang's `-O3`
flags on macOS 15.7.7 x86-64.

Run with:

```sh
./build/bench_hash_to_curve 8192 6
```

| Mapping | Mean (us) | P50 (us) | P95 (us) | P99 (us) | Throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| Try-and-increment | 54.749 | 38.330 | 130.954 | 183.993 | 18,265 ops/s |
| RFC 9380 SSWU | 170.487 | 167.672 | 196.827 | 234.871 | 5,866 ops/s |

The current RFC 9380 implementation is 3.11x slower by mean latency and 4.37x
slower at the median. Try-and-increment is faster because it uses one SHA-256
digest followed by AES-assisted candidate generation and usually finds a curve
point quickly. Its latency is input-dependent: P95 is 3.42x its median. SSWU
performs SHA-256 XMD, maps two field elements, and adds the resulting points;
its P95 is only 1.17x its median.

These numbers should guide engineering choices, not the security choice.
Try-and-increment is nonstandard and has an input-dependent rejection loop.
RFC 9380 provides the specified random-oracle encoding and interoperability.
Taihang's current BigInt/OpenSSL SSWU implementation has bounded mapping steps
but is not claimed to be constant-time for secret messages.
