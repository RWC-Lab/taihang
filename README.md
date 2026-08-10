# Taihang (太行)

Taihang is a high-performance C++20 cryptographic foundation library for
research and protocol engineering. It provides elliptic-curve and finite-ring
arithmetic, symmetric cryptographic primitives, serialization, network I/O,
data structures, and selected parallel algorithms behind a consistent,
context-based API.

The name refers to the Taihang Mountains (太行山), chosen to represent a stable
foundation on which larger systems can be built. It also preserves the
project's intended Chinese wordplay: *Taihang* evokes being highly capable.

Taihang is the ground-up successor to
[Kunlun](https://github.com/yuchen1024/Kunlun). Kunlun established the original
implementations and served as a productive research library; Taihang retains
that experience while redesigning the core for clearer ownership, stronger
composition, easier testing, and sustained development. Higher-level schemes
and protocols that were previously mixed into Kunlun are developed separately
in [taihang-protocols](https://github.com/RWC-Lab/taihang-protocols).

> [!WARNING]
> Taihang is research and engineering software. It has not been independently
> audited and should not be treated as a drop-in production cryptography
> solution. Users are responsible for validating protocol assumptions,
> parameter choices, side-channel requirements, and deployment threat models.

## Design Philosophy: Code as Paper

Taihang is guided by the idea that cryptographic code should be as clear to
follow as the mathematical description of the construction. “Code as Paper”
does not mean copying pseudocode literally; it means preserving the algorithm's
structure while expressing ownership, contexts, and failure conditions in a
form appropriate for robust software.

The design therefore emphasizes:

- **Mathematical correspondence.** Types and operations should make group,
  ring, and protocol relationships recognizable at the call site.
- **Explicit context.** Curves, scalar rings, and algorithm parameters should
  travel with the objects that depend on them instead of being hidden in
  process-global setup.
- **Readable performance.** Parallelism, precomputation, move semantics, and
  specialized data structures should improve hot paths without obscuring the
  underlying algorithm.
- **Composable layers.** The cryptographic core, protocols, and applications
  belong in separate repositories with a one-way dependency structure.
- **Verifiable behavior.** Public functionality should be accompanied by
  focused tests, while performance claims should be backed by reproducible
  benchmarks.

## Relationship to Kunlun

Kunlun is the origin of this project, not a compatibility layer. Taihang is a
new implementation informed by Kunlun's algorithms and practical lessons. API
compatibility is not a goal, and not every Kunlun module has been ported.

The project family is organized into distinct layers:

| Repository | Responsibility |
| --- | --- |
| **taihang** | Cryptographic primitives, algebra, utilities, networking, and foundational algorithms |
| **taihang-protocols** | Public-key encryption, zero-knowledge proofs, oblivious transfer, OPRF, VOLE, OKVS, PSI, mqRPMT, and related protocols |
| **taihang-applications** | Application-level systems built from the core and protocol layers |
| **Kunlun** | Original research codebase and historical reference implementation |

### Improvements over Kunlun

| Area | Kunlun | Taihang |
| --- | --- | --- |
| Library structure | Primarily header-oriented and monolithic | Public headers plus compiled implementations, reducing repeated compilation and enforcing library boundaries |
| Algebraic state | Process-global curve, ring, and discrete-log state | Explicit `ECGroup`/`ECPoint` and `Zn`/`ZnElement` context-instance APIs |
| Configuration | Compile-time or global configuration in many paths | Curve, ring, and solver parameters owned by the relevant object or public parameters |
| Resource ownership | Manual OpenSSL lifetime management in several modules | RAII-oriented wrappers, smart ownership, move semantics, and restricted copying where pointer stability matters |
| Composition | Primitives, protocols, and applications share one codebase | Layered repositories with a narrow dependency direction |
| Serialization | Module-specific encodings | Reusable fixed-width and stream serialization for core algebraic types |
| Error policy | Mixed assertions, printing, and direct process exits | Consistent `TAIHANG_ASSERT` contracts and `TAIHANG_CHECK` runtime checks |
| OpenSSL scratch state | Shared or manually coordinated `BN_CTX` use | Lazily initialized, RAII-managed thread-local `BN_CTX` instances |
| Parallel algorithms | Shared global coordination state | Instance-owned state and synchronized result publication, including atomic signaling in BSGS |
| Hash tables | General-purpose `std::unordered_map` paths | Robin-Hood flat hashing and compact 64-bit xxHash keys for BSGS workloads |
| Network I/O | Legacy transport paths and additional staging | Reusable buffers, direct TCP byte streams, and adaptive linearized/`writev` transmission |
| Validation | Ad hoc test programs | Discoverable GoogleTest suites and focused benchmark executables |

These changes are architectural rather than cosmetic. In particular, explicit
contexts allow independent curves and scalar rings to coexist in one process,
make object dependencies visible at call sites, and remove the hidden coupling
that made Kunlun difficult to extend safely.

## Features

### Cryptographic core

- `BigInt`: OpenSSL `BIGNUM` ownership, arithmetic, modular operations, and
  binary/text serialization.
- `Zn` and `ZnElement`: context-bound modular arithmetic with natural operator
  syntax, implicit modular reduction, and canonical fixed-width encoding. Code
  such as `c = a * b + d` remains close to the corresponding algebra.
- `ECGroup` and `ECPoint`: OpenSSL elliptic-curve contexts, point arithmetic,
  generator precomputation, vector operations, and multi-scalar
  multiplication.
- `BnContext`: lazily initialized thread-local OpenSSL scratch contexts with
  automatic lifetime management.
- `EC25519Point`: X25519-oriented point operations for MPC protocols.
- AES-128/AES-256, fixed-size 128-bit blocks, PRG, PRP, stream encryption, and
  SHA-256/SM3 hashing.
- Hash-to-integer and hash-to-scalar helpers.
- RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` hash-to-curve, including domain
  separation and RFC test-vector coverage.
- A faster, non-standard try-and-increment map for protocols whose design
  explicitly permits that construction.

### Algorithms and infrastructure

- Parallel baby-step giant-step discrete-log solving over bounded ranges, with
  persistent precomputation tables and configurable time-memory tradeoffs.
- Buffered and immediate TCP byte-stream I/O with reusable storage and
  adaptive scatter/gather transmission for large payloads.
- Bloom filters and plain hash structures.
- Polynomial, arithmetic, vector, inspection, transcoding, and serialization
  utilities.
- Runtime CPU information and architecture-specific acceleration paths.

## Repository Layout

```text
taihang/
├── include/taihang/
│   ├── algorithm/       # Foundational algorithms, including BSGS
│   ├── common/          # Configuration and contract checks
│   ├── crypto/          # Algebra and cryptographic primitives
│   ├── net/             # TCP network I/O
│   ├── structure/       # Bloom filters and hash structures
│   ├── system/          # Platform and CPU information
│   └── utility/         # Serialization and general mathematical utilities
├── source/              # Compiled implementations
├── tests/               # GoogleTest test suite
├── benchmarks/          # Standalone performance programs
├── third_party/         # Bundled header-only dependencies
└── CMakeLists.txt
```

## Requirements

- CMake 3.21 or later
- A C++20 compiler
- OpenSSL
- OpenMP
- xxHash with a CMake package configuration
- GoogleTest when `TAIHANG_BUILD_TESTS=ON`

The bundled Robin-Hood hash table does not require a separate installation.
The build enables the appropriate AES/SIMD compiler flags on supported x86-64
and ARM64 targets.

## Build and Test

The default configuration builds the library, tests, and benchmarks. When no
build type is supplied, CMake selects `Debug` so assertion-based contract tests
remain active.

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Useful CMake options are:

| Option | Default | Purpose |
| --- | --- | --- |
| `TAIHANG_BUILD_TESTS` | `ON` | Build and register the GoogleTest suite |
| `TAIHANG_BUILD_BENCHMARKS` | `ON` | Build standalone benchmark executables |
| `TAIHANG_ENABLE_LTO` | `ON` | Enable interprocedural optimization when supported |
| `TAIHANG_ENABLE_SANITIZER` | `OFF` | Enable AddressSanitizer on non-MSVC builds |

For performance measurements, use a separate release build:

```bash
cmake -S . -B build-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DTAIHANG_BUILD_TESTS=OFF
cmake --build build-release --parallel
./build-release/bench_bsgs_dlog
./build-release/bench_hash_to_curve
```

Benchmark results depend on the compiler, processor, OpenSSL build, thread
count, and selected parameters. Measure on the intended deployment platform
rather than treating repository-local results as universal figures.

## Basic Usage

The parent context must outlive every element or point that refers to it.
Shared ownership is convenient when parameters and protocol objects need to
carry those contexts together.

```cpp
#include <cstdint>
#include <memory>

#include <openssl/obj_mac.h>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

int main() {
    auto group = std::make_shared<taihang::ECGroup>(
        NID_X9_62_prime256v1);
    auto scalar_ring = std::make_shared<taihang::Zn>(group->order);

    taihang::ZnElement scalar(
        scalar_ring, taihang::BigInt(std::uint64_t{7}));
    taihang::ECPoint point = group->get_generator() * scalar;

    return point.is_at_infinity() ? 1 : 0;
}
```

For an in-tree CMake consumer:

```cmake
add_subdirectory(path/to/taihang)
target_link_libraries(my_target PRIVATE taihang::taihang)
```

Taihang also installs headers, the static library, and CMake package files:

```bash
cmake --install build-release --prefix /path/to/prefix
```

## Coding Style and API Conventions

Taihang uses a consistent naming scheme influenced by the Google C++ Style
Guide:

| Entity | Convention | Example |
| --- | --- | --- |
| Namespaces | `snake_case` | `taihang::dlog` |
| Types and classes | `PascalCase` | `ZnElement`, `ECPoint` |
| Functions | `snake_case` | `get_zero()`, `to_bytes()` |
| Variables | `snake_case` | `element_count` |
| Data members | `snake_case` | `ring_ctx` |
| Constants | `kPascalCase` | `kDefaultHash` |
| Template parameters | `PascalCase` | `template <typename Element>` |
| Macros | `ALL_CAPS` | `TAIHANG_ASSERT` |
| Files | `snake_case` | `ec_group.cpp` |

The following semantic conventions are equally important:

- Algebraic values retain a pointer to their parent context. Callers must not
  mix values from unrelated contexts or destroy a context while dependent
  values remain alive.
- `TAIHANG_ASSERT` expresses caller and internal contracts. It is disabled when
  `NDEBUG` is defined, so conditions must not contain required side effects.
- `TAIHANG_CHECK` is used for failures that must remain checked in release
  builds.
- Stream deserialization of context-dependent values requires the destination
  object to be initialized with the correct context first.
- Standardized and custom cryptographic constructions are named separately.
  Choose them according to the protocol specification, not solely by speed.

## Contributing

Changes should preserve the context-instance design, keep public declarations
in `include/` and implementations in `source/`, and include focused tests for
new behavior. Performance-sensitive work should include a reproducible
benchmark and retain a readable reference to the underlying algorithm.

## Citation and Contact

If Taihang supports academic work, cite the repository with the release or
commit used and cite the original papers for the constructions involved. For
the current project version, the following software citation can be used:

```bibtex
@software{taihang_2026,
  author  = {Yu Chen},
  title   = {Taihang: A C++ Cryptographic Foundation Library},
  year    = {2026},
  version = {0.1.0},
  url     = {https://github.com/RWC-Lab/taihang}
}
```

Questions, bug reports, and design discussions are welcome through the
[GitHub issue tracker](https://github.com/RWC-Lab/taihang/issues).

## License

Taihang is released under the [MIT License](LICENSE).
