# Taihang (太行)

**Taihang** is a high-performance, elegant, and industrial-grade C++ cryptography library. The name originates from the **Taihang Mountains** (太行山), one of China's most iconic mountain ranges - symbolizing stability, national strength, and a "pillar of the state" (国之重器). Phonetically, *Tai Hang* (太行) also serves as a pun in Chinese, meaning "highly capable". 

--- 

## ⛰️ Design Philosophy: "Code as Paper"

Taihang is built on the belief that writing cryptographic code as intuitive and elegant as writing a mathematical proof in a research paper. It prioritize: 

---

## 🚀 Key Improvements over Kunlun

taihang is the successor to the Kunlun library, redesigned from the ground up to be more robust, modular, and developer-friendly.

### 1. Architectural Evolution
* **HPP/CPP Separation**: No longer a header-only library. This drastically reduces compilation times for large projects and eliminates complex "multiple definition" linker errors.
* **Context-Instance Pattern**: Both `Zn/ZnElement` and `ECGroup/ECPoint` follow this pattern. This allows multiple different fields or curves to coexist in a single execution context without global state conflicts.
* **Implicit Mod-Arithmetic**: The `ZnElement` class wraps big integers, allowing developers to write code like `C = A * B + D` while the library silently handles modular reduction in the background.
* **Stateless Configuration**: Eliminated global variables. Parameters like curve names, point compression, and security levels are specified at runtime during object construction.


### 2. Modern C++ Standard
* **Efficiency & Robustness**: Leverages **Move Semantics** to avoid expensive big-integer copies.
* **Resource Management**: Uses smart pointers and strictly `deleted` copy constructors where manual resource duplication is risky.

### 3. High-Performance Parallelism
* **Thread-Safe OpenSSL**: Introduces a dedicated `BN_CTX` management class. Unlike standard OpenSSL wrappers, Taihang allows the number of parallel contexts to be specified at runtime, enabling true multi-threaded cryptographic execution.
* **Optimized NetIO**: A complete rewrite of the network layer. It communicates via direct byte-streams, removing legacy filesystem dependencies for direct, low-latency streaming.

---

## 📂 Directory Structure

taihang features a highly organized, modular layout:
```
tree -I "build|bin|lib|.git"           
```

```text
.
├── include/taihang/
│   ├── algorithm/     # High-level algorithms (e.g., BSGS DLog)
│   ├── crypto/        # Core primitives (Zn, EC, AES, Hash, PRG, PRP)
│   ├── net/           # Optimized Network I/O
│   ├── structure/     # Crypto-friendly data structures (Bloom Filter, Hash Maps)
│   └── utility/       # Arithmetic tools, Polynomials, and Serialization
├── source/            # Implementation files (CPP)
├── tests/             # Comprehensive GTest suite
├── benchmarks/        # Performance evaluation scripts
├── third_party/       # Bundled dependencies (e.g., robin_hood, curve25519)
```

---

## 🛠️ Build & Installation

### Build Options
* `-DTAIHANG_BUILD_TESTS=ON`: Build the GTest suite.
* `-DTAIHANG_ENABLE_LTO=ON`: Enable Link Time Optimization (Default: ON).
* `-DTAIHANG_ENABLE_SANITIZER=ON`: Enable AddressSanitizer for debugging.


### Dependencies
* **OpenSSL (3.0+)**: Core big-integer and symmetric primitives.
* **OpenMP**: For multi-threaded acceleration.
* **xxHash**: High-speed hashing for non-cryptographic tasks.
* **robin_map**: Flat hash table. Included in `third_party/`.
* **GTest**: Required to build and run the test suite.


### Building
Taihang uses CMake with hardware-specific optimizations (AVX2, AES-NI, ARM Crypto) automatically enabled.

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
# To run tests:
ctest --output-on-failure 
```
---

## 📏 Coding Style

Taihang follows a strict naming convention to maintain a professional and scannable codebase, largely inspired by the Google C++ Style Guide:

| Entity | Convention | Example |
| :--- | :--- | :--- |
| **Namespaces** | `snake_case` | `taihang::crypto` |
| **Types / Classes** | `PascalCase` | `ZnElement`, `ECPoint` |
| **Functions** | `snake_case` | `get_zero()`, `to_bytes()` |
| **Variables** | `snake_case` | `modulus`, `element_count` |
| **Members** | `snake_case` | `this->value`, `field_ctx` |
| **Constants** | `kPascalCase` | `kDefaultSecurityParam` |
| **Templates** | `PascalCase` | `template <typename T>` |
| **Macros** | `ALL_CAPS` | `TAIHANG_ASSERT` |
| **Files** | `snake_case` | `zn_element.cpp` |

---

## 🧪 Testing & Performance

* We use the **GoogleTest (gtest)** framework to ensure the correctness of every primitive. Every new feature requires a corresponding test case in the `tests/` directory. 
* Benchmarks for BSGS and other algorithms can be found in the `benchmarks/` directory to evaluate the library's performance in your specific environment.

---

## 📬 Contact & Citation
If you use taihang in your research, please cite the library or the related academic works.

---






