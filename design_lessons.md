## Design of EC Point Class

Follow the Context (the environment) ECGroup ====> Instance (the data) ECPoint pattern.

**ECGroup: Heavyweight Environment**
- ECGroup is a "Singleton-style" Context. ECGroup acts as the source of truth for all its points. It shouldn't be duplicated or moved around. 

- It contains the precomputation tables (which can be megabytes in size) and the curve parameters that are expensive to allocate and initialize. 
Deep-copying an ECGroup would require re-calculating all those expensive precomputation tables.

- By deleting the assignment operator, the compiler forces you to use a pointer or a reference, ensuring you only ever "point" to the heavy object rather than cloning it. From the architectural perspective, it forces you to treat the group as a *fixed environment*.

```
    // Disable copying to maintain pointer stability for ECPoint instances
    ECGroup(const ECGroup&) = delete;
    ECGroup& operator=(const ECGroup&) = delete;
```

**ECPoint: Lightweight Element**

- even performing deep-copying is fine. 

---
***
---

## Move semantics

Move semantics allow you to "steal" the resources of a temporary object instead of making an expensive copy. In the Taihang code you provided, ECPoint implements move semantics, while ECGroup (being the heavy context) disables them along with copying.

Here is how move semantics work using the ECPoint logic.

1. The Move Constructor (ECPoint)
In your ec_group.hpp, you have this line:
ECPoint(ECPoint&& other) noexcept;

The && (rvalue reference) tells the compiler: "I am a temporary object that is about to die. You can take my internal pointers."

Instead of allocating a new EC_POINT and copying the coordinates (Deep Copy), the move constructor simply performs a pointer swap:

```
C++
// Conceptual implementation of the Move Constructor
ECPoint::ECPoint(ECPoint&& other) noexcept 
    : group(other.group), pt_ptr(other.pt_ptr) {
    
    other.pt_ptr = nullptr; // The "Old" point is now empty/hollowed out
}
```

2. Why this matters for Performance
Imagine you have a function that returns a point:
ECPoint calculate_sum() { ... return result; }

Without Move Semantics: The program creates result, copies it into a temporary return value (expensive), then deletes result.

With Move Semantics: The program just hands the pt_ptr from the internal result to the caller. Zero memory allocation occurs.


### why ECPoint uses const*, while ElGamal.PP uses std::shared_ptr 


It is about the distinction between Ownership (Public Parameters) vs. Observation (ECPoint).

Part 1: Why shared_ptr wins for PP, but const* is correct for ECPoint
* You are correct that ECPoint holds a raw pointer. This is good design.
* However, PublicParameters should hold a shared_ptr. This is also good design.


Here is the architectural rule:
* PublicParameters is the ANCHOR (Owner): It is responsible for keeping the heavy ECGroup alive in memory.
* ECPoint is the KITE (Observer): It is a lightweight object that assumes the Anchor exists.

Why Raw Pointer fails for Public Parameters?
* If you define struct PublicParameters { const ECGroup* group; }, you create an "Ownership Vacuum."


**Scenario: The User's Code**
```
code
C++
// 1. Setup returns a PP.
// If setup used 'new ECGroup', who calls delete?
PublicParameters pp = setup(); 

// 2. We use the PP to create a point.
// point.group points to pp.group.
ECPoint msg = encrypt(pp, ...); 

// 3. We are done with PP, but we want to keep the ciphertext 'msg'.
// In a complex app, 'pp' might go out of scope here.
```
* If pp held a shared_ptr: When pp dies, the shared_ptr checks: "Is anyone else holding this?" If msg is still alive (and you implemented msg to hold a reference) or if another copy of pp exists, the Group stays alive.
* If pp held a raw pointer: When pp dies, it does nothing.
- If you didn't delete the group manually: Memory Leak.
- If you did delete it manually but msg is still alive: Dangling Pointer (Segfault) when you try to use msg.

**Verdict:**
- Use std::shared_ptr in Containers/Managers (like PublicParameters, KeyPairs) to ensure the heavy resource stays alive as long as needed.
- Use const ECGroup* in Math Objects (like ECPoint, ZnElement) to keep them tiny (8 bytes vs 24 bytes) and fast.



## std container: push_back vs. emplace_back

* push_back(): takes an existing object, copies or moves it into the vector

* emplace_back(): constructs the object directly inside the vector using forwards constructor arguments



## RAII stands for Resource Acquisition Is Initialization.

Why RAII Is So Important

RAII gives you:

✔ Automatic cleanup
✔ Exception safety
✔ No resource leaks
✔ Deterministic destruction (unlike GC languages)
✔ Clear ownership semantics

C++ smart pointers are RAII wrappers:

std::unique_ptr
std::shared_ptr

## stack vs. heap

The stack is a region of memory used for:

* Local variables
* Function parameters
* Return addresses
* Temporary objects

It is:

* Automatically managed
* Very fast
* LIFO (last in, first out)
* Limited in size

The heap is a large pool of memory used for dynamic allocation.

You explicitly request memory from it:

The memory:

* Stays alive until you manually free it
* Is slower to allocate than stack
* Can fragment
* Is much larger than the stack

In modern C++:

✔ Prefer stack allocation when possible
✔ Avoid raw new and delete
✔ Use smart pointers for heap
✔ Let RAII manage everything


### Modern C++ 的“成员初始化列表”（member initializer list）
* 它写在构造函数的函数体之前，用来初始化成员变量
* const成员只能用初始化列表初始化



Ah, the classic text-stream extraction hazard. Using std::ostream and std::istream with raw type chaining (<< and >>) works smoothly for primitive calculations, but it introduces a major pitfall when serialization switches from numbers to booleans without explicit delimiters.

The Bug: Token Smushing
When pp.malicious (a bool) is serialized using os << pp.malicious, it outputs as either 0 or 1 in text format. Immediately following it, you write pp.base_len (an integer, say 128).

If pp.malicious = false and pp.base_len = 128, your stream receives:

Plaintext
[base_ot_pp_data]0128
When is >> parses this back:

It reads the base parameters.

It encounters the string 0128.

Because pp.malicious is a boolean extraction target, is >> pp.malicious only consumes the first valid boolean digit (0). It sets pp.malicious = false.

The remaining digits (128) are left in the stream buffer to be extracted into pp.base_len.

However, if pp.malicious = true, the stream receives:

Plaintext
[base_ot_pp_data]1128
When reading it back, is >> pp.malicious reads the 1, sets pp.malicious = true. The stream left over is 128, which populates pp.base_len. This direction matches up purely by luck.

The true failure happens depending on how pp.base_ot_pp serializes. If pp.base_ot_pp ends in a numeric digit, that digit gets concatenated with your boolean variable. For example, if base_ot_pp ends with a 5, the stream sees 50128. is >> pp.base_ot_pp may swallow parts of the boolean or the next numbers, completely corrupting the stream alignment and shifting garbage data into pp.malicious (turning any non-zero leftover value into true).

The Fix: Add Space Delimiters
The simplest, standard C++ text-stream way to fix this is to inject space delimiters between fields so that the extraction operators (>>) know exactly where tokens start and stop.

Update your operators like this:

C++
std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.base_ot_pp << " " 
       << pp.malicious << " " 
       << pp.base_len;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    is >> pp.base_ot_pp >> pp.malicious >> pp.base_len;
    return is;
}
Because std::istream::operator>> automatically skips whitespace before parsing tokens, adding spaces keeps your serialization token-isolated and completely safe from layout variations or adjacent number smushing. Recompile, rerun test_alsz_ote, and your round-trips should pass beautifully!


## 尽量使用std::array代替C数组和std::vector

