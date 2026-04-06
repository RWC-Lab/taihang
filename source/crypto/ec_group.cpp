/****************************************************************************
 * @file      ec_group.cpp
 * @brief     Implementation of ECGroup and ECPoint for Taihang.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <omp.h>
#include <taihang/crypto/ec_group.hpp>
#include <cstring>
#include <xxhash.h>
#include <taihang/crypto/bn_ctx.hpp>

namespace taihang {

// --- ECGroup Implementation ---

const ECGroup& ECGroup::get_default_group() {
    // NID_X9_62_prime256v1 is the standard name for the secp256r1 curve: 415
    static ECGroup default_instance(NID_X9_62_prime256v1, true); 
    return default_instance;
}

ECGroup::ECGroup(int input_curve_id, bool precompute_flag) : group_ptr(nullptr) {
    BN_CTX* bn_ctx = BnContext::get();
    
    curve_id = input_curve_id; 

    group_ptr = EC_GROUP_new_by_curve_name(curve_id);
    TAIHANG_ASSERT(group_ptr != nullptr, "ECGroup: Failed to initialize OpenSSL EC_GROUP.");

    // Load parameters
    generator = EC_GROUP_get0_generator(group_ptr);
    TAIHANG_CHECK(1 == EC_GROUP_get_order(group_ptr, order.bn_ptr, bn_ctx), "ECGroup: Failed to get order.");
    TAIHANG_CHECK(1 == EC_GROUP_get_cofactor(group_ptr, cofactor.bn_ptr, bn_ctx), "ECGroup: Failed to get cofactor.");
    TAIHANG_CHECK(1 == EC_GROUP_get_curve_GFp(group_ptr, p.bn_ptr, a.bn_ptr, b.bn_ptr, bn_ctx), "ECGroup: Failed to get curve params.");

    base_field_byte_len = BN_num_bytes(p.bn_ptr);
    point_byte_len = 1 + 2 * base_field_byte_len;     // Uncompressed: 1 byte header + X + Y (2 * field_len)
    point_byte_compressed_len = 1 + base_field_byte_len;   // Compressed:   1 byte header + X (1 * field_len)

    if (precompute_flag) {
        precompute();
    }
}

ECGroup::~ECGroup() {
    if (group_ptr != nullptr) EC_GROUP_free(group_ptr);
}

void ECGroup::precompute() const {
    EC_GROUP_precompute_mult(const_cast<EC_GROUP*>(group_ptr), BnContext::get());
}

bool ECGroup::is_precomputed() const {
    return EC_GROUP_have_precompute_mult(group_ptr) == 1;
}

ECPoint ECGroup::get_infinity() const {
    ECPoint result(this);
    result.set_infinity();
    return result;
}

ECPoint ECGroup::get_generator() const {
    ECPoint result(this);
    const EC_POINT* g = EC_GROUP_get0_generator(group_ptr);
    TAIHANG_CHECK(1 == EC_POINT_copy(result.pt_ptr, g), "Failed to copy generator");
    return result;
}

ECPoint ECGroup::gen_random() const {
    ECPoint result(this);
    BigInt k = gen_random_bigint_less_than(order);
    
    // We want P = k*G. So we pass k as 'n', and nullptr for q, m.
    TAIHANG_CHECK(1 == EC_POINT_mul(group_ptr, result.pt_ptr, k.bn_ptr, nullptr, nullptr, BnContext::get()), "Gen Random EC Point failed");
    return result;
}

std::vector<ECPoint> ECGroup::gen_random(size_t n) const {
    // 1. Pre-allocate and Initialize
    // We construct the vector with 'n' points bound to *this* group context.
    // We use 'ECPoint(this)' as the prototype. This ensures all points in the 
    // vector are initialized with the correct group pointer (not necessarily the default one).
    std::vector<ECPoint> result_vector(n, ECPoint(this));

    // 2. Parallel Generation
    // We use a parallel for-loop to overwrite the initial "Infinity" points 
    // with actual random points. Since gen_random() involves heavy scalar 
    // multiplication, this scales linearly with core count.
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < n; ++i) {
        result_vector[i] = gen_random();
    }

    return result_vector;
}

// --- ECPoint Implementation ---

ECPoint::ECPoint(const ECGroup* input_group_ctx) : group_ctx(input_group_ctx) {
    TAIHANG_ASSERT(group_ctx != nullptr, "ECPoint: Context missing.");
    pt_ptr = EC_POINT_new(group_ctx->group_ptr);
    set_infinity();
}

ECPoint::ECPoint(const ECPoint& other) : group_ctx(other.group_ctx) {
    pt_ptr = EC_POINT_new(group_ctx->group_ptr);
    EC_POINT_copy(pt_ptr, other.pt_ptr);
}

ECPoint::ECPoint(ECPoint&& other) noexcept : group_ctx(other.group_ctx), pt_ptr(other.pt_ptr) {
    other.pt_ptr = nullptr;
}

ECPoint::~ECPoint() {
    if (pt_ptr) EC_POINT_free(pt_ptr);
}

ECPoint& ECPoint::operator=(const ECPoint& other) {
    if (this != &other) {
        // If the groups are different, we must re-allocate the internal OpenSSL point
        if (this->group_ctx != other.group_ctx) {
            if (this->pt_ptr != nullptr) {
                EC_POINT_free(this->pt_ptr);
            }
            this->group_ctx = other.group_ctx;
            this->pt_ptr = EC_POINT_new(this->group_ctx->group_ptr);
        }
        
        // Now that the context is guaranteed to match, copy the coordinates
        TAIHANG_CHECK(1 == EC_POINT_copy(this->pt_ptr, other.pt_ptr), 
                      "ECPoint: Failed to copy coordinates during assignment.");
    }
    return *this;
}

ECPoint& ECPoint::operator=(ECPoint&& other) noexcept {
    if (this != &other) {
        if (pt_ptr != nullptr) EC_POINT_free(pt_ptr);
        group_ctx = other.group_ctx; pt_ptr = other.pt_ptr;
        other.pt_ptr = nullptr;
    }
    return *this;
}

ECPoint ECPoint::add(const ECPoint& other) const {
    ECPoint result(group_ctx);
    int ret = EC_POINT_add(group_ctx->group_ptr, result.pt_ptr, pt_ptr, other.pt_ptr, BnContext::get());
    TAIHANG_CHECK(ret == 1, "ECPoint::add failed.");
    return result;
}

void ECPoint::add_inplace(const ECPoint& other) {
    // Result is written directly into this->pt_ptr.
    // No temporary point is allocated — this is the key difference from operator+.
    int ret = EC_POINT_add(
        group_ctx->group_ptr,
        this->pt_ptr,       // output: overwrite this
        this->pt_ptr,       // input A: this
        other.pt_ptr,       // input B: other
        BnContext::get()
    );
    TAIHANG_ASSERT(ret == 1, "ECPoint::add_inplace failed.");
}

ECPoint ECPoint::sub(const ECPoint& other) const {
    return this->add(other.neg());
}

// To overload operator *, the following algorithm is a bit slow cause extra check
ECPoint ECPoint::mul(const BigInt& scalar) const {
    ECPoint result(group_ctx);
    BN_CTX* bn_ctx = BnContext::get();
    int ret; 
    if (EC_POINT_cmp(group_ctx->group_ptr, pt_ptr, group_ctx->generator, bn_ctx) == 0) {
        ret = EC_POINT_mul(group_ctx->group_ptr, result.pt_ptr, scalar.bn_ptr, nullptr, nullptr, bn_ctx);
        TAIHANG_CHECK(ret == 1, "Generator multiplication failed");
    } else {
        ret = EC_POINT_mul(group_ctx->group_ptr, result.pt_ptr, nullptr, pt_ptr, scalar.bn_ptr, bn_ctx);
        TAIHANG_CHECK(ret == 1, "Multiplication failed");
    }
    return result;
}

ECPoint ECPoint::mul_generator(const BigInt& scalar) const {
    ECPoint result(group_ctx);
    // Passing scalar as the 3rd argument (g_scalar) triggers OpenSSL's 
    // precomputed table optimization for the generator.
    BN_CTX* bn_ctx = BnContext::get();
    int ret = EC_POINT_mul(group_ctx->group_ptr, result.pt_ptr, scalar.bn_ptr, nullptr, nullptr, bn_ctx); 
    TAIHANG_CHECK(ret == 1, "Generator multiplication failed");
    return result;
}


ECPoint ECPoint::mul(const ZnElement& scalar) const {
    // SAFETY CHECK:
    // Ensure the scalar comes from the correct field (Zn where n = group.order)
    TAIHANG_ASSERT(scalar.field_ctx->modulus == group_ctx->order, 
                   "ECPoint::mul type mismatch: Scalar field modulus != Group order");
    // Delegate to the generic implementation using the underlying BigInt
    return this->mul(scalar.value);
}

ECPoint ECPoint::mul_generator(const ZnElement& scalar) const {
    // SAFETY CHECK:
    // Ensure the scalar comes from the correct field (Zn where n = group.order)
    TAIHANG_ASSERT(scalar.field_ctx->modulus == group_ctx->order, 
                   "ECPoint::mul type mismatch: Scalar field modulus != Group order");
    // Delegate to the generic implementation using the underlying BigInt
    return this->mul_generator(scalar.value);
}

ECPoint ECPoint::neg() const {
    ECPoint result(*this);
    EC_POINT_invert(group_ctx->group_ptr, result.pt_ptr, BnContext::get());
    return result;
}

ECPoint ECPoint::dbl() const {
    ECPoint result(group_ctx);
    EC_POINT_dbl(group_ctx->group_ptr, result.pt_ptr, pt_ptr, BnContext::get());
    return result;
}

void ECPoint::set_infinity() { 
    EC_POINT_set_to_infinity(group_ctx->group_ptr, pt_ptr); 
}

bool ECPoint::is_at_infinity() const { 
    return EC_POINT_is_at_infinity(group_ctx->group_ptr, pt_ptr); 
}

bool ECPoint::is_on_curve() const { 
    return EC_POINT_is_on_curve(group_ctx->group_ptr, pt_ptr, BnContext::get()); 
}

bool ECPoint::compare_to(const ECPoint& other) const {
    return 0 == EC_POINT_cmp(group_ctx->group_ptr, pt_ptr, other.pt_ptr, BnContext::get());
}

// --- hash ---
uint64_t ECPoint::aeshash_to_uint64() const {
    if (EC_POINT_is_at_infinity(group_ctx->group_ptr, pt_ptr)) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    // 1. Stack Allocation with Alignment
    // P-256 Compressed is 33 bytes. P-521 is 67 bytes.
    // We allocate 80 bytes to be safe and ensure 16-byte alignment for SIMD.
    // '{0}' zero-initializes the buffer, handling the padding for the tail block automatically.
    alignas(16) uint8_t buffer[80] = {0};

    // 2. Serialize (Force Compressed for uniqueness)
    size_t len = group_ctx->point_byte_compressed_len;
    
    // Sanity check to prevent buffer overflow if a huge custom curve is added
    if (len > sizeof(buffer)) return 0; 

    if (EC_POINT_point2oct(group_ctx->group_ptr, pt_ptr, POINT_CONVERSION_COMPRESSED, 
                           buffer, len, BnContext::get()) == 0) {
        return 0;
    }

    // 3. Setup AES-NI Constants
    // Use static const to hint compiler to keep these in registers/rodata
    static const __m128i round_key = _mm_set_epi64x(0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF);
    // Initial state needs to be reset per call, but the constant values are static
    __m128i hash_state = _mm_set_epi64x(0x3692815C10459385, 0x5138501284712094); // Random IV

    // 4. Calculate Block Count
    // (len + 15) / 16  calculates ceil(len / 16) using integer math
    size_t num_blocks = (len + 15) / 16;
    
    // Cast buffer to SIMD pointer
    const __m128i* data_blocks = reinterpret_cast<const __m128i*>(buffer);

    // 5. The Loop (Correct for P-256, P-384, P-521)
    for (size_t i = 0; i < num_blocks; ++i) {
        // Load data (Aligned load is safe here due to alignas(16))
        __m128i data = _mm_load_si128(&data_blocks[i]);
        
        // Mix: XOR input -> AES Encrypt round
        hash_state = _mm_xor_si128(hash_state, data);
        hash_state = _mm_aesenc_si128(hash_state, round_key);
    }

    // 6. Finalize (One extra round for avalanche effect)
    hash_state = _mm_aesenc_si128(hash_state, round_key);

    // 7. Return lower 64 bits
    return static_cast<uint64_t>(_mm_cvtsi128_si64(hash_state));
}

uint64_t ECPoint::xxhash_to_uint64() const {
    // Point at infinity has no affine coordinates — return a fixed sentinel
    if (EC_POINT_is_at_infinity(group_ctx->group_ptr, pt_ptr)) {
        return 0xFFFFFFFFFFFFFFFFULL; // Distinct sentinel value
    }

    // Thread-local cache: Allocated once per thread, reused millions of times
    thread_local BIGNUM* x = BN_new();
    thread_local BIGNUM* y = BN_new();
    thread_local BN_CTX* ctx = BN_CTX_new();

    int ret = EC_POINT_get_affine_coordinates(group_ctx->group_ptr, pt_ptr, x, y, ctx);
    TAIHANG_ASSERT(ret == 1, "xxhash_to_uint64: Failed to get affine coordinates.");

    // Use Fixed-Length Padding
    // P-256 is 32 bytes, P-521 is 66 bytes. 
    // group_ctx->point_byte_len should be pre-calculated (field size in bytes).
    size_t field_len = group_ctx->point_byte_len; 
    alignas(16) uint8_t buffer[80]; 
    
    // BN_bn2binpad is faster than BN_bn2bin because it avoids conditional length logic
    BN_bn2binpad(x, buffer, field_len);

    // Hash the fixed-length buffer
    uint64_t hash = XXH3_64bits(buffer, field_len);

    // Symmetric bit-flip to handle P vs -P
    if (BN_is_odd(y)) {
        hash = ~hash;
    }

    return hash;
}

// --- Serialization ---

void ECPoint::to_bytes(uint8_t* buffer) const {
    // 1. Determine Fixed Length based on config
    size_t fixed_len = config::use_point_compression ? 
                       group_ctx->point_byte_compressed_len : 
                       group_ctx->point_byte_len;

    // 2. Handle Infinity (Special Fixed-Length Case)
    if (this->is_at_infinity()) {
        // OpenSSL's default behavior writes only 1 byte (0x00).
        // To enforce fixed length, we manually fill the entire buffer with zeros.
        // Format: [0x00, 0x00, ..., 0x00]
        std::memset(buffer, 0, fixed_len);
        return;
    }

    // 3. Handle Normal Point
    point_conversion_form_t form = config::use_point_compression ? 
                                   POINT_CONVERSION_COMPRESSED : 
                                   POINT_CONVERSION_UNCOMPRESSED;

    // We pass 'fixed_len' as the buffer length. OpenSSL will fill it.
    size_t actural_len = EC_POINT_point2oct(group_ctx->group_ptr, pt_ptr, form, 
                                        buffer, fixed_len, BnContext::get());

    // Sanity check: ensure OpenSSL wrote the expected number of bytes
    TAIHANG_CHECK(actural_len == fixed_len, "ECPoint serialization size mismatch.");
}

std::vector<uint8_t> ECPoint::to_bytes() const {
    size_t fixed_len = config::use_point_compression ? 
                 group_ctx->point_byte_compressed_len : 
                 group_ctx->point_byte_len;
    
    // std::vector constructor zero-initializes memory.
    // This is efficient and safe.
    std::vector<uint8_t> result(fixed_len);
    to_bytes(result.data());
    return result;
}

// --- Deserialization ---

void ECPoint::from_bytes(const uint8_t* buffer) {
    size_t fixed_len = config::use_point_compression ? 
                        group_ctx->point_byte_compressed_len : 
                        group_ctx->point_byte_len;

    // Optimization: Check for Infinity (All Zeros)
    // Checking just the first byte is sufficient because valid points
    // start with 0x02, 0x03 (Compressed) or 0x04 (Uncompressed).
    // 0x00 is reserved for Infinity.
    if (buffer[0] == 0x00) {
        this->set_infinity();
        return;
    }

    // Standard OpenSSL loading
    int ret = EC_POINT_oct2point(group_ctx->group_ptr, pt_ptr, buffer, fixed_len, BnContext::get());
    TAIHANG_CHECK(ret == 1, "ECPoint de-serialization failed (Invalid encoding).");
}

void ECPoint::from_bytes(const std::vector<uint8_t> input) {
    from_bytes(input.data()); 
}

// --- Stream Operators (Optimized) ---

std::ostream& operator<<(std::ostream& os, const ECPoint& point) {
    size_t fixed_len = config::use_point_compression ? 
                        point.group_ctx->point_byte_compressed_len : 
                        point.group_ctx->point_byte_len;

    // Use a fixed-size stack buffer to avoid heap allocation.
    // 256 bytes is enough for P-521 uncompressed (approx 133 bytes).
    // We avoid VLAs (uint8_t buffer[len]) for standard compliance.
    uint8_t buffer[256];
    
    // Safety check in debug mode
    TAIHANG_ASSERT(fixed_len <= sizeof(buffer), "Curve point size exceeds stack buffer limit.");

    point.to_bytes(buffer);
    os.write(reinterpret_cast<char*>(buffer), fixed_len);
    return os;
}

std::istream& operator>>(std::istream& is, ECPoint& point) {
    size_t fixed_len = config::use_point_compression ? 
                        point.group_ctx->point_byte_compressed_len : 
                        point.group_ctx->point_byte_len;

    uint8_t buffer[256];
    TAIHANG_ASSERT(fixed_len <= sizeof(buffer), "Curve point size exceeds stack buffer limit.");

    // Attempt to read exactly 'fixed_len' bytes
    if (is.read(reinterpret_cast<char*>(buffer), fixed_len)) {
        point.from_bytes(buffer);
    } else {
        // If read fails (eof or error), set failbit
        is.setstate(std::ios::failbit);
    }
    return is;
}

/**
 * @brief Converts the EC point to a hex string representation.
 * @return std::string containing the hex representation.
 */
std::string ECPoint::to_hex() const {
    point_conversion_form_t form = config::use_point_compression ? 
                                   POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;

    // We use the global BnContext for temporary calculations to avoid re-allocation
    char* hex_ptr = EC_POINT_point2hex(group_ctx->group_ptr, pt_ptr, form, BnContext::get());
    
    // Safety check: point2hex can return nullptr if the point is invalid or memory fails
    TAIHANG_ASSERT(hex_ptr != nullptr, "Failed to convert ECPoint to hex string");

    std::string result(hex_ptr);
    
    // Always free OpenSSL allocated memory immediately
    OPENSSL_free(hex_ptr);

    return result;
}

// --- debugging ---


void ECPoint::print(std::string_view label, std::ostream& os) const {
    os << label << (label.empty() ? "" : ": ") << to_hex() << std::endl;
}

// --- Vectorized & Parallel Implementation ---

ECPoint ec_point_msm(const std::vector<ECPoint>& vec_A, const std::vector<BigInt>& vec_a) {
    TAIHANG_ASSERT(vec_A.size() == vec_a.size(), "MSM: Size mismatch.");
    TAIHANG_ASSERT(vec_A.empty() == 0, "MSM: Size is zero.");

    size_t n = vec_A.size(); 
    return ec_point_msm(vec_A, vec_a, 0, n);
}

ECPoint ec_point_msm(const std::vector<ECPoint>& vec_A, const std::vector<BigInt>& vec_a, size_t start_index, size_t end_index) {
    TAIHANG_ASSERT(end_index <= vec_A.size() && start_index < end_index, "MSM: Invalid range.");
    
    size_t n = end_index - start_index;
    const ECGroup* group_ctx = vec_A[0].group_ctx;
    ECPoint result(group_ctx);

    std::vector<const EC_POINT*> points_raw(n);
    std::vector<const BIGNUM*> bignums_raw(n);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < n; ++i) {
        points_raw[i] = vec_A[start_index + i].pt_ptr;
        bignums_raw[i] = vec_a[start_index + i].bn_ptr;
    }

    TAIHANG_CHECK(1 == EC_POINTs_mul(group_ctx->group_ptr, result.pt_ptr, nullptr, n, 
                                     points_raw.data(), bignums_raw.data(), BnContext::get()), "Range MSM Failed.");
    return result;
}

ECPoint ec_point_msm(const std::vector<ECPoint>& vec_A, const std::vector<ZnElement>& vec_a) {
    size_t n = vec_A.size();
    TAIHANG_ASSERT(n == vec_a.size(), "MSM: Size mismatch.");
    if (n == 0) return ECGroup::get_default_group().get_infinity(); // Or handle empty

    const ECGroup* group_ctx = vec_A[0].group_ctx;
    ECPoint result(group_ctx);
    // Prepare raw pointers directly
    std::vector<const EC_POINT*> points_raw(n);
    std::vector<const BIGNUM*> bignums_raw(n);

    // This loop is extremely fast (pointer assignment)
    // No BigInt allocations happening here!
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < n; ++i) {
        points_raw[i] = vec_A[i].pt_ptr;
        bignums_raw[i] = vec_a[i].value.bn_ptr; // Direct access to BIGNUM*
    }
    int ret = EC_POINTs_mul(group_ctx->group_ptr, result.pt_ptr, nullptr, n, points_raw.data(), bignums_raw.data(), BnContext::get());
    TAIHANG_CHECK(ret == 1, "MSM Failed.");
    return result;
}

ECPoint ec_point_msm(const std::vector<ECPoint>& vec_A, const std::vector<ZnElement>& vec_a, size_t start_index, size_t end_index) {
    size_t n = end_index - start_index;

    const ECGroup* group_ctx = vec_A[0].group_ctx;
    ECPoint result(group_ctx);

    // Prepare raw pointers directly
    std::vector<const EC_POINT*> points_raw(n);
    std::vector<const BIGNUM*> bignums_raw(n);

    // Note: BN_copy is thread-safe as long as destination pointers are distinct
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < n; ++i) {
        points_raw[i] = vec_A[i + start_index].pt_ptr;
        bignums_raw[i] = vec_a[i + start_index].value.bn_ptr;
    }

    int ret = EC_POINTs_mul(group_ctx->group_ptr, result.pt_ptr, nullptr, n, points_raw.data(), bignums_raw.data(), BnContext::get());
    TAIHANG_CHECK(ret == 1, "MSM Failed.");
    return result;
}

std::vector<ECPoint> ec_point_vector_add(const std::vector<ECPoint>& vec_A, const std::vector<ECPoint>& vec_B) {
    TAIHANG_ASSERT(vec_A.size() == vec_B.size(), "Vector Add: Size mismatch.");
    size_t len = vec_A.size();
    std::vector<ECPoint> result_vector;
    result_vector.reserve(len);
    const ECGroup* group = vec_A[0].group_ctx;
    for(size_t i = 0; i < len; ++i) result_vector.emplace_back(group);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        result_vector[i] = vec_A[i].add(vec_B[i]);
    }
    return result_vector;
}

std::vector<ECPoint> ec_point_vector_mul(const std::vector<ECPoint>& vec_A, const BigInt& a) {
    size_t len = vec_A.size();
    std::vector<ECPoint> result_vector;
    result_vector.reserve(len);
    const ECGroup* group = vec_A[0].group_ctx;
    for(size_t i = 0; i < len; ++i) result_vector.emplace_back(group);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; i++) {
        result_vector[i] = vec_A[i].mul(a);
    }
    return result_vector;
}

std::vector<ECPoint> ec_point_vector_mul(const std::vector<ECPoint>& vec_A, const ZnElement& a) {
    return ec_point_vector_mul(vec_A, a.value);
}

std::vector<ECPoint> ec_point_vector_mul(const std::vector<ECPoint>& vec_A, const std::vector<BigInt>& vec_a) {
    TAIHANG_ASSERT(vec_A.size() == vec_a.size(), "Vector Product: Size mismatch.");
    size_t len = vec_A.size();
    std::vector<ECPoint> result_vector;
    result_vector.reserve(len);
    const ECGroup* group = vec_A[0].group_ctx;
    for(size_t i = 0; i < len; ++i) result_vector.emplace_back(group);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; i++) {
        result_vector[i] = vec_A[i].mul(vec_a[i]);
    }
    return result_vector;
}

std::vector<ECPoint> ec_point_vector_mul(const std::vector<ECPoint>& vec_A, const std::vector<ZnElement>& vec_a) {
    size_t n = vec_a.size();
    // 1. Construct 'n' empty BigInts first (fast allocation)
    std::vector<BigInt> vec_scalar(n); 

    // 2. Parallel deep copy
    // Note: BN_copy is thread-safe as long as destination pointers are distinct
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < n; ++i) {
        vec_scalar[i] = vec_a[i].value;
    }
    
    return ec_point_vector_mul(vec_A, vec_scalar);
}

/**
 * @brief Core "Try-and-Increment" loop using AES for speed.
 * @param entropy 256 bits of entropy (two blocks).
 */

static ECPoint hash_to_curve_fast_internal(Block input[2], const ECGroup& group) {
    ECPoint result(&group);
    BN_CTX* ctx = BnContext::get();
    BigInt x_candidate;
    
    // We use a counter to ensure we don't loop forever (though probability is negligible)
    uint64_t counter = 0; 

    while (true) {
        // 1. Get X candidate from current entropy
        BN_bin2bn(reinterpret_cast<const uint8_t*>(input), 32, x_candidate.bn_ptr);
        
        // 2. Determine Y-bit (LSB of first byte of entropy)
        // Accessing input[0] safely via reinterpret_cast
        uint8_t* bytes = reinterpret_cast<uint8_t*>(input);
        int y_bit = bytes[0] & 1;

        // 3. Attempt to set coordinates (Decompress)
        // This effectively checks if x^3 + ax + b is a quadratic residue
        if (EC_POINT_set_compressed_coordinates_GFp(group.group_ptr, result.pt_ptr, x_candidate.bn_ptr, y_bit, ctx) == 1) {
            // Check if point is on curve (redundant usually, but good for safety)
            if (EC_POINT_is_on_curve(group.group_ptr, result.pt_ptr, ctx) == 1) {
                // Ensure not at infinity and order check if necessary
                break;
            }
        }

        // 4. Permute entropy for next attempt
        aes::encrypt_two_blocks(aes::get_fixed_key(), input);
        counter++;
        if(counter > 1000) {
            // Sanity break: highly unlikely to happen on standard curves
             throw std::runtime_error("HashToCurveFast: failed to find point after 1000 attempts");
        }
    }
    return result;
}

// --- 1. Fast Path Implementations ---

ECPoint hash_to_curve_fast(const uint8_t* input_bytes, size_t len, const ECGroup& group) {
    alignas(16) uint8_t hash_out[32];
    cryptohash::digest<kDefaultHash>(input_bytes, len, hash_out); // Initial ingest

    Block input[2];
    input[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(hash_out));
    input[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(hash_out + 16));
    
    return hash_to_curve_fast_internal(input, group);
}

ECPoint hash_to_curve_fast(const std::string& input_str, const ECGroup& group) {
    return hash_to_curve_fast(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size(), group);
}

ECPoint hash_to_curve_fast(const Block& input_block, const ECGroup& group) {
    // Implements H(x) = AES_k(x ^ 1) || AES_k(x ^ 2).
    // Domain Separation: create two distinct inputs from one seed
    Block input[2]; 
    input[0] = _mm_xor_si128(input_block, _mm_set_epi64x(0, 1));
    input[1] = _mm_xor_si128(input_block, _mm_set_epi64x(0, 2));

    aes::encrypt_two_blocks(aes::get_fixed_key(), input); // Expand 128 to 256 bits
    return hash_to_curve_fast_internal(input, group);
}

// --- 2. Standard Path Implementations ---

ECPoint hash_to_curve_standard(const uint8_t* input_bytes, size_t len, const std::string& dst, const ECGroup& group) {
    // RFC 9380 involves: 1. expand_message_xmd, 2. SSWU map, 3. Addition
    // We utilize 48 bytes (L) for P-256 to ensure negligible bias.
    size_t L = 48; 
    std::vector<uint8_t> pseudo_random_bytes(2 * L); 
    
    // expand_message_xmd(data, dst, 2*L) implementation logic here...
    // (Calls internal SHA256-based block expansion)

    BigInt u0, u1;
    BN_bin2bn(pseudo_random_bytes.data(), L, u0.bn_ptr);
    BN_bin2bn(pseudo_random_bytes.data() + L, L, u1.bn_ptr);

    // Map to curve using SSWU (Shallue-van de Woestijne-Ulas)
    // Q0 = map_to_curve_sswu(u0 mod p); Q1 = map_to_curve_sswu(u1 mod p);
    // return Q0 + Q1;
    
    // For this context, we return an identity point if SSWU logic is not yet linked
    TAIHANG_ASSERT(false, "Standard Path: SSWU Math mapping implementation required.");
    return ECPoint(&group);
}

ECPoint hash_to_curve_standard(const std::string& input_str, const std::string& dst, const ECGroup& group) {
    return hash_to_curve_standard(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size(), dst, group);
}

ECPoint hash_to_curve_standard(const Block& input_block, const std::string& dst, const ECGroup& group) {
    return hash_to_curve_standard(reinterpret_cast<const uint8_t*>(&input_block), 16, dst, group);
}

} // namespace taihang




