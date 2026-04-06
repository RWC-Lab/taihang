/****************************************************************************
 * @file      zn.cpp
 * @brief     Implementation of Zn and ZnElement.
 *****************************************************************************/

#include <taihang/crypto/zn.hpp>
#include <openssl/bn.h>

namespace taihang {

// --- Zn (Context) Implementation ---

Zn::Zn(const BigInt& mod) : modulus(mod) {
    TAIHANG_ASSERT(!modulus.is_zero(), "Zn: Modulus cannot be zero.");
    element_byte_len = modulus.to_bytes().size();
}

ZnElement Zn::get_zero() const {
    return ZnElement(this, BigInt(0ULL));
}

ZnElement Zn::get_one() const {
    return ZnElement(this, BigInt(1ULL));
}

ZnElement Zn::gen_random() const {
    return ZnElement(this, gen_random_bigint_less_than(modulus));
}

// --- ZnElement (Instance) Implementation ---

ZnElement::ZnElement() : value(BigInt(0ULL)), field_ctx(nullptr) {}

ZnElement::ZnElement(const Zn* input_field_ctx, const BigInt& val) 
    :  value(val), field_ctx(input_field_ctx) {
    if(field_ctx){
        value = value.mod(field_ctx->modulus); 
    }
}

ZnElement::ZnElement(const Zn& field_ref, const BigInt& val) 
    : ZnElement(&field_ref, val) {}

ZnElement::ZnElement(std::shared_ptr<Zn> field, const BigInt& val) 
    : ZnElement(field.get(), val) {}

ZnElement::ZnElement(const ZnElement& other) 
    : value(other.value), field_ctx(other.field_ctx) {}

ZnElement::ZnElement(ZnElement&& other) noexcept 
    : value(std::move(other.value)), field_ctx(other.field_ctx) {
    other.field_ctx = nullptr;
}

ZnElement& ZnElement::operator=(const ZnElement& other) {
    if (this != &other) {
        field_ctx = other.field_ctx;
        value = other.value;
    }
    return *this;
}

ZnElement& ZnElement::operator=(ZnElement&& other) noexcept {
    if (this != &other) {
        field_ctx = other.field_ctx;
        value = std::move(other.value);
        other.field_ctx = nullptr;
    }
    return *this;
}

// --- Core Arithmetic ---

ZnElement ZnElement::add(const ZnElement& other) const {
    TAIHANG_ASSERT(field_ctx == other.field_ctx, "ZnElement: Field context mismatch in ADD");
    // Uses BigInt::mod_add
    return ZnElement(field_ctx, value.mod_add(other.value, field_ctx->modulus));
}

ZnElement ZnElement::sub(const ZnElement& other) const {
    TAIHANG_ASSERT(field_ctx == other.field_ctx, "ZnElement: Field context mismatch in SUB");
    // Uses BigInt::mod_sub
    return ZnElement(field_ctx, value.mod_sub(other.value, field_ctx->modulus));
}

ZnElement ZnElement::mul(const ZnElement& other) const {
    TAIHANG_ASSERT(field_ctx == other.field_ctx, "ZnElement: Field context mismatch in MUL");
    // Uses BigInt::mod_mul
    return ZnElement(field_ctx, value.mod_mul(other.value, field_ctx->modulus));
}

ZnElement ZnElement::inv() const {
    // Uses BigInt::mod_inverse
    return ZnElement(field_ctx, value.mod_inverse(field_ctx->modulus));
}

ZnElement ZnElement::neg() const {
    if (value.is_zero()) return *this;
    // -x mod n  =>  n - x
    return ZnElement(field_ctx, field_ctx->modulus.sub(value));
}

ZnElement ZnElement::pow(const BigInt& exp) const {
    // Uses BigInt::mod_exp
    return ZnElement(field_ctx, value.mod_exp(exp, field_ctx->modulus));
}

bool ZnElement::operator==(const ZnElement& other) const {
    if (field_ctx != other.field_ctx) return false;
    return value == other.value;
}

bool ZnElement::operator!=(const ZnElement& other) const {
    return !(*this == other);
}

void ZnElement::print() const {
    value.print(); // Delegates to BigInt print
}

std::vector<uint8_t> ZnElement::to_bytes() const {
    return value.to_bytes();
}

void ZnElement::from_bytes(const uint8_t* buffer, size_t len) {
    TAIHANG_ASSERT(buffer != nullptr, "ZnElement: from_bytes received null.");
    TAIHANG_ASSERT(field_ctx != nullptr, "ZnElement: Cannot deserialize without a valid field context.");

    TAIHANG_ASSERT(len == field_ctx->element_byte_len, "ZnElement: from_bytes length mismatch.");
    if (BN_bin2bn(buffer, static_cast<int>(len), this->value.bn_ptr) == nullptr) {
        TAIHANG_ASSERT(false, "ZnElement: from_bytes failed.");
    }
} 
} // namespace taihang