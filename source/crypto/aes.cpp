/****************************************************************************
 * @file      aes.cpp
 * @brief     Cross-architecture AES implementation (Intel AES-NI & ARM NEON).
 * @details   Supports hardware-accelerated AES-128 and AES-256. 
 * Optimized for high-throughput ECB and CBC modes.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/crypto/aes.hpp>
#include <taihang/common/check.hpp>
#include <cstring>

namespace taihang::aes {

/* --- Internal Helpers for Key Expansion (Architecture Specific) --- */

#if defined(TAIHANG_ARCH_X64)
static inline void assist_128(Block& temp1, Block temp2) {
    temp2 = _mm_shuffle_epi32(temp2.mm, _MM_SHUFFLE(3, 3, 3, 3));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, temp2.mm);
}

static inline void assist_256(Block& temp1, Block temp2) {
    Block temp3 = _mm_shuffle_epi32(temp2.mm, _MM_SHUFFLE(3, 3, 3, 3));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, _mm_slli_si128(temp1.mm, 4));
    temp1.mm = _mm_xor_si128(temp1.mm, temp3.mm);
}
#else
/** * @brief S-Box for ARM/Portable key expansion. 
 */
static const uint8_t kSBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint32_t sub_word(uint32_t w) {
    return (uint32_t)kSBox[w & 0xFF] | ((uint32_t)kSBox[(w >> 8) & 0xFF] << 8) |
           ((uint32_t)kSBox[(w >> 16) & 0xFF] << 16) | ((uint32_t)kSBox[(w >> 24) & 0xFF] << 24);
}

static uint32_t rot_word(uint32_t w) { return (w >> 8) | (w << 24); }
#endif

/* --- Public Key Setup --- */

AESKey set_encrypt_key(const Block* seed, int key_bits) {
    TAIHANG_ASSERT(key_bits == 128 || key_bits == 256, "Taihang only supports 128/256-bit AES.");
    AESKey key;
    key.num_rounds = (key_bits / 32) + 6;

    Block actual_seed[2];
    if (seed == nullptr) {
        actual_seed[0] = actual_seed[1] = kZeroBlock;
    } else {
        actual_seed[0] = seed[0];
        if (key_bits == 256) actual_seed[1] = seed[1];
    }

#if defined(TAIHANG_ARCH_X64)
    Block t1, t2;
    if (key_bits == 128) {
        key.expanded_keys[0] = t1 = actual_seed[0];
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x01)); key.expanded_keys[1] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x02)); key.expanded_keys[2] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x04)); key.expanded_keys[3] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x08)); key.expanded_keys[4] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x10)); key.expanded_keys[5] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x20)); key.expanded_keys[6] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x40)); key.expanded_keys[7] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x80)); key.expanded_keys[8] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x1B)); key.expanded_keys[9] = t1;
        assist_128(t1, _mm_aeskeygenassist_si128(t1.mm, 0x36)); key.expanded_keys[10] = t1;
    } else {
        key.expanded_keys[0] = t1 = actual_seed[0];
        key.expanded_keys[1] = t2 = actual_seed[1];
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x01)); key.expanded_keys[2] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[3] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x02)); key.expanded_keys[4] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[5] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x04)); key.expanded_keys[6] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[7] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x08)); key.expanded_keys[8] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[9] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x10)); key.expanded_keys[10] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[11] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x20)); key.expanded_keys[12] = t1;
        assist_256(t2, _mm_aeskeygenassist_si128(t1.mm, 0x00)); key.expanded_keys[13] = t2;
        assist_256(t1, _mm_aeskeygenassist_si128(t2.mm, 0x40)); key.expanded_keys[14] = t1;
    }
#else
    /* --- ARM/Portable Key Expansion --- */
    uint32_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    uint32_t* w = reinterpret_cast<uint32_t*>(key.expanded_keys);
    int nk = key_bits / 32;
    std::memcpy(w, &actual_seed, key_bits / 8);

    for (int i = nk; i < 4 * (key.num_rounds + 1); ++i) {
        uint32_t temp = w[i - 1];
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i / nk - 1];
        } else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
#endif
    return key;
}

AESKey set_decrypt_key(const Block* seed, int key_bits) {
    AESKey enc_key = set_encrypt_key(seed, key_bits);
    AESKey dec_key;
    dec_key.num_rounds = enc_key.num_rounds;
    dec_key.expanded_keys[0] = enc_key.expanded_keys[dec_key.num_rounds];
    dec_key.expanded_keys[dec_key.num_rounds] = enc_key.expanded_keys[0];

    for (int i = 1; i < dec_key.num_rounds; ++i) {
#if defined(TAIHANG_ARCH_X64)
        dec_key.expanded_keys[i].mm = _mm_aesimc_si128(enc_key.expanded_keys[dec_key.num_rounds - i].mm);
#else
        dec_key.expanded_keys[i].mm = vaesimcq_u8(enc_key.expanded_keys[dec_key.num_rounds - i].mm);
#endif
    }
    return dec_key;
}

const AESKey& get_fixed_key() {
    static const Block kFixedSeed = make_block(0xdeadbeef, 0xbadf00d);
    static const AESKey kFixedKey = set_encrypt_key(&kFixedSeed, 128);
    return kFixedKey;
}

/* --- Basic Block Operations --- */

void encrypt_block(const AESKey& key, Block& data) {
    TAIHANG_ASSERT(key.num_rounds == 10 || key.num_rounds == 14, "Invalid round count.");
#if defined(TAIHANG_ARCH_X64)
    data.mm = _mm_xor_si128(data.mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) 
        data.mm = _mm_aesenc_si128(data.mm, key.expanded_keys[i].mm);
    data.mm = _mm_aesenclast_si128(data.mm, key.expanded_keys[key.num_rounds].mm);
#else
    uint8x16_t zero = vdupq_n_u8(0);
    uint8x16_t state = veorq_u8(data.mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) {
        state = vaesmcq_u8(vaeseq_u8(state, zero));
        state = veorq_u8(state, key.expanded_keys[i].mm);
    }
    data.mm = veorq_u8(vaeseq_u8(state, zero), key.expanded_keys[key.num_rounds].mm);
#endif
}

void decrypt_block(const AESKey& key, Block& data) {
    TAIHANG_ASSERT(key.num_rounds == 10 || key.num_rounds == 14, "Invalid round count.");
#if defined(TAIHANG_ARCH_X64)
    data.mm = _mm_xor_si128(data.mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) 
        data.mm = _mm_aesdec_si128(data.mm, key.expanded_keys[i].mm);
    data.mm = _mm_aesdeclast_si128(data.mm, key.expanded_keys[key.num_rounds].mm);
#else
    uint8x16_t zero = vdupq_n_u8(0);
    uint8x16_t state = veorq_u8(data.mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) {
        state = vaesimcq_u8(vaesdq_u8(state, zero));
        state = veorq_u8(state, key.expanded_keys[i].mm);
    }
    data.mm = veorq_u8(vaesdq_u8(state, zero), key.expanded_keys[key.num_rounds].mm);
#endif
}

/* --- Mode Implementations --- */

void encrypt_ecb(const AESKey& key, const Block* plaintext, Block* ciphertext, size_t num_blocks) {
    if (num_blocks == 0) return;
    TAIHANG_ASSERT(plaintext == ciphertext || (ciphertext + num_blocks <= plaintext || plaintext + num_blocks <= ciphertext), "Overlap.");

    size_t i = 0;
    const int kWidth = 8;
    for (; i + kWidth <= num_blocks; i += kWidth) {
        Block b[kWidth];
        for (int j = 0; j < kWidth; ++j) b[j] = plaintext[i + j] ^ key.expanded_keys[0];
        for (int r = 1; r < key.num_rounds; ++r) {
            Block r_key = key.expanded_keys[r];
            for (int j = 0; j < kWidth; ++j) {
#if defined(TAIHANG_ARCH_X64)
                b[j].mm = _mm_aesenc_si128(b[j].mm, r_key.mm);
#else
                b[j].mm = veorq_u8(vaesmcq_u8(vaeseq_u8(b[j].mm, vdupq_n_u8(0))), r_key.mm);
#endif
            }
        }
        Block f_key = key.expanded_keys[key.num_rounds];
        for (int j = 0; j < kWidth; ++j) {
#if defined(TAIHANG_ARCH_X64)
            ciphertext[i + j].mm = _mm_aesenclast_si128(b[j].mm, f_key.mm);
#else
            ciphertext[i + j].mm = veorq_u8(vaeseq_u8(b[j].mm, vdupq_n_u8(0)), f_key.mm);
#endif
        }
    }
    for (; i < num_blocks; ++i) { 
        ciphertext[i] = plaintext[i]; 
        encrypt_block(key, ciphertext[i]); 
    }
}

void decrypt_ecb(const AESKey& key, const Block* ciphertext, Block* plaintext, size_t num_blocks) {
    if (num_blocks == 0) return;
    TAIHANG_ASSERT(ciphertext == plaintext || (plaintext + num_blocks <= ciphertext || ciphertext + num_blocks <= plaintext), "Overlap.");

    size_t i = 0;
    const int kWidth = 8;
    for (; i + kWidth <= num_blocks; i += kWidth) {
        Block b[kWidth];
        for (int j = 0; j < kWidth; ++j) b[j] = ciphertext[i + j] ^ key.expanded_keys[0];
        for (int r = 1; r < key.num_rounds; ++r) {
            Block r_key = key.expanded_keys[r];
            for (int j = 0; j < kWidth; ++j) {
#if defined(TAIHANG_ARCH_X64)
                b[j].mm = _mm_aesdec_si128(b[j].mm, r_key.mm);
#else
                b[j].mm = veorq_u8(vaesimcq_u8(vaesdq_u8(b[j].mm, vdupq_n_u8(0))), r_key.mm);
#endif
            }
        }
        Block f_key = key.expanded_keys[key.num_rounds];
        for (int j = 0; j < kWidth; ++j) {
#if defined(TAIHANG_ARCH_X64)
            plaintext[i + j].mm = _mm_aesdeclast_si128(b[j].mm, f_key.mm);
#else
            plaintext[i + j].mm = veorq_u8(vaesdq_u8(b[j].mm, vdupq_n_u8(0)), f_key.mm);
#endif
        }
    }
    for (; i < num_blocks; ++i) { 
        plaintext[i] = ciphertext[i]; 
        decrypt_block(key, plaintext[i]); 
    }
}

void encrypt_cbc(const AESKey& key, Block* data, size_t num_blocks, Block iv) {
    Block prev = iv;
    for (size_t i = 0; i < num_blocks; ++i) {
        data[i] ^= prev;
        encrypt_block(key, data[i]);
        prev = data[i];
    }
}

void decrypt_cbc(const AESKey& key, Block* data, size_t num_blocks, Block iv) {
    if (num_blocks == 0) return;
    const int kWidth = 8;
    size_t i = num_blocks;
    for (; i >= kWidth; i -= kWidth) {
        size_t start = i - kWidth;
        Block ct_buffer[kWidth];
        for (int j = 0; j < kWidth; ++j) ct_buffer[j] = data[start + j];
        Block prev_ct = (start == 0) ? iv : data[start - 1];

        Block b[kWidth];
        for (int j = 0; j < kWidth; ++j) b[j] = ct_buffer[j] ^ key.expanded_keys[0];
        for (int r = 1; r < key.num_rounds; ++r) {
            Block r_key = key.expanded_keys[r];
            for (int j = 0; j < kWidth; ++j) {
#if defined(TAIHANG_ARCH_X64)
                b[j].mm = _mm_aesdec_si128(b[j].mm, r_key.mm);
#else
                b[j].mm = veorq_u8(vaesimcq_u8(vaesdq_u8(b[j].mm, vdupq_n_u8(0))), r_key.mm);
#endif
            }
        }
        Block f_key = key.expanded_keys[key.num_rounds];
#if defined(TAIHANG_ARCH_X64)
        data[start].mm = _mm_xor_si128(_mm_aesdeclast_si128(b[0].mm, f_key.mm), prev_ct.mm);
        for (int j = 1; j < kWidth; ++j) 
            data[start + j].mm = _mm_xor_si128(_mm_aesdeclast_si128(b[j].mm, f_key.mm), ct_buffer[j - 1].mm);
#else
        data[start].mm = veorq_u8(veorq_u8(vaesdq_u8(b[0].mm, vdupq_n_u8(0)), f_key.mm), prev_ct.mm);
        for (int j = 1; j < kWidth; ++j)
            data[start + j].mm = veorq_u8(veorq_u8(vaesdq_u8(b[j].mm, vdupq_n_u8(0)), f_key.mm), ct_buffer[j - 1].mm);
#endif
    }
    while (i > 0) {
        Block prev = (i == 1) ? iv : data[i - 2];
        decrypt_block(key, data[i - 1]);
        data[i - 1] ^= prev;
        i--;
    }
}

void encrypt_two_blocks(const AESKey& key, Block* data) {
#if defined(TAIHANG_ARCH_X64)
    data[0].mm = _mm_xor_si128(data[0].mm, key.expanded_keys[0].mm);
    data[1].mm = _mm_xor_si128(data[1].mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) {
        data[0].mm = _mm_aesenc_si128(data[0].mm, key.expanded_keys[i].mm);
        data[1].mm = _mm_aesenc_si128(data[1].mm, key.expanded_keys[i].mm);
    }
    data[0].mm = _mm_aesenclast_si128(data[0].mm, key.expanded_keys[key.num_rounds].mm);
    data[1].mm = _mm_aesenclast_si128(data[1].mm, key.expanded_keys[key.num_rounds].mm);
#else
    uint8x16_t zero = vdupq_n_u8(0);
    data[0].mm = veorq_u8(data[0].mm, key.expanded_keys[0].mm);
    data[1].mm = veorq_u8(data[1].mm, key.expanded_keys[0].mm);
    for (int i = 1; i < key.num_rounds; ++i) {
        data[0].mm = veorq_u8(vaesmcq_u8(vaeseq_u8(data[0].mm, zero)), key.expanded_keys[i].mm);
        data[1].mm = veorq_u8(vaesmcq_u8(vaeseq_u8(data[1].mm, zero)), key.expanded_keys[i].mm);
    }
    data[0].mm = veorq_u8(vaeseq_u8(data[0].mm, zero), key.expanded_keys[key.num_rounds].mm);
    data[1].mm = veorq_u8(vaeseq_u8(data[1].mm, zero), key.expanded_keys[key.num_rounds].mm);
#endif
}

} // namespace taihang::aes