// uniform_interval.c
// Implements: pick k uniformly in [a, b] given an n with 2^(n-1) <= (b-a) <= 2^n - 1

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Portable explicit zero (avoid relying on OPENSSL_cleanse)
static void secure_zero(void* p, size_t n) {
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
}

// Return a fresh BIGNUM with uniform value in [0, 2^n - 1]
static BIGNUM* bn_uniform_n_bits(size_t n_bits) {
    size_t n_bytes = (n_bits + 7) / 8;
    unsigned char* buf;
    BIGNUM* r;

    if (n_bytes == 0) {
        // n=0 means range [0, 0]
        return BN_new(); // zero
    }

    buf = (unsigned char*)calloc(n_bytes, 1);
    if (!buf) {
        fprintf(stderr, "alloc failed\n");
        return NULL;
    }

    if (RAND_priv_bytes(buf, (int)n_bytes) != 1) {
        fprintf(stderr, "RAND_priv_bytes failed\n");
        free(buf);
        return NULL;
    }

    // Mask top unused bits so the value < 2^n_bits
    unsigned int top_unused = (unsigned int)(n_bytes * 8 - n_bits);
    if (top_unused > 0) {
        unsigned char mask = (unsigned char)(0xFFu >> top_unused);
        buf[0] &= mask;
    }

    r = BN_bin2bn(buf, (int)n_bytes, NULL);
    secure_zero(buf, n_bytes);
    free(buf);
    if (!r) {
        fprintf(stderr, "BN_bin2bn failed\n");
        return NULL;
    }
    return r;
}

/*
Agreed Primes non-compliant checks in interval but does not check if it is prime with Miller Rabin.
*/
static BIGNUM* uniform_in_interval(const BIGNUM* a, const BIGNUM* b, size_t n_bits) {
    if (BN_is_negative(a) || BN_is_negative(b)) {
        fprintf(stderr, "a and b must be non-negative (Z>=0 for this routine).\n");
        return NULL;
    }
    if (BN_cmp(a, b) > 0) {
        fprintf(stderr, "a must be <= b.\n");
        return NULL;
    }

    // range = b - a
    BIGNUM* range = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!range || !ctx) {
        BN_free(range);
        BN_CTX_free(ctx);
        fprintf(stderr, "alloc failed\n");
        return NULL;
    }
    if (!BN_copy(range, b)) {
        BN_free(range); BN_CTX_free(ctx);
        fprintf(stderr, "BN_copy failed\n");
        return NULL;
    }
    if (!BN_sub(range, range, a)) {
        BN_free(range); BN_CTX_free(ctx);
        fprintf(stderr, "BN_sub failed\n");
        return NULL;
    }

    // Check precondition: 2^(n-1) <= range <= 2^n - 1
    BIGNUM* two_pow_n_minus_1 = BN_new();
    BIGNUM* two_pow_n = BN_new();
    BIGNUM* one = BN_new();
    if (!two_pow_n_minus_1 || !two_pow_n || !one) {
        BN_free(range); BN_free(two_pow_n_minus_1); BN_free(two_pow_n); BN_free(one); BN_CTX_free(ctx);
        fprintf(stderr, "alloc failed\n");
        return NULL;
    }
    BN_one(one);

    // two_pow_n = 1 << n_bits
    if (!BN_lshift(two_pow_n, one, (int)n_bits)) {
        fprintf(stderr, "BN_lshift failed\n");
        return NULL;
    }
    // two_pow_n_minus_1 = 1 << (n_bits - 1)
    if (n_bits == 0) {
        fprintf(stderr, "n must be >= 1\n");
        return NULL;
    }
    if (!BN_lshift(two_pow_n_minus_1, one, (int)(n_bits - 1))) {
        fprintf(stderr, "BN_lshift failed (n-1)\n");
        return NULL;
    }

    // Check: range >= 2^(n-1)
    if (BN_cmp(range, two_pow_n_minus_1) < 0) {
        fprintf(stderr, "Precondition failed: (b - a) < 2^(n-1).\n");
        return NULL;
    }
    // Check: range <= 2^n - 1  <=>  range + 1 <= 2^n
    BIGNUM* range_plus_1 = BN_dup(range);
    if (!range_plus_1 || !BN_add(range_plus_1, range_plus_1, one)) {
        fprintf(stderr, "BN_add failed\n");
        return NULL;
    }
    if (BN_cmp(range_plus_1, two_pow_n) > 0) {
        fprintf(stderr, "Precondition failed: (b - a) > 2^n - 1.\n");
        return NULL;
    }

    // Rejection sampling loop:
    // 1) Pick k' in [0, 2^n - 1]
    // 2) If k' > range, repeat
    // 3) k = k' + a
    BIGNUM* kprime = BN_new();
    BIGNUM* k = BN_new();
    if (!kprime || !k) {
        BN_free(range); BN_free(range_plus_1); BN_free(two_pow_n_minus_1); BN_free(two_pow_n); BN_free(one);
        BN_free(kprime); BN_free(k); BN_CTX_free(ctx);
        fprintf(stderr, "alloc failed\n");
        return NULL;
    }

    int ok = 0;
    for (;;) {
        BIGNUM* r = bn_uniform_n_bits(n_bits);     // r in [0, 2^n - 1]
        if (!r) break;
        if (!BN_copy(kprime, r)) { BN_clear_free(r); break; }
        BN_clear_free(r);

        if (BN_cmp(kprime, range) <= 0) {
            // k = k' + a
            if (!BN_copy(k, kprime) || !BN_add(k, k, a)) break;
            ok = 1;
            break;
        }
        // else: retry
    }

    // Cleanup
    BN_clear_free(kprime);
    BN_free(range);
    BN_free(range_plus_1);
    BN_free(two_pow_n_minus_1);
    BN_free(two_pow_n);
    BN_free(one);
    BN_CTX_free(ctx);

    if (!ok) {
        BN_clear_free(k);
        fprintf(stderr, "Sampling failed\n");
        return NULL;
    }
    return k; // caller owns k
}

// --- Demo usage (remove in library code) ---
int main(void) {
    // Example: a = 1000, b = 1000 + (2^16 - 1)  => n = 16 satisfies 2^(n-1) <= (b-a) <= 2^n - 1
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    BIGNUM* two16 = BN_new();
    BN_set_word(a, 1000);
    BN_one(two16);
    BN_lshift(two16, two16, 16); // 2^16
    BN_copy(b, two16);
    BN_sub_word(b, 1);
    BN_add(b, b, a);             // b = a + (2^16 - 1)

    BIGNUM* k = uniform_in_interval(a, b, 16);
    if (!k) {
        fprintf(stderr, "uniform_in_interval failed\n");
        BN_free(a);
        BN_free(b);
        BN_free(two16);
        return 1;
    }

    // Print result
    char* k_dec = BN_bn2dec(k);
    printf("k = %s (decimal)\n", k_dec);

    // Cleanup
    OPENSSL_free(k_dec);
    BN_free(a);
    BN_free(b);
    BN_free(two16);
    BN_clear_free(k);
    return 0;
}
