// demo_rsa_prime.c
// Build: gcc -std=c11 -O2 -Wall -Wextra demo_rsa_prime.c -lcrypto -o demo_rsa_prime

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- minimal helpers ---

static BIGNUM* bn_uniform_n_bits(size_t n_bits) {
    size_t n_bytes = (n_bits + 7) / 8;
    unsigned char* buf = NULL;
    BIGNUM* r;

    buf = (unsigned char*)calloc(n_bytes ? n_bytes : 1, 1);
    if (!buf) {
        fprintf(stderr, "calloc failed\n");
        return NULL;
    }

    if (n_bytes && RAND_priv_bytes(buf, (int)n_bytes) != 1) {
        fprintf(stderr, "RAND_priv_bytes failed\n");
        free(buf);
        return NULL;
    }
    if (n_bytes) {
        unsigned int top_unused = (unsigned int)(n_bytes * 8 - n_bits);
        if (top_unused) buf[0] &= (unsigned char)(0xFFu >> top_unused);
    }
    r = BN_bin2bn(buf, (int)n_bytes, NULL);
    free(buf);
    if (!r) {
        fprintf(stderr, "BN_bin2bn failed\n");
        return NULL;
    }
    return r;
}

static size_t bits_for_range(const BIGNUM* range) {
    int bits = BN_num_bits(range);
    return bits > 0 ? (size_t)bits : 1;
}

// uniform k in [a,b]
static BIGNUM* uniform_in_interval(const BIGNUM* a, const BIGNUM* b) {
    if (BN_cmp(a, b) > 0) {
        fprintf(stderr, "a<=b required\n");
        return NULL;
    }
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return NULL;
    }
    BN_CTX_start(ctx);
    BIGNUM* range = BN_CTX_get(ctx);
    if (!range) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        fprintf(stderr, "alloc\n");
        return NULL;
    }
    BN_copy(range, b);
    BN_sub(range, range, a);

    if (BN_is_zero(range)) { // single-point interval
        BIGNUM* k = BN_new();
        BN_copy(k, a);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return k;
    }

    size_t n_bits = bits_for_range(range);
    for (;;) {
        BIGNUM* r = bn_uniform_n_bits(n_bits);          // [0, 2^n-1]
        if (!r) {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return NULL;
        }
        if (BN_cmp(r, range) <= 0) {
            BIGNUM* k = BN_new();
            BN_copy(k, r);
            BN_add(k, k, a);
            BN_clear_free(r);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return k;
        }
        BN_clear_free(r); // reject and retry
    }
}

// --- Miller–Rabin only (no small-prime sieve) ---

static int miller_rabin(const BIGNUM* n, int rounds, BN_CTX* ctx) {
    if (BN_is_negative(n) || BN_is_zero(n) || BN_is_one(n)) return 0;
    if (BN_is_word(n, 2)) return 1;
    if (!BN_is_odd(n)) return 0;

    BN_CTX_start(ctx);
    BIGNUM* n_1 = BN_CTX_get(ctx);
    BIGNUM* d   = BN_CTX_get(ctx);
    BIGNUM* a   = BN_CTX_get(ctx);
    BIGNUM* x   = BN_CTX_get(ctx);
    BIGNUM* one = BN_CTX_get(ctx);
    BIGNUM* n_2 = BN_CTX_get(ctx);
    if (!n_1 || !d || !a || !x || !one || !n_2) {
        BN_CTX_end(ctx);
        return 0;
    }

    BN_one(one);
    BN_copy(n_1, n);
    BN_sub(n_1, n_1, one);       // n-1
    BN_copy(d, n_1);
    unsigned int s = 0;          // n-1 = 2^s * d (d odd)
    while (!BN_is_odd(d)) {
        BN_rshift1(d, d);
        ++s;
    }

    BN_copy(n_2, n);
    BN_sub(n_2, n_2, one);
    BN_sub(n_2, n_2, one); // n-2

    for (int i = 0; i < rounds; ++i) {
        // a in [2, n-2]
        BIGNUM* lo = BN_new();
        BIGNUM* abase;
        BN_set_word(lo, 2);
        abase = uniform_in_interval(lo, n_2);
        BN_copy(a, abase);
        BN_free(lo);
        BN_clear_free(abase);

        // x = a^d mod n (const-time montgomery)
        if (!BN_mod_exp_mont_consttime(x, a, d, n, ctx, NULL)) {
            BN_CTX_end(ctx);
            return 0;
        }
        if (BN_is_one(x) || BN_cmp(x, n_1) == 0) continue;

        {
            int witness = 1;
            for (unsigned int r = 1; r < s; ++r) {
                if (!BN_mod_mul(x, x, x, n, ctx)) {
                    BN_CTX_end(ctx);
                    return 0;
                }
                if (BN_cmp(x, n_1) == 0) {
                    witness = 0;
                    break;
                }
                if (BN_is_one(x)) {
                    BN_CTX_end(ctx);
                    return 0; // nontrivial sqrt(1) -> composite
                }
            }
            if (witness) {
                BN_CTX_end(ctx);
                return 0; // composite
            }
        }
    }
    BN_CTX_end(ctx);
    return 1; // probably prime
}

/*
Agreed Primes, samples within an interval and checks with miller rabin if the num is prime
*/

static int is_probable_prime(const BIGNUM* n, int mr_rounds) {
    BN_CTX* ctx = BN_CTX_new();
    int ok;
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 0;
    }
    ok = miller_rabin(n, mr_rounds, ctx);
    BN_CTX_free(ctx);
    return ok;
}

// Sample until a probable prime appears (oddify and retry).
static BIGNUM* sample_prime_in_interval(const BIGNUM* a, const BIGNUM* b,
                                        int mr_rounds, size_t max_tries) {
    if (BN_cmp(a, b) > 0) {
        fprintf(stderr, "a<=b required\n");
        return NULL;
    }
    BIGNUM* lo = BN_dup(a);
    if (!lo) return NULL;
    if (BN_cmp_word(lo, 2) < 0) BN_set_word(lo, 2);

    for (size_t t = 0; t < max_tries; ++t) {
        BIGNUM* k = uniform_in_interval(lo, b);
        if (!k) {
            BN_free(lo);
            return NULL;
        }
        if (!BN_is_odd(k)) {
            if (BN_cmp(k, b) < 0) BN_add_word(k, 1);
            else {
                BN_clear_free(k);
                continue;
            }
        }
        if (is_probable_prime(k, mr_rounds)) {
            BN_free(lo);
            return k;
        }
        BN_clear_free(k);
    }
    BN_free(lo);
    fprintf(stderr, "No prime found (interval small or unlucky).\n");
    return NULL;
}

// --- demo main: 256-bit prime in [2^255, 2^256-1] ---
int main(void) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* a;
    BIGNUM* b;
    BIGNUM* one;
    BIGNUM* p;
    char* hex;

    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    one = BN_CTX_get(ctx);
    BN_one(one);

    BN_lshift(a, one, 255);                    // a = 2^255
    BN_lshift(b, one, 256);
    BN_sub(b, b, one);                         // b = 2^256 - 1

    p = sample_prime_in_interval(a, b, 32, 500000);
    if (p) {
        hex = BN_bn2hex(p);
        printf("Prime (~256-bit):\n%s\n", hex);
        OPENSSL_free(hex);
        BN_clear_free(p);
    } else {
        fprintf(stderr, "Failed.\n");
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}
