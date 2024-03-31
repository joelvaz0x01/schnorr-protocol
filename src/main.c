#include <stdio.h>
#include <openssl/bn.h>

#define PRIME_SECURITY 2048
#define SECURITY_LEVEL 1024
#define PROOF_ITERATIONS 1000

/**
 * Generates two safe prime numbers, p and q, where p = 2q + 1
 * @param p prime number p
 * @param q prime number q
 * @return 0 if success, 1 if error
 */
int generate_safe_primes(BIGNUM **p, BIGNUM **q) {
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!BN_generate_prime_ex2(*p, PRIME_SECURITY, 1, NULL, NULL, NULL, ctx)) {
        fprintf(stderr, "Failed to generate prime p.\n");
        BN_CTX_free(ctx);
        return 1;
    }

    // Calculate p - 1
    if (!BN_sub(*q, *p, BN_value_one())) {
        fprintf(stderr, "Failed to subtract 1 from p.\n");
        BN_CTX_free(ctx);
        return 1;
    }

    // Calculate q: (p - 1) / 2
    if (!BN_rshift1(*q, *q)) {
        fprintf(stderr, "Failed to calculate q.\n");
        BN_CTX_free(ctx);
        return 1;
    }

    BN_CTX_free(ctx);
    return 0;
}

/**
 * Generate key pair (α, v) with given prime number p
 * @param p prime number p
 * @param q prime number q
 * @param alpha generator α
 * @param beta generator β
 * @param a private key generated
 * @param v public key generated
 * @return 0 if success, 1 if error
 */
int generate_key_pair(const BIGNUM *p, const BIGNUM *q, BIGNUM **alpha, BIGNUM **beta, BIGNUM **a, BIGNUM **v) {
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    if (!BN_priv_rand_range(*alpha, p)) {
        fprintf(stderr, "Error: Failed to generate alpha\n");
        goto cleanup;
    }

    // Calculate: P - 1
    if (!BN_sub(*beta, p, BN_value_one())) {
        fprintf(stderr, "Error: Failed to calculate P - 1\n");
        goto cleanup;
    }

    // Calculate: (P - 1) / Q
    if (!BN_div(*beta, NULL, *beta, q, ctx)) {
        fprintf(stderr, "Error: Failed to divide P - 1 by Q\n");
        goto cleanup;
    }

    // Calculate: α^((P-1)/Q) mod P
    if (!BN_mod_exp(*beta, *alpha, *beta, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate beta\n");
        goto cleanup;
    }

    // Generate private key
    if (!BN_priv_rand_range(*a, q)) {
        fprintf(stderr, "Error: Failed to generate private key\n");
        goto cleanup;
    }

    // Calculate public key (β^−a mod P)
    if (!BN_mod_exp(*v, BN_mod_inverse(NULL, *beta, p, ctx), *a, p, ctx)) {
        fprintf(stderr, "Error: Failed to generate public key\n");
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return 0;

    cleanup:
    BN_CTX_free(ctx);
    return 1;
}

/**
 * Generate public and private nonce for zero knowledge proof
 * @param p prime number p
 * @param q prime number q
 * @param beta generator β
 * @param r private nonce
 * @param x public nonce
 * @return 0 if success, 1 if error
 */
int generate_nonce(const BIGNUM *p, const BIGNUM *q, const BIGNUM *beta, BIGNUM **r, BIGNUM **x) {
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Generate private nonce
    if (!BN_priv_rand_range(*r, q)) {
        fprintf(stderr, "Error: Failed to generate private nonce\n");
        goto cleanup;
    }

    // Calculate public nonce
    if (!BN_mod_exp(*x, beta, *r, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate public nonce\n");
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return 0;

    cleanup:
    BN_CTX_free(ctx);
    return 1;
}

/**
 * Generate a random challenge for zero knowledge proof
 * @param p prime number p
 * @param q prime number q
 * @param e challenge generated
 * @return 0 if success, 1 if error
 */
int generate_challenge(BIGNUM **e) {
    BIGNUM *two = BN_secure_new();
    BIGNUM *sec_level = BN_secure_new();
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!two || !sec_level || !ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Set variables: 2 and sec_level
    if (!BN_set_word(two, 2) || !BN_set_word(sec_level, (unsigned int) SECURITY_LEVEL)) {
        fprintf(stderr, "Error: Failed to set variables\n");
        goto cleanup;
    }

    // Calculate interval: 2^sec_level
    if (!BN_exp(sec_level, two, sec_level, ctx)) {
        fprintf(stderr, "Error: Failed to calculate interval\n");
        goto cleanup;
    }
    BN_clear_free(two);

    // Generate challenge
    if (!BN_priv_rand_range(*e, sec_level)) {
        fprintf(stderr, "Error: Failed to generate challenge\n");
        BN_CTX_free(ctx);
        return 1;
    }

    BN_CTX_free(ctx);
    return 0;

    cleanup:
    BN_clear_free(two);
    BN_clear_free(sec_level);
    BN_CTX_free(ctx);
    return 1;
}

/**
 * Make the proof for zero knowledge proof
 * @param q prime number q
 * @param a private key
 * @param r private nonce
 * @param e challenge
 * @return 0 if success, 1 if error
 */
int make_proof(const BIGNUM *q, const BIGNUM *a, const BIGNUM *e, const BIGNUM *r, BIGNUM **y) {
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Calculate a * e
    if (!BN_mul(*y, a, e, ctx)) {
        fprintf(stderr, "Error: Failed to multiply a and e\n");
        goto cleanup;
    }

    // Calculate y: (a * e + r) mod q
    if (!BN_mod_add(*y, *y, r, q, ctx)) {
        fprintf(stderr, "Error: Failed to sum a*e and r\n");
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return 0;

    cleanup:
    BN_CTX_free(ctx);
    return 1;
}

/**
 * Calculate the proof for zero knowledge proof
 * @param beta generator β
 * @param y proof of Alice's identity
 * @param v Alice's public key
 * @param e challenge
 * @param z Bob's verification of Alice's identity
 * @return 0 if success, 1 if error
 */
int
calculate_proof(const BIGNUM *beta, const BIGNUM *y, const BIGNUM *v, const BIGNUM *e, const BIGNUM *p, BIGNUM **z) {
    BIGNUM *z_aux = BN_secure_new();
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!z_aux || !ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Calculate β^y mod p
    if (!BN_mod_exp(z_aux, beta, y, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate β^y\n");
        goto cleanup;
    }

    // Calculate v^e mod p
    if (!BN_mod_exp(*z, v, e, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate v^e\n");
        goto cleanup;
    }

    // Calculate z: β^y * v^e mod p
    if (!BN_mod_mul(*z, z_aux, *z, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate β^y * v^e\n");
        goto cleanup;
    }

    BN_clear_free(z_aux);
    BN_CTX_free(ctx);
    return 0;

    cleanup:
    BN_clear_free(z_aux);
    BN_CTX_free(ctx);
    return 1;
}


int main() {
    BIGNUM *p = BN_secure_new(); // Safe prime p
    BIGNUM *q = BN_secure_new(); // Safe prime q
    BIGNUM *alpha = BN_secure_new(); // Generator α
    BIGNUM *beta = BN_secure_new(); // Generator β
    BIGNUM *a = BN_secure_new(); // Alice's private key
    BIGNUM *v = BN_new(); // Alice's public key
    BIGNUM *r = BN_secure_new(); // Alice's private nonce
    BIGNUM *x = BN_new(); // Alice's public nonce
    BIGNUM *e = BN_secure_new(); // Bob's challenge
    BIGNUM *y = BN_secure_new(); // Proof of Alice's identity
    BIGNUM *z = BN_secure_new(); // Bob's verification of Alice's identity

    if (!p || !q || !alpha || !beta || !a || !v || !r || !x || !e || !y || !z) {
        fprintf(stderr, "Memory allocation failed.\n");
        goto cleanup;
    }

    // Generate safe primes
    if (generate_safe_primes(&p, &q)) {
        fprintf(stderr, "Error generating safe primes.\n");
        goto cleanup;
    }
    printf("p: %s\nq: %s\n", BN_bn2dec(p), BN_bn2dec(q));

    // Generate key pair
    if (generate_key_pair(p, q, &alpha, &beta, &a, &v)) {
        fprintf(stderr, "Error generating key pair.\n");
        goto cleanup;
    }
    printf("Generator α: %s\nGenerator β: %s\n", BN_bn2dec(alpha), BN_bn2dec(beta));
    printf("Private key: %s\nPublic key: %s\n", BN_bn2dec(a), BN_bn2dec(v));


    int nTimes = 0, right = 0, wrong = 0;

    while (nTimes < PROOF_ITERATIONS) {
        // Alice: Generate public and private nonce
        if (generate_nonce(p, q, beta, &r, &x)) {
            fprintf(stderr, "Error generating nonce.\n");
            goto cleanup;
        }
        // printf("Private nonce: %s\nPublic nonce: %s\n", BN_bn2dec(r), BN_bn2dec(x));

        // Bob <- Alice: x
        if (generate_challenge(&e)) {
            fprintf(stderr, "Error generating challenge.\n");
            goto cleanup;
        }
        // printf("Challenge: %s\n", BN_bn2dec(e));

        // Alice <- Bob: e
        if (make_proof(q, a, e, r, &y)) {
            fprintf(stderr, "Error making proof.\n");
            goto cleanup;
        }
        // printf("Proof: %s\n", BN_bn2dec(y));

        // Bob <- Alice: y
        if (calculate_proof(beta, y, v, e, p, &z)) {
            fprintf(stderr, "Error calculating proof.\n");
            goto cleanup;
        }
        // printf("Proof calculated: %s\n", BN_bn2dec(z));

        BN_cmp(x, z) == 0 ? right++ : wrong++;
        nTimes++;
    }

    printf("Final report:\n");
    printf(" - True: %d/%d - %d%%\n", right, nTimes, right / nTimes * 100);
    printf(" - False: %d/%d - %d%%\n", wrong, nTimes, wrong / nTimes * 100);

    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(a);
    BN_clear_free(v);
    BN_clear_free(r);
    BN_clear_free(x);
    BN_clear_free(e);
    BN_clear_free(y);
    BN_clear_free(z);
    return 0;

    cleanup:
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(alpha);
    BN_clear_free(beta);
    BN_clear_free(a);
    BN_clear_free(v);
    BN_clear_free(r);
    BN_clear_free(x);
    BN_clear_free(e);
    BN_clear_free(y);
    BN_clear_free(z);
    return -1;
}
