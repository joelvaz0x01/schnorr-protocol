#include <openssl/bn.h>
#include <stdio.h>

#define PRIME_SECURITY 2048
#define SECURITY_LEVEL 1024
#define PROOF_ITERATIONS 1000

/**
 * Free a BIGNUM variable
 * @param bn BIGNUM variable to be freed
 * @return NULL
 */
void *free_bn(BIGNUM **bn) {
    BN_clear_free(*bn);
    return NULL;
}

/**
 * Free a BN_CTX variable
 * @param ctx BN_CTX variable to be freed
 * @return NULL
 */
void *free_ctx(BN_CTX **ctx) {
    BN_CTX_free(*ctx);
    return NULL;
}

/**
 * Generates two safe prime numbers, p and q, where p = 2q + 1
 * @param p prime number p
 * @param q prime number q
 * @return 0 if success, 1 if error
 */
int generate_safe_primes(BIGNUM **p, BIGNUM **q) {
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    if (!BN_generate_prime_ex2(*p, PRIME_SECURITY, 1, NULL, NULL, NULL, ctx)) {
        fprintf(stderr, "Failed to generate prime p.\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate p - 1
    if (!BN_sub(*q, *p, BN_value_one())) {
        fprintf(stderr, "Failed to subtract 1 from p.\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate q: (p - 1) / 2
    if (!BN_rshift1(*q, *q)) {
        fprintf(stderr, "Failed to calculate q.\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    ctx = free_ctx(&ctx);
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
        return 1;
    }

    if (!BN_priv_rand_range(*alpha, p)) {
        fprintf(stderr, "Error: Failed to generate alpha\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate: P - 1
    if (!BN_sub(*beta, p, BN_value_one())) {
        fprintf(stderr, "Error: Failed to calculate P - 1\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate: (P - 1) / Q
    if (!BN_div(*beta, NULL, *beta, q, ctx)) {
        fprintf(stderr, "Error: Failed to divide P - 1 by Q\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate: α^((P-1)/Q) mod P
    if (!BN_mod_exp(*beta, *alpha, *beta, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate beta\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Generate private key
    if (!BN_priv_rand_range(*a, q)) {
        fprintf(stderr, "Error: Failed to generate private key\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate public key (β^−a mod P)
    if (!BN_mod_exp(*v, BN_mod_inverse(NULL, *beta, p, ctx), *a, p, ctx)) {
        fprintf(stderr, "Error: Failed to generate public key\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    ctx = free_ctx(&ctx);
    return 0;
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
        return 1;
    }

    // Generate private nonce
    if (!BN_priv_rand_range(*r, q)) {
        fprintf(stderr, "Error: Failed to generate private nonce\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate public nonce
    if (!BN_mod_exp(*x, beta, *r, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate public nonce\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    ctx = free_ctx(&ctx);
    return 0;
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
        return 1;
    }

    // Set variables: 2 and sec_level
    if (!BN_set_word(two, 2) || !BN_set_word(sec_level, (unsigned int) SECURITY_LEVEL)) {
        fprintf(stderr, "Error: Failed to set variables\n");
        two = free_bn(&two);
        sec_level = free_bn(&sec_level);
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate interval: 2^sec_level
    if (!BN_exp(sec_level, two, sec_level, ctx)) {
        fprintf(stderr, "Error: Failed to calculate interval\n");
        two = free_bn(&two);
        sec_level = free_bn(&sec_level);
        ctx = free_ctx(&ctx);
        return 1;
    }
    two = free_bn(&two);

    // Generate challenge
    if (!BN_priv_rand_range(*e, sec_level)) {
        fprintf(stderr, "Error: Failed to generate challenge\n");
        sec_level = free_bn(&sec_level);
        ctx = free_ctx(&ctx);
        return 1;
    }

    sec_level = free_bn(&sec_level);
    ctx = free_ctx(&ctx);
    return 0;
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
        return 1;
    }

    // Calculate a * e
    if (!BN_mul(*y, a, e, ctx)) {
        fprintf(stderr, "Error: Failed to multiply a and e\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate y: (a * e + r) mod q
    if (!BN_mod_add(*y, *y, r, q, ctx)) {
        fprintf(stderr, "Error: Failed to sum a*e and r\n");
        ctx = free_ctx(&ctx);
        return 1;
    }

    ctx = free_ctx(&ctx);
    return 0;
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
int calculate_proof(const BIGNUM *beta, const BIGNUM *y, const BIGNUM *v, const BIGNUM *e, const BIGNUM *p,
                    BIGNUM **z) {
    BIGNUM *z_aux = BN_secure_new();
    BN_CTX *ctx = BN_CTX_secure_new();

    if (!z_aux || !ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    // Calculate β^y mod p
    if (!BN_mod_exp(z_aux, beta, y, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate β^y\n");
        z_aux = free_bn(&z_aux);
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate v^e mod p
    if (!BN_mod_exp(*z, v, e, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate v^e\n");
        z_aux = free_bn(&z_aux);
        ctx = free_ctx(&ctx);
        return 1;
    }

    // Calculate z: β^y * v^e mod p
    if (!BN_mod_mul(*z, z_aux, *z, p, ctx)) {
        fprintf(stderr, "Error: Failed to calculate β^y * v^e\n");
        z_aux = free_bn(&z_aux);
        ctx = free_ctx(&ctx);
        return 1;
    }

    z_aux = free_bn(&z_aux);
    ctx = free_ctx(&ctx);
    return 0;
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
        return -1;
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
    printf("Generator Alpha: %s\nGenerator Beta: %s\n", BN_bn2dec(alpha), BN_bn2dec(beta));
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

    printf("\nFinal report:\n");
    printf(" - True: %d/%d - %d%%\n", right, nTimes, right / nTimes * 100);
    printf(" - False: %d/%d - %d%%\n", wrong, nTimes, wrong / nTimes * 100);

    p = free_bn(&p);
    q = free_bn(&q);
    alpha = free_bn(&alpha);
    beta = free_bn(&beta);
    a = free_bn(&a);
    v = free_bn(&v);
    r = free_bn(&r);
    x = free_bn(&x);
    e = free_bn(&e);
    y = free_bn(&y);
    z = free_bn(&z);
    return 0;

cleanup:
    p = free_bn(&p);
    q = free_bn(&q);
    alpha = free_bn(&alpha);
    beta = free_bn(&beta);
    a = free_bn(&a);
    v = free_bn(&v);
    r = free_bn(&r);
    x = free_bn(&x);
    e = free_bn(&e);
    y = free_bn(&y);
    z = free_bn(&z);
    return -1;
}
