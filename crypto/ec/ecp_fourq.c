/* crypto/ec/ecp_fourq.c */

/**
 * Copyright OpenSSL 2016
 * Contents licensed under the terms of the OpenSSL license
 * See http://www.openssl.org/source/license.html for details
 *
 *
 * ./config shared -L/path/to/FourQlib_v1.0 -I/path/to/FourQlib_v1.0 -lFourQ
 *
 * @author Billy Brumley <billy.brumley AT tut DOT fi>
 */

#include <openssl/err.h>

#include "internal/bn_int.h"
#include "ec_lcl.h"

/* this CRUD prevents FourQ.h include from barfing */
#if defined(OPENSSL_SYS_WINDOWS)
# define __WINDOWS__
#elif defined(OPENSSL_SYS_LINUX)
# define __LINUX__
#endif

#if defined(__ARM_ARCH__)
# define _ARM_
#elif defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
# define _AMD64_
#elif defined(THIRTY_TWO_BIT)
# define _X86_
#endif

#include <FourQ.h>

/* TODO BBB locking API changed. This is a hack. */
#define CRYPTO_add(a,b,c)       ((*(a))+=(b))
#define CRYPTO_LOCK_EC_PRE_COMP 0

/* precomp management */
typedef struct {
    void *T_fixed;
    int references;
} FOURQ_PRE_COMP;

static void *fourq_pre_comp_dup(void *src_)
{
    FOURQ_PRE_COMP *src = src_;

    if (src != NULL)
        CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

    return src_;
}

static void fourq_pre_comp_free(void *pre_)
{
    int i;
    FOURQ_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    OPENSSL_free(pre->T_fixed);
    OPENSSL_free(pre);
}

static void fourq_pre_comp_clear_free(void *pre_)
{
    int i;
    FOURQ_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    OPENSSL_clear_free(pre->T_fixed,
                       NPOINTS_FIXEDBASE * sizeof(point_precomp_t));
    OPENSSL_clear_free(pre, sizeof(*pre));
}

void ec_GFp_fourq_group_finish(EC_GROUP *group)
{
    fourq_pre_comp_free(group->field_data2);
    ec_GFp_simple_group_finish(group);
}

void ec_GFp_fourq_group_clear_finish(EC_GROUP *group)
{
    fourq_pre_comp_clear_free(group->field_data2);
    ec_GFp_simple_group_clear_finish(group);
}

int ec_GFp_fourq_group_copy(EC_GROUP *g1, const EC_GROUP *g2)
{
    if (!ec_GFp_simple_group_copy(g1, g2))
        return 0;
    g1->field_data2 = fourq_pre_comp_dup(g2->field_data2);
    return 1;
}

int ec_GFp_fourq_group_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)
{
    return 1;
}

int ec_GFp_fourq_point_init(EC_POINT *q)
{
    q->Z_is_one = 1;
    if ((q->custom_data = OPENSSL_malloc(sizeof(point_affine))) == NULL)
        return 0;
    return 1;
}

void ec_GFp_fourq_point_finish(EC_POINT *q)
{
    OPENSSL_free(q->custom_data);
    q->custom_data = NULL;
}

void ec_GFp_fourq_point_clear_finish(EC_POINT *q)
{
    OPENSSL_clear_free(q->custom_data, sizeof(point_affine));
    q->custom_data = NULL;
}

int ec_GFp_fourq_point_copy(EC_POINT *dst, const EC_POINT *src)
{
    if (dst->custom_data == NULL || src->custom_data == NULL)
        return 0;
    dst->Z_is_one = src->Z_is_one;
    memcpy(dst->custom_data, src->custom_data, sizeof(point_affine));
    return 1;
}

int ec_GFp_fourq_point_set_to_infinity(const EC_GROUP *group, EC_POINT *q)
{
    memset(q->custom_data, 0, sizeof(point_affine));
    point_affine *Q = (point_affine *) q->custom_data;
    Q->y[0][0] = 1;
    return 1;
}

int ec_GFp_fourq_point_set_affine_coordinates(const EC_GROUP *group,
                                              EC_POINT *q, const BIGNUM *x,
                                              const BIGNUM *y, BN_CTX *ctx)
{
    if (x == NULL || y == NULL)
        return 0;
    point_affine *Q = (point_affine *) q->custom_data;
    if (!bn_copy_words(Q->x, x, 2 * NWORDS_FIELD))
        return 0;
    if (!bn_copy_words(Q->y, y, 2 * NWORDS_FIELD))
        return 0;
    return 1;
}

int ec_GFp_fourq_point_get_affine_coordinates(const EC_GROUP *group,
                                              const EC_POINT *q, BIGNUM *x,
                                              BIGNUM *y, BN_CTX *ctx)
{
    point_affine *Q = (point_affine *) q->custom_data;
    if (x && !bn_set_words(x, Q->x, 2 * NWORDS_FIELD))
        return 0;
    if (y && !bn_set_words(y, Q->y, 2 * NWORDS_FIELD))
        return 0;
    return 1;
}

/* TODO BBB implement */
int ec_GFp_fourq_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                     const EC_POINT *b, BN_CTX *ctx)
{
#if 0
    return ec_GFp_simple_add(group, r, a, b, ctx);
#endif
    return 0;
}

/* TODO BBB implement */
int ec_GFp_fourq_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                     BN_CTX *ctx)
{
#if 0
    return ec_GFp_simple_dbl(group, r, a, ctx);
#endif
    return 0;
}

/* TODO BBB implement */
int ec_GFp_fourq_invert(const EC_GROUP *group, EC_POINT *q, BN_CTX *ctx)
{
#if 0
    return ec_GFp_simple_invert(group, q, ctx);
#endif
    return 0;
}

/*
 *  1: The point is at infinity
 *  0: The point is not at infinity, or error?
 */
int ec_GFp_fourq_is_at_infinity(const EC_GROUP *group, const EC_POINT *q)
{
    int i;
    point_affine *Q = (point_affine *) q->custom_data;
    digit_t r = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        r |= Q->x[0][i];
        r |= Q->x[1][i];
        if (i != 0)
            r |= Q->y[0][i];
        r |= Q->y[1][i];
    }
    /* TODO BBB rewrite with logic */
    if ((r == 0) && (Q->y[0][0] == 1))
        return 1;
    return 0;
}

/*
 *  1: The point is on the curve
 *  0: The point is not on the curve
 * -1: An error occurred
 */
int ec_GFp_fourq_is_on_curve(const EC_GROUP *group, const EC_POINT *q,
                             BN_CTX *ctx)
{
    if (q->custom_data == NULL)
        return -1;
    point_affine *Q = (point_affine *) q->custom_data;
    point_extproj_t A;
    point_setup_ni(Q, A);
    if (ecc_point_validate(A, &curve4Q) == false) {
        return 0;
    }
    return 1;
}

/*
 *  1: The points are not equal
 *  0: The points are equal
 * -1: An error occurred
 */
int ec_GFp_fourq_point_cmp(const EC_GROUP *group, const EC_POINT *a,
                           const EC_POINT *b, BN_CTX *ctx)
{
    if (a->custom_data == NULL || b->custom_data == NULL)
        return -1;
    return CRYPTO_memcmp(a->custom_data, b->custom_data,
                         sizeof(point_affine));
}

int ec_GFp_fourq_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    fourq_pre_comp_free(group->field_data2);
    FOURQ_PRE_COMP *pre = NULL;
    size_t len;
    if ((pre = OPENSSL_malloc(sizeof(*pre))) == NULL)
        return 0;
    pre->references = 1;
    len = NPOINTS_FIXEDBASE * sizeof(point_precomp_t);
    if ((pre->T_fixed = OPENSSL_zalloc(len)) == NULL) {
        OPENSSL_free(pre);
        return 0;
    }
    point_t A;
    eccset(A, &curve4Q);
    ecc_precomp_fixed(A, pre->T_fixed, false, &curve4Q);
    group->field_data2 = pre;
    return 1;
}

int ec_GFp_fourq_have_precompute_mult(const EC_GROUP *group)
{
    return group->field_data2 != NULL;
}

/**
 * TODO BBB fix long / negative scalars
 * TODO BBB check return values
 * TODO BBB num > 1
 */
int ec_GFp_fourq_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                     size_t num, const EC_POINT *points[],
                     const BIGNUM *scalars[], BN_CTX *ctx)
{
    if (num > 1)
        return 0;
    point_affine *R, *P = NULL;
    R = (point_affine *) r->custom_data;
    digit256_t scalard;
    digit256_t scalarsd;
    int rv = 0;

    do {
        if (scalar) {
            bn_copy_words(scalard, scalar, NWORDS_ORDER);
        }
        if (num == 1) {
            bn_copy_words(scalarsd, scalars[0], NWORDS_ORDER);
            P = (point_affine *) (points[0]->custom_data);
        }

        if (scalar && (num == 1)) {
            point_t A;
            eccset(A, &curve4Q);
            if (!ecc_mul(A, scalard, A, false, &curve4Q))
                break;
            if (!ecc_mul(P, scalarsd, R, false, &curve4Q))
                break;
            point_extproj_t PP;
            point_extproj_precomp_t QQ;
            point_setup_ni(A, PP);
            R1_to_R2_ni(PP, QQ, &curve4Q);
            point_setup_ni(R, PP);
            eccadd_ni(QQ, PP);
            eccnorm(PP, R);
        } else if (scalar) {
            FOURQ_PRE_COMP *pre = NULL;
            pre = group->field_data2;
            if (pre && pre->T_fixed) {
                if (!ecc_mul_fixed(pre->T_fixed, scalard, R, &curve4Q))
                    break;
            } else {
                point_t A;
                eccset(A, &curve4Q);
                if (!ecc_mul(A, scalard, R, false, &curve4Q))
                    break;
            }
        } else if (num) {
            if (!ecc_mul(P, scalarsd, R, false, &curve4Q))
                break;
        }                       /* TODO BBB else */
        rv = 1;
    } while (0);

    return rv;
}

const EC_METHOD *EC_GFp_fourq_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ec_GFp_simple_group_init,
        ec_GFp_fourq_group_finish,
        ec_GFp_fourq_group_clear_finish,
        ec_GFp_fourq_group_copy,
        ec_GFp_simple_group_set_curve,
        ec_GFp_simple_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GFp_fourq_group_check_discriminant,
        ec_GFp_fourq_point_init,
        ec_GFp_fourq_point_finish,
        ec_GFp_fourq_point_clear_finish,
        ec_GFp_fourq_point_copy,
        ec_GFp_fourq_point_set_to_infinity,
        0 /* point_set_Jprojective_coordinates_GFp */ ,
        0 /* point_get_Jprojective_coordinates_GFp */ ,
        ec_GFp_fourq_point_set_affine_coordinates,
        ec_GFp_fourq_point_get_affine_coordinates,
        0 /* point_set_compressed_coordinates */ ,
        0 /* point2oct */ ,
        0 /* oct2point */ ,
        ec_GFp_fourq_add,
        ec_GFp_fourq_dbl,
        ec_GFp_fourq_invert,
        ec_GFp_fourq_is_at_infinity,
        ec_GFp_fourq_is_on_curve,
        ec_GFp_fourq_point_cmp,
        ec_GFp_simple_make_affine,
        ec_GFp_simple_points_make_affine,
        ec_GFp_fourq_mul,
        ec_GFp_fourq_precompute_mult,
        ec_GFp_fourq_have_precompute_mult,
        0 /* field_mul */ ,
        0 /* field_sqr */ ,
        0 /* field_div */ ,
        0 /* field_encode */ ,
        0 /* field_decode */ ,
        0 /* field_set_to_one */ ,
        ec_key_simple_priv2oct,
        ec_key_simple_oct2priv,
        0,                      /* set private */
        ec_key_simple_generate_key,
        ec_key_simple_check_key,
        ec_key_simple_generate_public_key,
        0,                      /* keycopy */
        0,                      /* keyfinish */
        ecdh_simple_compute_key
    };

    return &ret;
}
