// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto.h"
#include "crypto-ops.h"
#include "random.h"
#include "hash-ops.h"

//namespace Crypto {

  static inline void random_scalar(EllipticCurveScalar *res) {
    unsigned char tmp[64];
    generate_random_bytes(64, tmp);
    sc_reduce(tmp);
    memcpy(res->data, tmp, 32);
  }

  void random_scalar_noinline(EllipticCurveScalar *res)
  {
    random_scalar(res);
  }

  static inline void hash_to_scalar(const void *data, size_t length, EllipticCurveScalar *res) {
    cn_fast_hash(data, length, res->data);
    sc_reduce32(res->data);
  }

  void generate_keys(PublicKey *pub, SecretKey *sec) {
    ge_p3 point;
    random_scalar(sec);
    ge_scalarmult_base(&point, sec->data);
    ge_p3_tobytes(pub->data, &point);
  }

  bool check_key(const PublicKey *key) {
    ge_p3 point;
    return ge_frombytes_vartime(&point, key->data) == 0;
  }

  static void hash_to_ec(const PublicKey *key, ge_p3 *res) {
    Hash h;
    ge_p2 point;
    ge_p1p1 point2;
    cn_fast_hash(key->data, sizeof(PublicKey), h.data);
    ge_fromfe_frombytes_vartime(&point, h.data);
    ge_mul8(&point2, &point);
    ge_p1p1_to_p3(res, &point2);
  }

  void generate_key_image(const PublicKey *pub, const SecretKey *sec, KeyImage *image) {
    ge_p3 point;
    ge_p2 point2;
    assert(sc_check(sec->data) == 0);
    hash_to_ec(pub, &point);
    ge_scalarmult(&point2, sec->data, &point);
    ge_tobytes(image->data, &point2);
  }

  typedef struct rs_comm {
    Hash h;
    struct {
      EllipticCurvePoint a, b;
    } ab[];
  } rs_comm;

  static inline size_t rs_comm_size(size_t pubs_count) {
    return sizeof(rs_comm) + pubs_count * sizeof(EllipticCurvePoint) * 2;
  }

  void generate_ring_signature(const Hash *prefix_hash, const KeyImage *image,
    const PublicKey *const *pubs, size_t pubs_count,
    const SecretKey *sec, size_t sec_index,
    Signature *sig) {
    size_t i;
    ge_p3 image_unp;
    ge_dsmp image_pre;
    EllipticCurveScalar sum, k, h;
    rs_comm *const buf = (rs_comm *)(alloca(rs_comm_size(pubs_count)));
    assert(sec_index < pubs_count);
#if !defined(NDEBUG)
    {
      ge_p3 t;
      PublicKey t2;
      KeyImage t3;
      assert(sc_check(sec->data) == 0);
      ge_scalarmult_base(&t, sec->data);
      ge_p3_tobytes(&t2, &t);
      assert(array_cmp(pubs[sec_index]->data, t2.data, 32));
      generate_key_image(pubs[sec_index], sec, &t3);
      assert(array_cmp(image->data, t3.data, 32));
      for (i = 0; i < pubs_count; i++)
      {
        assert(check_key(pubs[i]));
      }
    }
#endif
    if (ge_frombytes_vartime(&image_unp, image->data) != 0) {
      abort();
    }
    ge_dsm_precomp(image_pre, &image_unp);
    sc_0(sum.data);
    buf->h = *prefix_hash;
    for (i = 0; i < pubs_count; i++) {
      ge_p2 tmp2;
      ge_p3 tmp3;
      if (i == sec_index) {
        random_scalar(&k);
        ge_scalarmult_base(&tmp3, k.data);
        ge_p3_tobytes(&buf->ab[i].a, &tmp3);
        hash_to_ec(pubs[i], &tmp3);
        ge_scalarmult(&tmp2, k.data, &tmp3);
        ge_tobytes(&buf->ab[i].b, &tmp2);
      } else {
        random_scalar(sig[i].data);
        random_scalar(sig[i].data + 32);
        if (ge_frombytes_vartime(&tmp3, pubs[i]) != 0) {
          abort();
        }
        ge_double_scalarmult_base_vartime(&tmp2, sig[i].data, &tmp3, sig[i].data + 32);
        ge_tobytes(&buf->ab[i].a, &tmp2);
        hash_to_ec(pubs[i], &tmp3);
        ge_double_scalarmult_precomp_vartime(&tmp2, sig[i].data + 32, &tmp3, sig[i].data, image_pre);
        ge_tobytes(&buf->ab[i].b, &tmp2);
        sc_add(sum.data, sum.data, sig[i].data);
      }
    }
    hash_to_scalar(buf, rs_comm_size(pubs_count), &h);
    sc_sub(sig[sec_index].data, h.data, sum.data);
    sc_mulsub(sig[sec_index].data + 32, sig[sec_index].data, sec->data, k.data);
  }

// }
