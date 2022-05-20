// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "CryptoTypes.h"

typedef struct EllipticCurvePoint
{
  uint8_t data[32];
} EllipticCurvePoint;

typedef struct EllipticCurveScalar
{
  uint8_t data[32];
} EllipticCurveScalar;

void generate_keys(PublicKey *pub, SecretKey *sec);

void generate_ring_signature(
    const Hash *prefix_hash, const KeyImage *image,
    const PublicKey *const *pubs, size_t pubs_count,
    const SecretKey *sec, size_t sec_index,
    Signature *sig);

void generate_key_image(const PublicKey *pub, const SecretKey *sec, KeyImage *image);

void random_scalar_noinline(EllipticCurveScalar *res);
