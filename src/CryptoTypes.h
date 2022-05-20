// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <stdint.h>

typedef struct Hash {
  uint8_t data[32];
} Hash;

typedef struct PublicKey {
  uint8_t data[32];
} PublicKey;

typedef struct SecretKey {
  uint8_t data[32];
} SecretKey;

typedef struct KeyDerivation {
  uint8_t data[32];
} KeyDerivation;

typedef struct KeyImage {
  uint8_t data[32];
} KeyImage;

typedef struct Signature {
  uint8_t data[64];
} Signature;
