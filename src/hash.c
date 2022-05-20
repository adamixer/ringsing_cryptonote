// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash-ops.h"
#include "keccak.h"
#include "sha3.h"

void hash_permutation(union hash_state *state) {
  keccakf((uint64_t*)state, 24);
}

void hash_process(union hash_state *state, const uint8_t *buf, size_t count) {
  keccak1600(buf, (int)count, (uint8_t*)state);
}

#ifndef USE_SHA3
void cn_fast_hash(const void *data, size_t length, uint8_t *hash) {
  union hash_state state;
  hash_process(&state, data, length);
  memcpy(hash, &state, HASH_SIZE);
}
#else
void cn_fast_hash(const void *data, size_t length, uint8_t *hash) {
  sha3_context c;
  sha3_Init256(&c);
  sha3_Update(&c, data, length);
  const uint8_t *res = sha3_Finalize(&c);
  memcpy(hash, res, HASH_SIZE);
}
#endif
