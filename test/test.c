#include <stdio.h>
#include "crypto-ops.h"
#include "crypto.h"
#include "hash-ops.h"
#include "random.h"

bool hexdecode(const char *from, size_t length, void *to)
{
  size_t i;
  for (i = 0; i < length; i++)
  {
    int v = 0;
    if (from[2 * i] >= '0' && from[2 * i] <= '9')
    {
      v = from[2 * i] - '0';
    }
    else if (from[2 * i] >= 'a' && from[2 * i] <= 'f')
    {
      v = from[2 * i] - 'a' + 10;
    }
    else
    {
      return false;
    }
    v <<= 4;
    if (from[2 * i + 1] >= '0' && from[2 * i + 1] <= '9')
    {
      v |= from[2 * i + 1] - '0';
    }
    else if (from[2 * i + 1] >= 'a' && from[2 * i + 1] <= 'f')
    {
      v |= from[2 * i + 1] - 'a' + 10;
    }
    else
    {
      return false;
    }
    *((unsigned char *)(to) + i) = v;
  }
  return true;
}

void check(int test_line_cnt, int *fail_cnt, int cond)
{
  if (!cond)
  {
    printf("test failed at line %d\n", test_line_cnt);
    (*fail_cnt)++;
  }
}

int main(int argc, char *argv[])
{
  fake_random();

  const char *fn = argv[1];
  FILE *fp = fopen(fn, "r");
  if (fp == NULL)
  {
    printf("Error: could not open test cases file %s\n", fn);
    return 1;
  }

  const unsigned MAX_LENGTH = 100000;
  char line[MAX_LENGTH];
  int line_cnt = 0;
  int fail_cnt = 0;
  int ignore_cnt = 0;
  while (fgets(line, MAX_LENGTH, fp))
  {
    line_cnt++;
    char *ch;
    ch = strtok(line, " ");
    if (ch == NULL)
    {
      printf("invalid line %d\n", line_cnt);
      continue;
    }

    if (strcmp(ch, "random_scalar") == 0)
    {
      EllipticCurveScalar t1;
      EllipticCurveScalar t2;
      random_scalar_noinline(&t1);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, t2.data);
      check(line_cnt, &fail_cnt, array_cmp(t1.data, t2.data, sizeof(EllipticCurveScalar)));
    }
    else if (strcmp(ch, "generate_keys") == 0)
    {
      PublicKey pk1, pk2;
      SecretKey sk1, sk2;
      generate_keys(&pk1, &sk1);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, pk2.data);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, sk2.data);
      check(line_cnt, &fail_cnt,
            array_cmp(pk1.data, pk2.data, sizeof(PublicKey)) &&
                array_cmp(sk1.data, sk2.data, sizeof(SecretKey)));
    }
    else if (strcmp(ch, "generate_signature") == 0)
    {
      EllipticCurveScalar t;
      random_scalar_noinline(&t);
    }
    else if (strcmp(ch, "generate_key_image") == 0)
    {
      PublicKey pk;
      SecretKey sk;
      KeyImage i1, i2;
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, pk.data);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, sk.data);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, i2.data);
      generate_key_image(&pk, &sk, &i1);

      check(line_cnt, &fail_cnt, array_cmp(i1.data, i2.data, sizeof(KeyImage)));
    }
    else if (strcmp(ch, "generate_ring_signature") == 0)
    {
      SecretKey sk;
      Hash h;
      KeyImage i;
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, h.data);
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, i.data);
      ch = strtok(NULL, " ");
      int pk_cnt = atoi(ch);
      PublicKey pks[pk_cnt];
      PublicKey const *pkptrs[pk_cnt];

      for (int i = 0; i < pk_cnt; i++)
      {
        ch = strtok(NULL, " ");
        hexdecode(ch, 64, pks[i].data);
        pkptrs[i] = &pks[i];
      }
      ch = strtok(NULL, " ");
      hexdecode(ch, 64, sk.data);
      ch = strtok(NULL, " ");
      int sk_idx = atoi(ch);

      Signature sig_exp[pk_cnt];
      ch = strtok(NULL, " ");
      hexdecode(ch, 128 * pk_cnt, sig_exp);

      Signature sig[pk_cnt];
      generate_ring_signature(&h, &i, pkptrs, pk_cnt, &sk, sk_idx, sig);
      check(line_cnt, &fail_cnt, array_cmp((const unsigned char *)sig, (const unsigned char *)sig_exp, pk_cnt * sizeof(Signature)));
    }
    else
    {
      ignore_cnt++;
    }
  }
  printf("ran %d test, ignore %d, fail %d\n", line_cnt, ignore_cnt, fail_cnt);

  fclose(fp);

  return 0;
}
