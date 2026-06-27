/* ----- sign/ed25519, derived from supercop/crypto_sign/try.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <lib25519.h>
#include "lib25519_test.h"

#define fail ((ok = 0),printf)
static const char *sign_ed25519_checksums[] = {
  "ce11fd7c1eac4dd0bc5eec49b26ad1e91aef696fae50ce377dbd806dc394da01",
  "2ed857f17c917a8185e6c296303a11772ae45683a5e7cb5b095489bad65fffde",
} ;

static void (*crypto_sign_keypair)(unsigned char *,unsigned char *);
static void (*crypto_sign)(unsigned char *,long long *,const unsigned char *,long long,const unsigned char *);
static int (*crypto_sign_open)(unsigned char *,long long *,const unsigned char *,long long,const unsigned char *);
#define crypto_sign_SECRETKEYBYTES lib25519_sign_ed25519_SECRETKEYBYTES
#define crypto_sign_PUBLICKEYBYTES lib25519_sign_ed25519_PUBLICKEYBYTES
#define crypto_sign_BYTES lib25519_sign_ed25519_BYTES

static void *storage_sign_ed25519_p;
static unsigned char *test_sign_ed25519_p;
static void *storage_sign_ed25519_s;
static unsigned char *test_sign_ed25519_s;
static void *storage_sign_ed25519_m;
static unsigned char *test_sign_ed25519_m;
static void *storage_sign_ed25519_c;
static unsigned char *test_sign_ed25519_c;
static void *storage_sign_ed25519_t;
static unsigned char *test_sign_ed25519_t;
static void *storage_sign_ed25519_p2;
static unsigned char *test_sign_ed25519_p2;
static void *storage_sign_ed25519_s2;
static unsigned char *test_sign_ed25519_s2;
static void *storage_sign_ed25519_m2;
static unsigned char *test_sign_ed25519_m2;
static void *storage_sign_ed25519_c2;
static unsigned char *test_sign_ed25519_c2;
static void *storage_sign_ed25519_t2;
static unsigned char *test_sign_ed25519_t2;

static void test_sign_ed25519_impl(long long impl)
{
  unsigned char *p = test_sign_ed25519_p;
  unsigned char *s = test_sign_ed25519_s;
  unsigned char *m = test_sign_ed25519_m;
  unsigned char *c = test_sign_ed25519_c;
  unsigned char *t = test_sign_ed25519_t;
  unsigned char *p2 = test_sign_ed25519_p2;
  unsigned char *s2 = test_sign_ed25519_s2;
  unsigned char *m2 = test_sign_ed25519_m2;
  unsigned char *c2 = test_sign_ed25519_c2;
  unsigned char *t2 = test_sign_ed25519_t2;
  long long plen = crypto_sign_PUBLICKEYBYTES;
  long long slen = crypto_sign_SECRETKEYBYTES;
  long long mlen;
  long long clen;
  long long tlen;

  if (targeti && strcmp(targeti,".") && strcmp(targeti,lib25519_dispatch_sign_ed25519_implementation(impl))) return;
  if (targetn && atol(targetn) != impl) return;
  if (impl >= 0) {
    crypto_sign_keypair = lib25519_dispatch_sign_ed25519_keypair(impl);
    crypto_sign = lib25519_dispatch_sign_ed25519(impl);
    crypto_sign_open = lib25519_dispatch_sign_ed25519_open(impl);
    printf("sign_ed25519 %lld implementation %s compiler %s\n",impl,lib25519_dispatch_sign_ed25519_implementation(impl),lib25519_dispatch_sign_ed25519_compiler(impl));
  } else {
    crypto_sign_keypair = lib25519_sign_ed25519_keypair;
    crypto_sign = lib25519_sign_ed25519;
    crypto_sign_open = lib25519_sign_ed25519_open;
    printf("sign_ed25519 selected implementation %s compiler %s\n",lib25519_sign_ed25519_implementation(),lib25519_sign_ed25519_compiler());
  }
  for (long long checksumbig = 0;checksumbig < 2;++checksumbig) {
    long long loops = checksumbig ? 64 : 8;
    long long maxtest = checksumbig ? 4096 : 128;

    checksum_clear();

    for (long long loop = 0;loop < loops;++loop) {
      int result;
      mlen = myrandom() % (maxtest + 1);

      output_prepare(p2,p,plen);
      output_prepare(s2,s,slen);
      crypto_sign_keypair(p,s);
      declassify(p,plen);
      declassify(s,slen);
      checksum(p,plen);
      checksum(s,slen);
      output_compare(p2,p,plen,"crypto_sign_keypair");
      output_compare(s2,s,slen,"crypto_sign_keypair");
      clen = mlen + crypto_sign_BYTES;
      output_prepare(c2,c,clen);
      input_prepare(m2,m,mlen);
      memcpy(s2,s,slen);
      double_canary(s2,s,slen);
      secret(m,mlen);
      secret(s,slen);
      crypto_sign(c,&clen,m,mlen,s);
      declassify(m,mlen);
      declassify(s,slen);
      declassify(c,clen);
      if (clen < mlen) fail("failure: crypto_sign returns smaller output than input\n");
      if (clen > mlen + crypto_sign_BYTES) fail("failure: crypto_sign returns more than crypto_sign_BYTES extra bytes\n");
      checksum(c,clen);
      output_compare(c2,c,clen,"crypto_sign");
      input_compare(m2,m,mlen,"crypto_sign");
      input_compare(s2,s,slen,"crypto_sign");
      tlen = clen;
      output_prepare(t2,t,tlen);
      memcpy(c2,c,clen);
      double_canary(c2,c,clen);
      memcpy(p2,p,plen);
      double_canary(p2,p,plen);
      declassify(c,clen);
      declassify(p,plen);
      result = crypto_sign_open(t,&tlen,c,clen,p);
      declassify(&result,sizeof result);
      if (result != 0) fail("failure: crypto_sign_open returns nonzero\n");
      declassify(c,clen);
      declassify(p,plen);
      declassify(t,tlen);
      if (tlen != mlen) fail("failure: crypto_sign_open does not match mlen\n");
      if (memcmp(t,m,mlen) != 0) fail("failure: crypto_sign_open does not match m\n");
      checksum(t,tlen);
      output_compare(t2,t,clen,"crypto_sign_open");
      input_compare(c2,c,clen,"crypto_sign_open");
      input_compare(p2,p,plen,"crypto_sign_open");

      double_canary(t2,t,tlen);
      double_canary(c2,c,clen);
      double_canary(p2,p,plen);
      declassify(c2,clen);
      declassify(p2,plen);
      result = crypto_sign_open(t2,&tlen,c2,clen,p2);
      declassify(&result,sizeof result);
      if (result != 0) fail("failure: crypto_sign_open returns nonzero\n");
      declassify(c2,clen);
      declassify(p2,plen);
      declassify(t2,tlen);
      if (memcmp(t2,t,tlen) != 0) fail("failure: crypto_sign_open is nondeterministic\n");

      double_canary(t2,t,tlen);
      double_canary(c2,c,clen);
      double_canary(p2,p,plen);
      declassify(c2,clen);
      declassify(p,plen);
      result = crypto_sign_open(c2,&tlen,c2,clen,p);
      declassify(&result,sizeof result);
      if (result != 0) fail("failure: crypto_sign_open with c=t overlap returns nonzero\n");
      declassify(c2,tlen);
      declassify(p,plen);
      if (memcmp(c2,t,tlen) != 0) fail("failure: crypto_sign_open does not handle c=t overlap\n");
      memcpy(c2,c,clen);
      declassify(c,clen);
      declassify(p2,plen);
      result = crypto_sign_open(p2,&tlen,c,clen,p2);
      declassify(&result,sizeof result);
      if (result != 0) fail("failure: crypto_sign_open with p=t overlap returns nonzero\n");
      declassify(p2,tlen);
      declassify(c,clen);
      if (memcmp(p2,t,tlen) != 0) fail("failure: crypto_sign_open does not handle p=t overlap\n");
      memcpy(p2,p,plen);

      c[myrandom() % clen] += 1 + (myrandom() % 255);
      if (crypto_sign_open(t,&tlen,c,clen,p) == 0)
        if ((tlen != mlen) || (memcmp(t,m,mlen) != 0))
          fail("failure: crypto_sign_open allows trivial forgeries\n");
      c[myrandom() % clen] += 1 + (myrandom() % 255);
      if (crypto_sign_open(t,&tlen,c,clen,p) == 0)
        if ((tlen != mlen) || (memcmp(t,m,mlen) != 0))
          fail("failure: crypto_sign_open allows trivial forgeries\n");
      c[myrandom() % clen] += 1 + (myrandom() % 255);
      if (crypto_sign_open(t,&tlen,c,clen,p) == 0)
        if ((tlen != mlen) || (memcmp(t,m,mlen) != 0))
          fail("failure: crypto_sign_open allows trivial forgeries\n");
    }
    checksum_expected(sign_ed25519_checksums[checksumbig]);
  }
}

void test_sign_ed25519(void)
{
  long long maxalloc = 0;
  if (targeto && strcmp(targeto,"sign")) return;
  if (targetp && strcmp(targetp,"ed25519")) return;
  storage_sign_ed25519_p = callocplus(4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  test_sign_ed25519_p = (unsigned char *) aligned(storage_sign_ed25519_p,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  if (4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES > maxalloc) maxalloc = 4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES;
  storage_sign_ed25519_s = callocplus(4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  test_sign_ed25519_s = (unsigned char *) aligned(storage_sign_ed25519_s,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  if (4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES > maxalloc) maxalloc = 4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES;
  storage_sign_ed25519_m = callocplus(4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  test_sign_ed25519_m = (unsigned char *) aligned(storage_sign_ed25519_m,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  if (4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES > maxalloc) maxalloc = 4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES;
  storage_sign_ed25519_c = callocplus(4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  test_sign_ed25519_c = (unsigned char *) aligned(storage_sign_ed25519_c,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  if (4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES > maxalloc) maxalloc = 4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES;
  storage_sign_ed25519_t = callocplus(4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  test_sign_ed25519_t = (unsigned char *) aligned(storage_sign_ed25519_t,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  if (4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES > maxalloc) maxalloc = 4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES;
  storage_sign_ed25519_p2 = callocplus(maxalloc);
  test_sign_ed25519_p2 = (unsigned char *) aligned(storage_sign_ed25519_p2,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  storage_sign_ed25519_s2 = callocplus(maxalloc);
  test_sign_ed25519_s2 = (unsigned char *) aligned(storage_sign_ed25519_s2,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  storage_sign_ed25519_m2 = callocplus(maxalloc);
  test_sign_ed25519_m2 = (unsigned char *) aligned(storage_sign_ed25519_m2,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  storage_sign_ed25519_c2 = callocplus(maxalloc);
  test_sign_ed25519_c2 = (unsigned char *) aligned(storage_sign_ed25519_c2,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);
  storage_sign_ed25519_t2 = callocplus(maxalloc);
  test_sign_ed25519_t2 = (unsigned char *) aligned(storage_sign_ed25519_t2,4096+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_sign_SECRETKEYBYTES);

  for (long long offset = 0;offset < 2;++offset) {
    if (targetoffset && atol(targetoffset) != offset) continue;
    if (offset && valgrind) break;
    printf("sign_ed25519 offset %lld\n",offset);
    for (long long impl = -1;impl < lib25519_numimpl_sign_ed25519();++impl)
      forked(test_sign_ed25519_impl,impl);
    ++test_sign_ed25519_p;
    ++test_sign_ed25519_s;
    ++test_sign_ed25519_m;
    ++test_sign_ed25519_c;
    ++test_sign_ed25519_t;
    ++test_sign_ed25519_p2;
    ++test_sign_ed25519_s2;
    ++test_sign_ed25519_m2;
    ++test_sign_ed25519_c2;
    ++test_sign_ed25519_t2;
  }
  free(storage_sign_ed25519_t2);
  free(storage_sign_ed25519_c2);
  free(storage_sign_ed25519_m2);
  free(storage_sign_ed25519_s2);
  free(storage_sign_ed25519_p2);
  free(storage_sign_ed25519_t);
  free(storage_sign_ed25519_c);
  free(storage_sign_ed25519_m);
  free(storage_sign_ed25519_s);
  free(storage_sign_ed25519_p);
}
#undef crypto_sign_SECRETKEYBYTES
#undef crypto_sign_PUBLICKEYBYTES
#undef crypto_sign_BYTES

