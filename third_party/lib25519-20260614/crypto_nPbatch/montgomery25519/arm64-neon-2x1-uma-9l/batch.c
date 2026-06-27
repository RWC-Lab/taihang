#include "crypto_nP_montgomery25519.h"
#include "crypto_nPbatch.h"
#include "mont25519_batch.h"

void crypto_nPbatch(unsigned char *nP,
  const unsigned char *n,
  const unsigned char *P,
  long long batch
  )
{
  while (batch >= 2) {
    crypto_nP_2x1((void *) nP,(void *) n,(void *) P);
    nP += 32*2;
    n += 32*2;
    P += 32*2;
    batch -= 2;
  }
  while (batch > 0) {
    crypto_nP_montgomery25519(nP,n,P);
    nP += 32;
    n += 32;
    P += 32;
    --batch;
  }
}
