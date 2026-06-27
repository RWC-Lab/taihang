#include <stdio.h>
#include <inttypes.h>

#ifdef __FILC__
#include <cpuid.h>
#include <stdfil.h>
#elif defined(_MSC_VER)
#include <immintrin.h>
#include <intrin.h>
#endif

static void cpuid0(uint32_t func,uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d)
{
#ifdef __FILC__
  __get_cpuid(func,a,b,c,d);
#elif defined(_MSC_VER)
  uint32_t x[4];
  __cpuid(x,func);
  *a = x[0];
  *b = x[1];
  *c = x[2];
  *d = x[3];
#else
  asm volatile("cpuid":"=a"(*a),"=b"(*b),"=c"(*c),"=d"(*d):"a"(func),"c"(0));
#endif
}

static uint64_t xgetbv0(void)
{
#ifdef __FILC__
  return zxgetbv();
#elif defined(_MSC_VER)
  return _xgetbv(0);
#else
  uint32_t a,d;
  asm(".byte 15;.byte 1;.byte 208":"=a"(a),"=d"(d):"c"(0));
  return a|(((uint64_t)d)<<32);
#endif
}

__attribute__((visibility("default")))
void lib25519_cpuid(unsigned int *result,long long resultlen)
{
  uint32_t a,b,c,d;
  uint32_t cpuidmax,extendedcpuidmax;
  int havexgetbv = 0;

  cpuid0(0,&a,&b,&c,&d);
  cpuidmax = a;
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  cpuid0(0x80000000,&a,&b,&c,&d);
  extendedcpuidmax = a;

  a = b = c = d = 0;
  if (extendedcpuidmax >= 0x80000002) cpuid0(0x80000002,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  if (extendedcpuidmax >= 0x80000003) cpuid0(0x80000003,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  if (extendedcpuidmax >= 0x80000004) cpuid0(0x80000004,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  if (cpuidmax >= 1) cpuid0(1,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }
  /* 27=osxsave; 28=avx */
  if (((1<<27)|(1<<28)) == (((1<<27)|(1<<28)) & c))
    havexgetbv = 1;

  a = b = c = d = 0;
  if (cpuidmax >= 7) cpuid0(7,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  if (extendedcpuidmax >= 0x80000001) cpuid0(0x80000001,&a,&b,&c,&d);
  if (resultlen > 0) { *result++ = a; --resultlen; }
  if (resultlen > 0) { *result++ = b; --resultlen; }
  if (resultlen > 0) { *result++ = c; --resultlen; }
  if (resultlen > 0) { *result++ = d; --resultlen; }

  a = b = c = d = 0;
  if (havexgetbv) a = xgetbv0(); /* will keep bottom 32 bits */
  if (resultlen > 0) { *result++ = a; --resultlen; }

  while (resultlen > 0) { *result++ = 0; --resultlen; }
}
