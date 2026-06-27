/*
gcc has __builtin_cpu_supports("avx2")
but implemented it incorrectly until 2018:
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85100

cannot expect all of those machines to have upgraded gcc yet

furthermore, why is checking just for avx2 enough?
has intel guaranteed that it will never introduce
a cpu with avx2 instructions and without (e.g.) sse4.2?

so manually check cpuid and xgetbv here
and include all the "lower" instruction sets
rather than trying to guess which ones are implied
*/

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

#define WANT_1_3 ((1<<23)|(1<<25)|(1<<26))
/* 23=mmx; 25=sse; 26=sse2 */

#define WANT_1_2 ((1<<0)|(1<<9)|(1<<19)|(1<<20)|(1<<27)|(1<<28))
/* 0=sse3; 9=ssse3; 19=sse41; 20=sse42; 27=osxsave; 28=avx */

#define WANT_7_1 ((1<<3)|(1<<5)|(1<<8)|(1<<19))
/* 3=bmi1; 5=avx2; 8=bmi2; 19=adx */

#define WANT_7_2 ((1<<9))
/* 9=vaes */

#define WANT_EXT1_2 ((1<<6))
/* 6=sse4a */

#define WANT_XCR ((1<<1)|(1<<2))
/* 1=xmm; 2=ymm */

int supports(void)
{
  uint32_t cpuidmax,id0,id1,id2;
  uint32_t feature0,feature1,feature2,feature3;
  uint64_t xcr;

  cpuid0(0,&cpuidmax,&id0,&id1,&id2);
  if (cpuidmax < 7) return 0;

  cpuidmax = feature1 = feature2 = feature3 = 0;
  cpuid0(0x80000000,&cpuidmax,&feature1,&feature2,&feature3);
  if (cpuidmax < 0x80000001) return 0;

  cpuid0(1,&feature0,&feature1,&feature2,&feature3);
  if (WANT_1_2 != (WANT_1_2 & feature2)) return 0;
  if (WANT_1_3 != (WANT_1_3 & feature3)) return 0;

  cpuid0(7,&feature0,&feature1,&feature2,&feature3);
  if (WANT_7_1 != (WANT_7_1 & feature1)) return 0;
  if (WANT_7_2 != (WANT_7_2 & feature2)) return 0;

  cpuid0(0x80000001,&feature0,&feature1,&feature2,&feature3);
  if (WANT_EXT1_2 != (WANT_EXT1_2 & feature2)) return 0;

  xcr = xgetbv0();
  if (WANT_XCR != (WANT_XCR & xcr)) return 0;

  return 1;
}
