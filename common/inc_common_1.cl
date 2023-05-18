#include "inc_common.h"

DECLSPEC u32 hc_swap32_S (const u32 v)
{
  u32 r;

  #ifdef HC_CPU_OPENCL_EMU_H
  r = byte_swap_32 (v);
  #else
  #if   (defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1
  __asm__ __volatile__ ("V_PERM_B32 %0, 0, %1, %2;" : "=v"(r) : "v"(v), "v"(0x00010203));
  #elif defined IS_NV  && HAS_PRMT  == 1
  asm volatile ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r) : "r"(v));
  #else
  #ifdef USE_SWIZZLE
  r = as_uint (as_uchar4 (v).s3210);
  #else
  r = ((v & 0xff000000) >> 24)
    | ((v & 0x00ff0000) >>  8)
    | ((v & 0x0000ff00) <<  8)
    | ((v & 0x000000ff) << 24);
  #endif
  #endif
  #endif

  return r;
}

DECLSPEC void append_0x80_4x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset)
{
  u32 v[4];

  set_mark_1x4_S (v, offset);

  const u32 offset16 = offset / 16;

  append_helper_1x4_S (w0, ((offset16 == 0) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w1, ((offset16 == 1) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w2, ((offset16 == 2) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w3, ((offset16 == 3) ? 0x80808080 : 0), v);
}

DECLSPEC void set_mark_1x4_S (PRIVATE_AS u32 *v, const u32 offset)
{
  const u32 c = (offset & 15) / 4;
  const u32 r = 0xff << ((offset & 3) * 8);

  v[0] = (c == 0) ? r : 0;
  v[1] = (c == 1) ? r : 0;
  v[2] = (c == 2) ? r : 0;
  v[3] = (c == 3) ? r : 0;
}

DECLSPEC void append_helper_1x4_S (PRIVATE_AS u32 *r, const u32 v, PRIVATE_AS const u32 *m)
{
  r[0] |= v & m[0];
  r[1] |= v & m[1];
  r[2] |= v & m[2];
  r[3] |= v & m[3];
}

#if HAS_VADD3 == 1
DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  /*
  u32x r = 0;

  #if VECT_SIZE == 1
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));
  #endif

  #if VECT_SIZE >= 2
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  #endif

  #if VECT_SIZE >= 4
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  #endif

  #if VECT_SIZE >= 8
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s4) : "v"(b.s4), "v"(a.s4), "v"(c.s4));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s5) : "v"(b.s5), "v"(a.s5), "v"(c.s5));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s6) : "v"(b.s6), "v"(a.s6), "v"(c.s6));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s7) : "v"(b.s7), "v"(a.s7), "v"(c.s7));
  #endif

  #if VECT_SIZE >= 16
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s8) : "v"(b.s8), "v"(a.s8), "v"(c.s8));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s9) : "v"(b.s9), "v"(a.s9), "v"(c.s9));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sa) : "v"(b.sa), "v"(a.sa), "v"(c.sa));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sb) : "v"(b.sb), "v"(a.sb), "v"(c.sb));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sc) : "v"(b.sc), "v"(a.sc), "v"(c.sc));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sd) : "v"(b.sd), "v"(a.sd), "v"(c.sd));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.se) : "v"(b.se), "v"(a.se), "v"(c.se));
  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sf) : "v"(b.sf), "v"(a.sf), "v"(c.sf));
  #endif

  return r;
  */

  return a + b + c;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  /*
  u32 r = 0;

  __asm__ __volatile__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));

  return r;
  */

  return a + b + c;
}
#else
DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  return a + b + c;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  return a + b + c;
}
#endif

DECLSPEC u32 hc_rotl32_S (const u32 a, const int n)
{
  #if   defined HC_CPU_OPENCL_EMU_H
  return rotl32 (a, n);
  #elif defined IS_CUDA || defined IS_HIP
  return rotl32_S (a, n);
  #else
  #ifdef USE_ROTATE
  return rotate (a, (u32) (n));
  #else
  return ((a << n) | (a >> (32 - n)));
  #endif
  #endif
}
