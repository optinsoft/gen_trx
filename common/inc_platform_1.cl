#include "inc_platform_1.h"

DECLSPEC u32 rotl32_S (const u32 a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}
