#include "kernel/bip39.cl"
#include "kernel/common.cl"
#include "kernel/ec.cl"
#include "kernel/sha256.cl"
#include "kernel/sha512.cl"

__kernel void verify_batch(__global ulong *H_array, __global ulong *L_array, __global ulong *output) {
  int gid = get_global_id(0);

  ulong inner_data[32] = {0};
  ulong outer_data[32] = {0};
  ulong hmacSeedOutput[8] = {0};

  ulong memHigh = H_array[gid];
  ulong firstMem = L_array[gid];
  ulong memLow = firstMem;

  ulong mnemonicLong[16] = {0};
  ulong pbkdLong[16] = {0};
  uint seedNum[16] = {0};
  uchar mnemonicString[128] = {0};

  uint offset = 0;
  prepareSeedNumber(seedNum, memHigh, memLow);
  prepareSeedString(seedNum, mnemonicString, offset);
  ucharLong(mnemonicString, offset - 1, mnemonicLong, 0);

  #pragma unroll
  for (int lid = 0; lid < 16; lid++) {
    inner_data[lid] = mnemonicLong[lid] ^ IPAD;
    outer_data[lid] = mnemonicLong[lid] ^ OPAD;
  }

  outer_data[16] = 6655295901103053916;
  inner_data[16] = 7885351518267664739;
  inner_data[17] = 6442450944;
  outer_data[24] = 9223372036854775808;
  outer_data[31] = 1536;
  inner_data[31] = 1120;

  pbkdf2_hmac_sha512_long(inner_data, outer_data, pbkdLong);
  hmac_sha512_bitcoin_seed(pbkdLong, hmacSeedOutput);

  for(int i = 0; i < 8; i++) output[gid * 8 + i] = hmacSeedOutput[i];
}
