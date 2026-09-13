/* Expose RandomWOW's compile-time configuration to Rust.
 *
 * `specs/15-testing-and-conformance.md` §2.4 asks for a test that "asserts
 * RANDOMX_ARGON_SALT == \"RandomWOW\x01\" by reading the compiled constant
 * through FFI. This catches the single most likely build mistake -- linking
 * against upstream RandomX."
 *
 * The point is that these values come from the header the *library* was
 * compiled with, so they cannot drift from it. A Rust-side copy of the numbers
 * would prove nothing.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "configuration.h"

const char *wow_rx_argon_salt(void) {
  return RANDOMX_ARGON_SALT;
}

size_t wow_rx_argon_salt_len(void) {
  /* sizeof minus the terminating NUL: the salt is "RandomWOW\x01", 10 bytes. */
  return sizeof(RANDOMX_ARGON_SALT) - 1;
}

uint32_t wow_rx_argon_memory(void) { return RANDOMX_ARGON_MEMORY; }
uint32_t wow_rx_argon_iterations(void) { return RANDOMX_ARGON_ITERATIONS; }
uint32_t wow_rx_argon_lanes(void) { return RANDOMX_ARGON_LANES; }
uint32_t wow_rx_cache_accesses(void) { return RANDOMX_CACHE_ACCESSES; }
uint32_t wow_rx_superscalar_latency(void) { return RANDOMX_SUPERSCALAR_LATENCY; }
uint64_t wow_rx_dataset_base_size(void) { return RANDOMX_DATASET_BASE_SIZE; }
uint64_t wow_rx_dataset_extra_size(void) { return RANDOMX_DATASET_EXTRA_SIZE; }
uint32_t wow_rx_program_size(void) { return RANDOMX_PROGRAM_SIZE; }
uint32_t wow_rx_program_iterations(void) { return RANDOMX_PROGRAM_ITERATIONS; }
uint32_t wow_rx_program_count(void) { return RANDOMX_PROGRAM_COUNT; }
uint32_t wow_rx_scratchpad_l3(void) { return RANDOMX_SCRATCHPAD_L3; }
uint32_t wow_rx_scratchpad_l2(void) { return RANDOMX_SCRATCHPAD_L2; }
uint32_t wow_rx_scratchpad_l1(void) { return RANDOMX_SCRATCHPAD_L1; }
uint32_t wow_rx_jump_bits(void) { return RANDOMX_JUMP_BITS; }
uint32_t wow_rx_jump_offset(void) { return RANDOMX_JUMP_OFFSET; }

/* The instruction frequencies, in the order specs/03 §3.1 lists them. Summing
 * these to 256 is the other assertion §2.4 asks for. */
void wow_rx_frequencies(uint32_t out[32]) {
  uint32_t f[32] = {
      RANDOMX_FREQ_IADD_RS,  RANDOMX_FREQ_IADD_M,   RANDOMX_FREQ_ISUB_R,
      RANDOMX_FREQ_ISUB_M,   RANDOMX_FREQ_IMUL_R,   RANDOMX_FREQ_IMUL_M,
      RANDOMX_FREQ_IMULH_R,  RANDOMX_FREQ_IMULH_M,  RANDOMX_FREQ_ISMULH_R,
      RANDOMX_FREQ_ISMULH_M, RANDOMX_FREQ_IMUL_RCP, RANDOMX_FREQ_INEG_R,
      RANDOMX_FREQ_IXOR_R,   RANDOMX_FREQ_IXOR_M,   RANDOMX_FREQ_IROR_R,
      RANDOMX_FREQ_IROL_R,   RANDOMX_FREQ_ISWAP_R,  RANDOMX_FREQ_FSWAP_R,
      RANDOMX_FREQ_FADD_R,   RANDOMX_FREQ_FADD_M,   RANDOMX_FREQ_FSUB_R,
      RANDOMX_FREQ_FSUB_M,   RANDOMX_FREQ_FSCAL_R,  RANDOMX_FREQ_FMUL_R,
      RANDOMX_FREQ_FDIV_M,   RANDOMX_FREQ_FSQRT_R,  RANDOMX_FREQ_CBRANCH,
      RANDOMX_FREQ_CFROUND,  RANDOMX_FREQ_ISTORE,   RANDOMX_FREQ_NOP,
      0,                     0};
  memcpy(out, f, sizeof(f));
}

/* How many of the 32 slots above are real frequencies. */
size_t wow_rx_frequency_count(void) { return 30; }
