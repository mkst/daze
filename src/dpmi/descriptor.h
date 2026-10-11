#ifndef DAZE_DPMI_DESCRIPTOR_H
#define DAZE_DPMI_DESCRIPTOR_H

#include <stdint.h>

/* Eight-byte 80386 descriptor codec. The caller owns descriptor validation,
 * table access, and cache maintenance. The low four bits of `flags` become
 * byte 6's high nibble (G, D/B, L, AVL). */
void daze_dpmi_descriptor_encode(uint8_t descriptor[8], uint32_t base, uint32_t limit,
                                 uint8_t access, uint8_t flags);

/* Replaces the base of an already-valid descriptor; preserves limit, access,
 * and flags byte-for-byte. */
void daze_dpmi_descriptor_set_base(uint8_t descriptor[8], uint32_t base);

/* Preserves base, access, D/B, L, and AVL. Limits through 000FFFFFh clear G;
 * larger limits require all low 12 bits set and use page granularity (G=1).
 * Returns 0 without changing the descriptor if the limit is unrepresentable,
 * otherwise 1. */
int daze_dpmi_descriptor_set_limit(uint8_t descriptor[8], uint32_t limit);

/* The low rights byte supplies access/type; bits 15–12 supply G, D/B, L, AVL.
 * Preserves the base and encoded limit bits. Rights validation belongs to the caller. */
void daze_dpmi_descriptor_set_access(uint8_t descriptor[8], uint16_t rights);

#endif
