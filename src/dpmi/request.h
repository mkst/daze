#ifndef DAZE_DPMI_REQUEST_H
#define DAZE_DPMI_REQUEST_H

#include "linear_memory.h"
#include "memory.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Backends resolve selectors and guest memory; descriptor services use supplied images
 * and never infer bases from selector numbers. */

/* Guest register mapping:
 * function = AX; selector = BX for descriptor services, not linear allocation.
 * size = BX:CX bytes for 0501h/0503h; operand = CX:DX base/limit for 0007h/0008h
 * or SI:DI linear handle for 0502h/0503h; rights = CX for 0009h.
 * exception/interrupt = BL. vector_segment/offset models the 16-bit exception
 * pair CX:DX; interrupt_segment/offset models protected vectors as CX:EDX.
 * Real-mode vector services use CX:DX.
 * count = CX for 0000h, BX paragraphs for 0100h.
 * state_buffer_size is the caller-supplied 0305h reply size, not a guest operand.
 * rm_segment/offset = CX:DX, pm_selector/offset = SI:EDI endpoint replies. */
typedef struct {
  uint16_t function;
  uint16_t selector;
  uint32_t size;
  uint32_t operand;
  uint16_t rights;
  uint16_t exception;
  uint16_t vector_segment;
  uint16_t vector_offset;
  uint8_t interrupt;
  uint16_t interrupt_segment;
  uint32_t interrupt_offset;
  uint16_t count;
  uint16_t state_buffer_size;
  uint16_t rm_segment;
  uint16_t rm_offset;
  uint16_t pm_selector;
  uint32_t pm_offset;
} DazeDpmiRequest;

/* Borland DPMILOAD passes a live 0501h handle in DX to legacy 0102h/0101h
 * requests. This bridge uses operand=16-bit token, size=paragraphs<<4 for
 * resize. It does not allocate DOS memory or interpret tokens as selectors. */

/* success means CF clear; failure supplies dpmi_error and ax = error word.
 * Successful ax retains the function unless the service returns a value there.
 * Descriptor mutation failures preserve the supplied eight-byte image.
 * Exception offsets are modeled as 16 bits; low-word register writes preserve
 * incoming high halves. Protected interrupt offsets use full EDX.
 * Endpoint replies echo backend-supplied values. Virtual-interrupt replies
 * report the prior state, before the requested enable/disable operation. */
typedef struct {
  int success;
  uint16_t dpmi_error;
  uint16_t ax;
  uint32_t base;
  uint32_t handle;
  uint32_t largest_available;
  uint8_t descriptor[8];
  uint16_t vector_segment;
  uint16_t vector_offset;
  uint16_t interrupt_segment;
  uint32_t interrupt_offset;
  uint16_t state_buffer_size;
  uint16_t rm_segment;
  uint16_t rm_offset;
  uint16_t pm_selector;
  uint32_t pm_offset;
  int previous_virtual_interrupts_enabled;
} DazeDpmiResult;

void daze_dpmi_request_resize_loader_block(DazeDpmiLinearMemory *memory,
                                           const DazeDpmiRequest *request, DazeDpmiResult *result);
void daze_dpmi_request_release_loader_block(DazeDpmiLinearMemory *memory,
                                            const DazeDpmiRequest *request, DazeDpmiResult *result);

/* Register writes shared by the vector-pair services (0200h--0205h). A
 * `write_*16` field means replace only the corresponding low word; `write_edx`
 * replaces the complete EDX. On failure only AX is specified, and `success`
 * is the carry-clear condition. Adapters retain every unlisted register. */
typedef struct {
  int success;
  int write_ax16;
  uint16_t ax;
  int write_cx16;
  uint16_t cx;
  int write_dx16;
  uint16_t dx;
  int write_edx;
  uint32_t edx;
} DazeDpmiVectorResultContract;

/* Register writes shared by transition endpoint queries (0305h/0306h).
 * Low-word writes retain high halves; EDI is a full-width endpoint offset.
 * The endpoints themselves remain adapter-owned inputs to the request. */
typedef struct {
  int success;
  int write_ax16;
  uint16_t ax;
  int write_bx16;
  uint16_t bx;
  int write_cx16;
  uint16_t cx;
  int write_si16;
  uint16_t si;
  int write_edi;
  uint32_t edi;
} DazeDpmiTransitionResultContract;

/* Register writes shared by scalar services: 0400h version, and 0900h/0901h
 * virtual-interrupt queries. `write_cl` and `write_al` alter only those bytes;
 * all other 16-bit writes retain the incoming upper halves. */
typedef struct {
  int success;
  int write_ax16;
  uint16_t ax;
  int write_al;
  uint8_t al;
  int write_bx16;
  uint16_t bx;
  int write_cl;
  uint8_t cl;
  int write_dx16;
  uint16_t dx;
} DazeDpmiScalarResultContract;

/* Register writes shared by 0501h--0503h linear-memory services and the
 * DPMILOAD 0101h/0102h token bridge. All listed outputs are low words;
 * 0502h/0101h/0102h success changes no general register. */
typedef struct {
  int success;
  int write_ax16;
  uint16_t ax;
  int write_bx16;
  uint16_t bx;
  int write_cx16;
  uint16_t cx;
  int write_si16;
  uint16_t si;
  int write_di16;
  uint16_t di;
} DazeDpmiLinearResultContract;

/* Unset exception slots read as 0000:0000; the caller owns zero initialization. */
typedef struct {
  uint16_t segment;
  uint16_t offset;
} DazeDpmiExceptionVector;

/* One protected interrupt-vector slot for 0204h/0205h. Unlike exception
 * vectors, DPMI carries the offset in full EDX. The caller owns this table
 * and its zero initialization. */
typedef struct {
  uint16_t segment;
  uint32_t offset;
} DazeDpmiInterruptVector;

/* Claim a fresh LDT slot only after validation; descriptor installation and cache
 * maintenance belong to the backend. */
typedef struct {
  uint8_t *used;
  size_t capacity;
  uint16_t first_index;
} DazeDpmiLdtAllocator;

/* 0100h: count is BX paragraphs. Atomically allocate DOS memory and one
 * LDT slot. AX is the real segment, handle is the selector, descriptor is
 * its data image. Failure returns AX=8/8011h and largest_available in
 * paragraphs, without consuming either allocator. */
void daze_dpmi_request_allocate_dos_memory(DazeDosMemory *memory, DazeDpmiLdtAllocator *allocator,
                                           const DazeDpmiRequest *request, DazeDpmiResult *result);

/* 0000h returns the first selector in AX and claims `count` consecutive slots.
 * Descriptor images remain backend-owned. Invalid count/allocator or no free
 * run returns 8011h without changing the bitmap. */
void daze_dpmi_request_allocate_ldt_descriptors(const DazeDpmiRequest *request,
                                                DazeDpmiLdtAllocator *allocator,
                                                DazeDpmiResult *result);

/* 0001h: release one allocated LDT selector in the caller-owned bitmap.
 * Invalid, GDT, or already-free selectors return 8022h without changing it. */
void daze_dpmi_request_free_ldt_descriptor(const DazeDpmiRequest *request,
                                           DazeDpmiLdtAllocator *allocator, DazeDpmiResult *result);

void daze_dpmi_request_get_selector_increment(const DazeDpmiRequest *request,
                                              DazeDpmiResult *result);

/* 0501h returns base/handle; failure returns 8012h with both outputs zero. */
void daze_dpmi_request_allocate_linear_memory(DazeDpmiLinearMemory *memory,
                                              const DazeDpmiRequest *request,
                                              DazeDpmiResult *result);

/* 0503h returns the possibly relocated base; failure returns 8012h. */
void daze_dpmi_request_resize_linear_memory(DazeDpmiLinearMemory *memory,
                                            const DazeDpmiRequest *request, DazeDpmiResult *result);

/* 0502h rejects unknown/released handles with 8023h and no allocator change. */
void daze_dpmi_request_free_linear_memory(DazeDpmiLinearMemory *memory,
                                          const DazeDpmiRequest *request, DazeDpmiResult *result);

/* 0500h: report the current largest allocatable linear block. The caller
 * owns the fixed guest information image and its ES:DI destination. */
void daze_dpmi_request_get_free_memory_information(const DazeDpmiLinearMemory *memory,
                                                   const DazeDpmiRequest *request,
                                                   DazeDpmiResult *result);

enum { DAZE_DPMI_FREE_MEMORY_INFORMATION_SIZE = 48 };

/* 0500h's little-endian payload leaves unspecified fields at FFFFFFFFh.
 * The caller supplies a writable buffer of the fixed size. */
void daze_dpmi_free_memory_information_encode(
  uint32_t largest_available, uint8_t information[DAZE_DPMI_FREE_MEMORY_INFORMATION_SIZE]);

void daze_dpmi_request_get_version(const DazeDpmiRequest *request, DazeDpmiResult *result);

/* 0600h/0601h succeed without side effects in the non-paging memory model. */
void daze_dpmi_request_lock_linear_region(const DazeDpmiRequest *request, DazeDpmiResult *result);

/* 0006h: return the caller-resolved descriptor base in result.base. Table
 * lookup stays backend-owned because selectors may name GDT or LDT entries. */
void daze_dpmi_request_get_segment_base(const DazeDpmiRequest *request, uint32_t base,
                                        DazeDpmiResult *result);

void daze_dpmi_request_set_segment_base(const DazeDpmiRequest *request, const uint8_t descriptor[8],
                                        DazeDpmiResult *result);

/* 0008h rejects unrepresentable limits with 8021h and an unchanged image. */
void daze_dpmi_request_set_segment_limit(const DazeDpmiRequest *request,
                                         const uint8_t descriptor[8], DazeDpmiResult *result);

/* 0009h rejects AVL, system/nonzero-DPL descriptors, and present code unless
 * readable and nonconforming. Failure returns 8021h with an unchanged image. */
void daze_dpmi_request_set_access_rights(const DazeDpmiRequest *request,
                                         const uint8_t descriptor[8], DazeDpmiResult *result);

/* 000Ah aliases caller-resolved present GDT code as writable LDT data.
 * Success returns the new selector in AX and its descriptor image. Invalid
 * source or exhausted allocator returns 8022h without changing the bitmap. */
void daze_dpmi_request_create_data_alias(const DazeDpmiRequest *request,
                                         const uint8_t source_descriptor[8],
                                         DazeDpmiLdtAllocator *allocator, DazeDpmiResult *result);

/* 0202h: out-of-range exceptions return 8021h with zero vector outputs. */
void daze_dpmi_request_get_exception_vector(const DazeDpmiRequest *request,
                                            const DazeDpmiExceptionVector *vectors, size_t count,
                                            DazeDpmiResult *result);

/* 0203h: out-of-range exceptions return 8021h without changing the table. */
void daze_dpmi_request_set_exception_vector(const DazeDpmiRequest *request,
                                            DazeDpmiExceptionVector *vectors, size_t count,
                                            DazeDpmiResult *result);

/* 0200h/0201h: read/write the CX:DX real-mode vector pair for BL. */
void daze_dpmi_request_get_real_mode_vector(const DazeDpmiRequest *request,
                                            const uint16_t *segments, const uint16_t *offsets,
                                            size_t count, DazeDpmiResult *result);
void daze_dpmi_request_set_real_mode_vector(const DazeDpmiRequest *request, uint16_t *segments,
                                            uint16_t *offsets, size_t count,
                                            DazeDpmiResult *result);

/* 0204h returns CX:EDX; an unset slot reads 0000:00000000. */
void daze_dpmi_request_get_interrupt_vector(const DazeDpmiRequest *request,
                                            const DazeDpmiInterruptVector *vectors, size_t count,
                                            DazeDpmiResult *result);

void daze_dpmi_request_set_interrupt_vector(const DazeDpmiRequest *request,
                                            DazeDpmiInterruptVector *vectors, size_t count,
                                            DazeDpmiResult *result);

/* Translate a successful or failed 0200h--0205h service result into the
 * documented architectural register effects. Returns zero for another
 * function, so callers cannot accidentally manufacture an unsupported reply. */
int daze_dpmi_request_vector_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiVectorResultContract *contract);

int daze_dpmi_request_transition_result_contract(const DazeDpmiRequest *request,
                                                 const DazeDpmiResult *result,
                                                 DazeDpmiTransitionResultContract *contract);

int daze_dpmi_request_scalar_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiScalarResultContract *contract);

int daze_dpmi_request_linear_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiLinearResultContract *contract);

void daze_dpmi_request_get_state_save_endpoints(const DazeDpmiRequest *request,
                                                DazeDpmiResult *result);

void daze_dpmi_request_get_raw_switch_endpoints(const DazeDpmiRequest *request,
                                                DazeDpmiResult *result);

/* 0900h reports the prior state and disables the caller-owned flag in one call.
 * A null flag fails with AX=8021h. */
void daze_dpmi_request_get_and_disable_virtual_interrupts(int *virtual_interrupts_enabled,
                                                          DazeDpmiResult *result);

/* 0901h reports the prior state and enables the caller-owned flag in one call.
 * A null flag fails with AX=8021h. */
void daze_dpmi_request_get_and_enable_virtual_interrupts(int *virtual_interrupts_enabled,
                                                         DazeDpmiResult *result);

/* Vector diagnostics retain full register widths and KVM's conditional ES reload to
 * expose backend differences. cs/ip is the post-interrupt address; off_bits
 * distinguishes 16-bit exception offsets from 32-bit interrupt offsets. */

typedef struct {
  const char *backend;
  uint16_t function;
  uint32_t cs;
  uint32_t ip;
  int db;
  uint8_t bl;
  int off_bits;
  uint32_t in_ecx;
  uint32_t in_edx;
  uint32_t in_edi;
  uint32_t in_es;
  uint32_t res_segment;
  uint32_t res_offset;
  uint32_t out_ecx;
  uint32_t out_edx;
  uint32_t out_edi;
  uint32_t out_es;
  int es_reload;
  uint32_t slot_segment;
  uint32_t slot_offset;
} DazeDpmiVectorRecord;

static inline int daze_dpmi_vector_record_enabled(void) {
  return getenv("DAZE_DPMI_VECTOR_RECORD") != NULL;
}

static inline void daze_dpmi_vector_record_print(const DazeDpmiVectorRecord *record) {
  if (record == NULL || !daze_dpmi_vector_record_enabled()) return;
  fprintf(stderr,
          "dpmi-vector backend=%s fn=%04x cs=%04x ip=%08x db=%d bl=%02x off_bits=%d "
          "in_ecx=%08x in_edx=%08x in_edi=%08x in_es=%08x res=%04x:%08x "
          "out_ecx=%08x out_edx=%08x out_edi=%08x out_es=%08x es_reload=%d slot=%04x:%08x\n",
          record->backend, record->function, record->cs, record->ip, record->db, record->bl,
          record->off_bits, record->in_ecx, record->in_edx, record->in_edi, record->in_es,
          record->res_segment, record->res_offset, record->out_ecx, record->out_edx,
          record->out_edi, record->out_es, record->es_reload, record->slot_segment,
          record->slot_offset);
}

#endif
