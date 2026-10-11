#ifndef DAZE_UNICORN_CONTEXT_H
#define DAZE_UNICORN_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#include "trace_config.h"
#include "dosfs.h"
#include "file_service.h"
#include "process_state.h"
#include "memory.h"
#include "alternate_state.h"
#include "linear_memory.h"
#include "request.h"
#include "metrics.h"
#include "raw_vector_projection.h"
#include "dpmi_process_state.h"
#include "guest_memory_layout.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

enum {
  k_instruction_limit = 20 * 1000 * 1000,
  k_dpmi_rm_frame_size = 0x32,
  k_dpmi_rm_edi = 0x00,
  k_dpmi_rm_esi = 0x04,
  k_dpmi_rm_ebp = 0x08,
  k_dpmi_rm_ebx = 0x10,
  k_dpmi_rm_edx = 0x14,
  k_dpmi_rm_ecx = 0x18,
  k_dpmi_rm_eax = 0x1c,
  k_dpmi_rm_flags = 0x20,
  k_dpmi_rm_es = 0x22,
  k_dpmi_rm_ds = 0x24,
  k_dpmi_rm_fs = 0x26,
  k_dpmi_rm_gs = 0x28,
  k_dpmi_rm_ip = 0x2a,
  k_dpmi_rm_cs = 0x2c,
  k_dpmi_rm_sp = 0x2e,
  k_dpmi_rm_ss = 0x30,
  k_dpmi_exception_far_call_size = 5,
};

typedef struct {
  uint64_t linear_address;
  uint16_t cs;
  uint16_t ip;
  uint8_t bytes[8];
} CodeTrace;

/* Only one nested EXEC child is supported. */
typedef struct {
  uc_context *parent_context;
  uint16_t psp_segment;
  uint16_t allocation_segment;
  uint16_t parent_psp_segment;
  uint16_t parent_dta_segment;
  uint16_t parent_dta_offset;
  uint32_t parent_resident_image_end;
  DazeDosMemory parent_memory;
  DazeDosfsExecHandles handles;
  uint8_t exit_code;
  uint8_t termination_type;
  int active;
  int status_available;
} DazeDosChildProcess;

/* A vector may decline DOS service through a null far jump. Preserve caller selectors
 * and hidden bases for host fallback; either decline or IRET must retire both delivery
 * hooks. */
typedef struct {
  uc_engine *engine;
  uc_context *caller_context;
  uc_hook decline_hook;
  void *continuation_context;
  uc_hook return_hook;
  void *return_context;
  uint16_t return_cs;
  uint32_t return_eip;
  uint16_t delivered_cs;
  uint32_t delivered_eip;
  uint16_t frame_ss;
  uint32_t frame_esp;
  uint8_t frame_size;
  int active;
  int already_advanced;
} DazeProtectedDosContinuation;

/* Captured selector-fault state is guest-derived, not a fixed client address. */
typedef struct {
  uint32_t fault_linear;
  uint16_t error_code;
  uint16_t fault_cs;
  uint16_t fault_ip;
  uint16_t fault_ss;
  uint16_t fault_sp;
  uint16_t fault_ds;
  uint16_t fault_es;
  uint8_t instruction_size;
  uint16_t gprs[7];
  uint32_t eflags;
  uint8_t instruction[5];
} DazeDpmiExceptionFault;

/* One in-flight exception delivery owns a locked-stack slot and exact-address
 * entry, return, and successor hooks. Retiring a delivery releases its hooks
 * and slot; termination disarms any deliveries still active. */
typedef struct DazeUnicornExceptionHookContext DazeUnicornExceptionHookContext;

typedef struct {
  uc_hook hook;
  uc_hook return_hook;
  uc_hook successor_hook;
  /* Owned heap hook context, freed with the delivery; NULL for records without installed
   * hooks. */
  DazeUnicornExceptionHookContext *hook_context;
  uint64_t entry_linear;
  uint64_t return_linear;
  uint32_t frame_linear;
  uint16_t gateway_cs;
  uint16_t gateway_ip;
  uint16_t gateway_ss;
  uint16_t gateway_sp;
  uint32_t gateway_eflags;
  uint16_t entry_cs;
  uint16_t entry_ip;
  uint16_t entry_ss;
  uint16_t entry_sp;
  uint16_t entry_ds;
  uint16_t entry_es;
  uint16_t entry_gprs[7];
  uint32_t entry_eflags;
  uint8_t frame[16];
  /* The faulting operand selector determines whether return retries the fault. */
  uint16_t error_code;
  int armed;
  int return_armed;
  int return_reached;
  int successor_armed;
  int entry_reached;
  unsigned frame_depth;
  int active;
} DazeDpmiExceptionTransfer;

enum { k_dpmi_exception_max_depth = 8 };

typedef struct {
  DazeDpmiExceptionTransfer records[k_dpmi_exception_max_depth];
  unsigned depth;
} DazeDpmiExceptionTransferStack;

typedef struct {
  DazeMetrics metrics;
  int full_code_hook;
  int debug;
  DazeUnicornTraceConfig diagnostic_trace;
  uint64_t last_code_address;
  int have_code;
  CodeTrace recent_code[24];
  size_t recent_code_count;
  size_t recent_code_next;
} DazeUnicornEngine;

typedef struct {
  uint8_t interrupt_number;
  int stopped;
  int continue_run;
  int use_resume_address;
  uint64_t resume_address;
  int host_dos_gate;
  int raw_pm_wrapper_written;
  int raw_pm_32_wrapper_written;
  int raw_vector_snapshot_valid;
  int raw_vector_snapshot_child_active;
  uint16_t raw_vector_snapshot_allocation_segment;
  uint16_t raw_vector_snapshot_segment[256];
  uint16_t raw_vector_snapshot_offset[256];
  DazeRawVectorProjection raw_vector_projections[DAZE_RAW_VECTOR_PROJECTION_MAX];
  int rm_procedure_active;
  int rm_procedure_32bit_reentry;
  int interrupt_already_advanced;
  int terminated;
  uint8_t exit_code;
  DpmiAlternateState rm_procedure_pm_state;
  uint32_t rm_procedure_frame_address;
  DazeProtectedDosContinuation dos_continuation;
  DazeDpmiExceptionTransferStack exception_delivery_stack;
} DazeUnicornRunState;

typedef struct {
  DazeDpmiProcessState dpmi;
  DazeDosProcessState dos_process;
  DazeDosChildProcess child_process;
  DazeDosMemory dos_memory;
  uint32_t resident_image_end;
} DazeDosRuntimeProcessState;

typedef struct DazeUnicornContext {
  DazeUnicornEngine engine;
  DazeUnicornRunState run;
  DazeDosRuntimeProcessState process;
} DazeUnicornContext;

typedef struct {
  DazeUnicornContext *context;
  DazeDosfsFileService *files;
} DazeUnicornInterruptContext;

/* Hooks execute in later emulation runs; heap context is owned and freed by the
 * exception delivery. */
struct DazeUnicornExceptionHookContext {
  DazeUnicornRunState *run;
  DazeUnicornEngine *engine;
  DazeDpmiProcessState *dpmi;
};

/* The hook executes in a later emulation run; heap context is owned and freed by the
 * continuation. */
typedef struct {
  DazeUnicornRunState *run;
  DazeUnicornEngine *engine;
  DazeDosRuntimeProcessState *process;
  DazeDosfsFileService *files;
} DazeUnicornContinuationContext;

/* Withdraw descriptors created for owned raw-vector targets before their DOS
 * allocation is released. It leaves unrelated LDT slots untouched. */
int daze_withdraw_raw_vector_projections(uc_engine *uc, DazeUnicornRunState *run,
                                         DazeMetrics *metrics, uint16_t allocation_segment);

DazeDpmiExceptionTransfer *daze_dpmi_exception_active(DazeUnicornRunState *run);
DazeDpmiExceptionTransfer *daze_dpmi_exception_record(DazeUnicornRunState *run, unsigned depth);

#include "unicorn_registers.h"

#endif
