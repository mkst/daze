#ifndef DAZE_DOS_INT21_SERVICE_H
#define DAZE_DOS_INT21_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "dosfs.h"
#include "file_service.h"
#include "file_time.h"
#include "file_attrs.h"
#include "fcb.h"
#include "find_result.h"
#include "memory.h"
#include "process_state.h"

typedef struct {
  uint16_t ax;
  uint16_t bx;
  uint16_t cx;
  uint16_t dx;
  uint16_t si;
  uint16_t di;
  uint16_t ds;
  uint16_t es;
  uint16_t flags;
} DazeDosInt21Request;

enum {
  DAZE_DOS_INT21_REG_AX = 1u << 0,
  DAZE_DOS_INT21_REG_BX = 1u << 1,
  DAZE_DOS_INT21_REG_CX = 1u << 2,
  DAZE_DOS_INT21_REG_DX = 1u << 3,
  DAZE_DOS_INT21_REG_SI = 1u << 4,
  DAZE_DOS_INT21_REG_DI = 1u << 5,
  DAZE_DOS_INT21_REG_DS = 1u << 6,
  DAZE_DOS_INT21_REG_ES = 1u << 7,
};

enum {
  DAZE_DOS_INT21_FLAG_CF = 1u << 0,
  DAZE_DOS_INT21_FLAG_ZF = 1u << 6,
};

typedef enum {
  DAZE_DOS_INT21_HANDLED = 0,
  DAZE_DOS_INT21_UNSUPPORTED = 1,
  DAZE_DOS_INT21_TERMINATED = 2,
  DAZE_DOS_INT21_EXEC = 3,
} DazeDosInt21Disposition;

/* `register_write_mask` and `flag_write_mask` make preservation explicit:
 * fields not selected remain exactly as the backend captured them. */
typedef struct {
  DazeDosInt21Disposition disposition;
  /* Meaningful only for DAZE_DOS_INT21_TERMINATED. This is service detail,
   * not an AX write: adapters retain ownership of their terminal mechanics. */
  uint8_t termination_status;
  uint16_t register_write_mask;
  uint16_t flag_write_mask;
  uint16_t flag_values;
  uint16_t ax;
  uint16_t bx;
  uint16_t cx;
  uint16_t dx;
  uint16_t si;
  uint16_t di;
  uint16_t ds;
  uint16_t es;
} DazeDosInt21Result;

typedef int (*DazeDosInt21GuestRead)(void *context, uint16_t segment, uint16_t offset, void *bytes,
                                     size_t size);
typedef int (*DazeDosInt21GuestWrite)(void *context, uint16_t segment, uint16_t offset,
                                      const void *bytes, size_t size);

typedef struct {
  void *context;
  DazeDosInt21GuestRead read;
  DazeDosInt21GuestWrite write;
} DazeDosInt21GuestMemory;

/* observed runs after host I/O; completed runs only after its guest-memory effect
 * succeeds. */
typedef void (*DazeDosInt21TransferHook)(void *context, const DazeDosInt21Request *request,
                                         const DazeDosfsFileResult *file);

typedef int (*DazeDosInt21PreReleaseHook)(void *context, uint16_t allocation_segment);

/* State and callback contexts are borrowed from the caller. Adapters own
 * guest-memory access, lifecycle hooks, and execution/resume mechanics. */
typedef struct {
  DazeDosfsFileService *files;
  DazeDosProcessState *process_state;
  DazeDosMemory *dos_memory;
  DazeDosInt21PreReleaseHook pre_release;
  void *pre_release_context;
  DazeDosInt21GuestMemory guest_memory;
  DazeDosInt21TransferHook transfer_observed;
  DazeDosInt21TransferHook transfer_completed;
  void *transfer_context;
  uint16_t indos_segment;
  uint16_t indos_offset;
  uint16_t dbcs_table_segment;
  uint16_t sda_segment;
  uint16_t sda_offset;
} DazeDosInt21Context;

typedef enum {
  DAZE_DOS_INT21_DISPATCH_OK = 1,
  DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT = 0,
  DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE = -1,
} DazeDosInt21DispatchStatus;

int daze_dos_int21_is_shared_function(uint8_t ah);

/* Dispatches the admitted shared subset. Unsupported functions return an
 * UNSUPPORTED result with no register or flag writes. */
DazeDosInt21DispatchStatus daze_dos_int21_dispatch(const DazeDosInt21Context *context,
                                                   const DazeDosInt21Request *request,
                                                   DazeDosInt21Result *result);

#endif
