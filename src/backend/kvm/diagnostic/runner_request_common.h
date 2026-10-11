#ifndef DAZE_KVM_RUNNER_REQUEST_COMMON_H
#define DAZE_KVM_RUNNER_REQUEST_COMMON_H

#include "dosfs.h"
#include "file_service.h"
#include "image.h"
#include "mz_layout.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int valid;
  uint32_t cr0;
  uint16_t ax, bx, cx, dx, si, di, bp;
  uint16_t cs, ip, ds, es, fs, gs, ss, sp, flags;
} DazeKvmRealModeEntrySnapshot;

typedef struct {
  int valid;
  uint8_t vector;
  uint16_t ax, bx, cx, dx, si, di, ds, es, flags;
  uint16_t return_cs, return_ip;
  uint16_t caller_return_cs, caller_return_ip;
  DazeKvmRealModeEntrySnapshot entry_snapshot;
} DazeKvmRunnerDpmiHandoff;

typedef struct {
  uint8_t vector;
  uint16_t ax, bx, cx, dx, si, di, ds, es, flags;
  uint16_t return_cs, return_ip;
} DazeKvmRunnerRequestImage;

/* Embedded first so runner requests share one launch description. */
typedef struct DazeKvmRunnerRequestCommon {
  const DazeImage *image;
  const DazeMzHeader *header;
  const char *command_tail;
  const char *guest_path;
  /* An EXEC child supplies its DOS-built PSP rather than the direct-launch
   * PSP. The bytes are caller-owned and must stay live through bootstrap. */
  const uint8_t *psp_override;
  uint16_t initial_ax, initial_bx, initial_cx, initial_dx, initial_si, initial_di;
  int preserve_initial_gprs;
  int exec_child;
  uint16_t psp_segment, environment_segment, dpmi_entry_segment, dos_vector_segment, load_segment;
  uint32_t guest_size, stop_linear;
  const DazeDosfsMounts *mounts;
  DazeDosfsHandles *handles;
  DazeDosfsFileService *files;
  const char *const *env_vars;
  int env_var_count;
} DazeKvmRunnerRequestCommon;

#endif
