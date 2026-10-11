#include "int21_service.h"

#include "kvm_bytes.h"
#include "runner_private.h"

#include <stdio.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

enum {
  RECORD_SIZE = 24,
};

typedef struct {
  const char *name;
  uint16_t ax;
  uint16_t bx;
  uint16_t cx;
} Scenario;

static uint16_t read_low16(uc_engine *uc, int reg) {
  uint32_t value = 0;
  if (uc_reg_read(uc, reg, &value) != UC_ERR_OK) return 0;
  return (uint16_t)value;
}

static int write_low16(uc_engine *uc, int reg, uint16_t value) {
  uint32_t full = 0;
  if (uc_reg_read(uc, reg, &full) != UC_ERR_OK) return 0;
  full = (full & 0xffff0000u) | value;
  return uc_reg_write(uc, reg, &full) == UC_ERR_OK;
}

static int capture_unicorn_request(uc_engine *uc, DazeDosInt21Request *request) {
  uint32_t flags = 0;
  if (uc == NULL || request == NULL || uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags) != UC_ERR_OK)
    return 0;
  *request = (DazeDosInt21Request){
    .ax = read_low16(uc, UC_X86_REG_EAX),
    .bx = read_low16(uc, UC_X86_REG_EBX),
    .cx = read_low16(uc, UC_X86_REG_ECX),
    .dx = read_low16(uc, UC_X86_REG_EDX),
    .si = read_low16(uc, UC_X86_REG_ESI),
    .di = read_low16(uc, UC_X86_REG_EDI),
    .ds = read_low16(uc, UC_X86_REG_DS),
    .es = read_low16(uc, UC_X86_REG_ES),
    .flags = (uint16_t)flags,
  };
  return 1;
}

static int apply_unicorn_result(uc_engine *uc, const DazeDosInt21Result *result) {
  if (uc == NULL || result == NULL) return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_AX) != 0 &&
      !write_low16(uc, UC_X86_REG_EAX, result->ax))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_BX) != 0 &&
      !write_low16(uc, UC_X86_REG_EBX, result->bx))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_CX) != 0 &&
      !write_low16(uc, UC_X86_REG_ECX, result->cx))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DX) != 0 &&
      !write_low16(uc, UC_X86_REG_EDX, result->dx))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_SI) != 0 &&
      !write_low16(uc, UC_X86_REG_ESI, result->si))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DI) != 0 &&
      !write_low16(uc, UC_X86_REG_EDI, result->di))
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DS) != 0 &&
      uc_reg_write(uc, UC_X86_REG_DS, &result->ds) != UC_ERR_OK)
    return 0;
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_ES) != 0 &&
      uc_reg_write(uc, UC_X86_REG_ES, &result->es) != UC_ERR_OK)
    return 0;
  uint32_t flags = 0;
  if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags) != UC_ERR_OK) return 0;
  flags =
    (flags & ~(uint32_t)result->flag_write_mask) | (result->flag_values & result->flag_write_mask);
  return uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags) == UC_ERR_OK;
}

static void encode_kvm_record(const DazeDosInt21Request *request, uint8_t record[RECORD_SIZE]) {
  memset(record, 0, RECORD_SIZE);
  daze_write_u16(record, request->ax);
  daze_write_u16(record + 2, request->bx);
  daze_write_u16(record + 4, request->cx);
  daze_write_u16(record + 6, request->dx);
  daze_write_u16(record + 8, request->ds);
  daze_write_u16(record + 10, request->es);
  daze_write_u16(record + 12, request->si);
  daze_write_u16(record + 14, request->di);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, request->flags);
}

/* This intentionally receives accounting state but never changes it: shared
 * DOS reply marshalling is not allowed to own KVM broker observations. */
static int apply_kvm_result(const uint8_t record[RECORD_SIZE],
                            uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE],
                            const DazeDosInt21Result *result,
                            DazeKvmPreflightBoundaryResult *accounting) {
  (void)accounting;
  if (record == NULL || mailbox == NULL || result == NULL) return 0;
  daze_kvm_runner_gate_reply_init(record, mailbox);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_AX) != 0)
    daze_write_u16(mailbox, result->ax);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_BX) != 0)
    daze_write_u16(mailbox + 2, result->bx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_CX) != 0)
    daze_write_u16(mailbox + 4, result->cx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DX) != 0)
    daze_write_u16(mailbox + 6, result->dx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_SI) != 0)
    daze_write_u16(mailbox + 8, result->si);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DI) != 0)
    daze_write_u16(mailbox + 10, result->di);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_ES) != 0)
    daze_write_u16(mailbox + 12, result->es);
  uint16_t flags = daze_read_u16(mailbox + 14);
  flags = (uint16_t)((flags & (uint16_t)~result->flag_write_mask) |
                     (result->flag_values & result->flag_write_mask));
  daze_write_u16(mailbox + 14, flags);
  return 1;
}

static int initialize_unicorn(uc_engine **engine, const DazeDosInt21Request *request) {
  if (engine == NULL || request == NULL || uc_open(UC_ARCH_X86, UC_MODE_32, engine) != UC_ERR_OK)
    return 0;
  const uint32_t eax = 0xaabb0000u | request->ax;
  const uint32_t ebx = 0xccdd0000u | request->bx;
  const uint32_t ecx = 0xeeff0000u | request->cx;
  const uint32_t edx = 0x11220000u | request->dx;
  const uint32_t esi = 0x33440000u | request->si;
  const uint32_t edi = 0x55660000u | request->di;
  const uint32_t flags = request->flags;
  return uc_reg_write(*engine, UC_X86_REG_EAX, &eax) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_EBX, &ebx) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_ECX, &ecx) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_EDX, &edx) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_ESI, &esi) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_EDI, &edi) == UC_ERR_OK &&
         uc_reg_write(*engine, UC_X86_REG_EFLAGS, &flags) == UC_ERR_OK;
}

static int verify_transports(const char *name, const DazeDosInt21Request *request,
                             const DazeDosInt21Result *result) {
  int pass = 1;
  const uint16_t expected_ax =
    (result->register_write_mask & DAZE_DOS_INT21_REG_AX) != 0 ? result->ax : request->ax;
  const uint16_t expected_bx =
    (result->register_write_mask & DAZE_DOS_INT21_REG_BX) != 0 ? result->bx : request->bx;
  const uint16_t expected_cx =
    (result->register_write_mask & DAZE_DOS_INT21_REG_CX) != 0 ? result->cx : request->cx;
  const uint16_t expected_dx =
    (result->register_write_mask & DAZE_DOS_INT21_REG_DX) != 0 ? result->dx : request->dx;
  const uint16_t expected_flags = (uint16_t)((request->flags & (uint16_t)~result->flag_write_mask) |
                                             (result->flag_values & result->flag_write_mask));
  const uint16_t expected_flag_bits =
    (uint16_t)(expected_flags & (DAZE_DOS_INT21_FLAG_CF | DAZE_DOS_INT21_FLAG_ZF));
  uc_engine *unicorn = NULL;
  DazeDosInt21Request captured;
  if (!initialize_unicorn(&unicorn, request) || !capture_unicorn_request(unicorn, &captured) ||
      memcmp(&captured, request, sizeof(captured)) != 0 || !apply_unicorn_result(unicorn, result) ||
      read_low16(unicorn, UC_X86_REG_EAX) != expected_ax ||
      read_low16(unicorn, UC_X86_REG_EBX) != expected_bx ||
      read_low16(unicorn, UC_X86_REG_ECX) != expected_cx ||
      read_low16(unicorn, UC_X86_REG_EDX) != expected_dx ||
      (read_low16(unicorn, UC_X86_REG_EFLAGS) &
       (DAZE_DOS_INT21_FLAG_CF | DAZE_DOS_INT21_FLAG_ZF)) != expected_flag_bits) {
    fprintf(stderr, "%s: Unicorn adapter mismatch\n", name);
    pass = 0;
  }
  uint32_t eax = 0;
  if (unicorn == NULL || uc_reg_read(unicorn, UC_X86_REG_EAX, &eax) != UC_ERR_OK ||
      (eax & 0xffff0000u) != 0xaabb0000u) {
    fprintf(stderr, "%s: Unicorn high AX word changed\n", name);
    pass = 0;
  }
  if (unicorn != NULL) uc_close(unicorn);

  uint8_t record[RECORD_SIZE];
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE];
  DazeKvmPreflightBoundaryResult accounting;
  DazeKvmPreflightBoundaryResult expected_accounting;
  encode_kvm_record(request, record);
  memset(mailbox, 0xff, sizeof(mailbox));
  memset(&accounting, 0xa5, sizeof(accounting));
  expected_accounting = accounting;
  if (!apply_kvm_result(record, mailbox, result, &accounting) ||
      daze_read_u16(mailbox) != expected_ax || daze_read_u16(mailbox + 2) != expected_bx ||
      daze_read_u16(mailbox + 4) != expected_cx || daze_read_u16(mailbox + 6) != expected_dx ||
      daze_read_u16(mailbox + 8) != request->si || daze_read_u16(mailbox + 10) != request->di ||
      daze_read_u16(mailbox + 12) != request->es ||
      (daze_read_u16(mailbox + 14) & (DAZE_DOS_INT21_FLAG_CF | DAZE_DOS_INT21_FLAG_ZF)) !=
        expected_flag_bits ||
      memcmp(&accounting, &expected_accounting, sizeof(accounting)) != 0) {
    fprintf(stderr, "%s: KVM mailbox adapter mismatch\n", name);
    pass = 0;
  }
  return pass;
}

int main(void) {
  int pass = 1;
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeDosProcessState process_state;
  DazeDosMemory dos_memory;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  if (daze_dosfs_handles_bind_standard(&handles, 0, 1, 2, NULL) != DAZE_DOSFS_OK) return 1;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dos_process_state_init(&process_state, 0x0ff0);
  daze_dos_memory_init(&dos_memory, 0x1000, 0xa000);
  const DazeDosInt21Context context = {
    .files = &files,
    .process_state = &process_state,
    .dos_memory = &dos_memory,
    .dbcs_table_segment = 0x0600,
  };
  static const Scenario scenarios[] = {
    {.name = "console status", .ax = 0x0b5a, .bx = 0x1234, .cx = 0x9abc},
    {.name = "current drive", .ax = 0x1900, .bx = 0x5678, .cx = 0x9abc},
    {.name = "set DTA", .ax = 0x1a00, .bx = 0x5678, .cx = 0x9abc},
    {.name = "ioctl valid handle", .ax = 0x4400, .bx = 0, .cx = 0x9abc},
    {.name = "ioctl invalid handle", .ax = 0x4400, .bx = 99, .cx = 0x9abc},
    {.name = "force duplicate valid handles", .ax = 0x4600, .bx = 0, .cx = 5},
    {.name = "force duplicate invalid handle", .ax = 0x4600, .bx = 99, .cx = 6},
    {.name = "file time valid handle", .ax = 0x5700, .bx = 0, .cx = 0x9abc},
    {.name = "file time invalid handle", .ax = 0x5700, .bx = 99, .cx = 0x9abc},
    {.name = "set file time valid handle", .ax = 0x5701, .bx = 0, .cx = 0x9abc},
    {.name = "set file time invalid handle", .ax = 0x5701, .bx = 99, .cx = 0x9abc},
    {.name = "handle count accepted", .ax = 0x6700, .bx = DAZE_DOSFS_MAX_HANDLES, .cx = 0x9abc},
    {.name = "handle count rejected", .ax = 0x6700, .bx = DAZE_DOSFS_MAX_HANDLES + 1, .cx = 0x9abc},
  };

  for (size_t index = 0; index < sizeof(scenarios) / sizeof(scenarios[0]); ++index) {
    const Scenario *scenario = scenarios + index;
    const DazeDosInt21Request request = {
      .ax = scenario->ax,
      .bx = scenario->bx,
      .cx = scenario->cx,
      .dx = 0xdef0,
      .si = 0x1357,
      .di = 0x2468,
      .ds = 0,
      .es = 0,
      .flags = 0x0203,
    };
    DazeDosInt21Result result;
    if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
        result.disposition != DAZE_DOS_INT21_HANDLED ||
        !verify_transports(scenario->name, &request, &result)) {
      pass = 0;
    }
  }

  daze_dos_process_state_record_child_termination(&process_state, 7, 3);
  const DazeDosInt21Request child_status_request = {
    .ax = 0x4d00,
    .bx = 0x5678,
    .cx = 0x9abc,
    .dx = 0xdef0,
    .si = 0x1357,
    .di = 0x2468,
    .flags = 0x0203,
  };
  DazeDosInt21Result child_status_result;
  if (daze_dos_int21_dispatch(&context, &child_status_request, &child_status_result) !=
        DAZE_DOS_INT21_DISPATCH_OK ||
      child_status_result.disposition != DAZE_DOS_INT21_HANDLED ||
      child_status_result.ax != 0x0307 ||
      !verify_transports("child status", &child_status_request, &child_status_result)) {
    pass = 0;
  }

  const DazeDosInt21Request flags_request = {
    .ax = 0x9999,
    .bx = 0x8888,
    .cx = 0x7777,
    .dx = 0x6666,
    .si = 0x5555,
    .di = 0x4444,
    .ds = 0,
    .es = 0,
    .flags = 0x0203,
  };
  const DazeDosInt21Result flags_result = {
    .disposition = DAZE_DOS_INT21_HANDLED,
    .flag_write_mask = DAZE_DOS_INT21_FLAG_CF | DAZE_DOS_INT21_FLAG_ZF,
    .flag_values = DAZE_DOS_INT21_FLAG_ZF,
  };
  if (!verify_transports("independent CF/ZF", &flags_request, &flags_result)) {
    pass = 0;
  }

  daze_dos_process_state_dispose(&process_state);
  daze_dosfs_handles_close_all(&handles);
  if (!pass) return 1;
  puts("int21 adapter: passed");
  return 0;
}
