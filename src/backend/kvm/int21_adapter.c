#include "int21_adapter.h"

#include "dos_function.h"
#include "int21_service.h"
#include "interrupt_vector.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "machine_access.h"

#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

static void reply_carry(uint8_t *mailbox, int carry) {
  uint16_t flags = daze_read_u16(mailbox + 14);
  flags = carry ? (uint16_t)(flags | 1u) : (uint16_t)(flags & ~1u);
  daze_write_u16(mailbox + 14, flags);
}

static DazeDosInt21Request int21_request_from_record(const uint8_t record[24]) {
  return (DazeDosInt21Request){
    .ax = daze_read_u16(record),
    .bx = daze_read_u16(record + 2),
    .cx = daze_read_u16(record + 4),
    .dx = daze_read_u16(record + 6),
    .ds = daze_read_u16(record + 8),
    .es = daze_read_u16(record + 10),
    .si = daze_read_u16(record + 12),
    .di = daze_read_u16(record + 14),
    .flags = daze_read_u16(record + 22),
  };
}

static int apply_int21_result_to_mailbox(uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE],
                                         const DazeDosInt21Result *result) {
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
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DS) != 0) return 0;
  uint16_t flags = daze_read_u16(mailbox + 14);
  flags = (uint16_t)((flags & (uint16_t)~result->flag_write_mask) |
                     (result->flag_values & result->flag_write_mask));
  daze_write_u16(mailbox + 14, flags);
  return 1;
}

typedef struct {
  const DazeKvmMachine *machine;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct kvm_sregs sregs;
#endif
} DazeInt21KvmGuestMemory;

static int int21_kvm_guest_address(const DazeInt21KvmGuestMemory *memory, uint16_t segment,
                                   uint16_t offset, size_t size, uint32_t *address) {
  if (memory == NULL || memory->machine == NULL || memory->machine->guest == NULL ||
      address == NULL)
    return 0;
  uint64_t base = (uint32_t)segment << 4;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if ((memory->sregs.cr0 & 1u) != 0) {
    const struct kvm_segment *segments[] = {
      &memory->sregs.ds, &memory->sregs.es, &memory->sregs.fs,
      &memory->sregs.gs, &memory->sregs.ss, &memory->sregs.cs,
    };
    int matched = 0;
    for (size_t index = 0; index < sizeof(segments) / sizeof(segments[0]); ++index) {
      if ((uint16_t)segments[index]->selector == segment) {
        base = segments[index]->base;
        matched = 1;
        break;
      }
    }
    if (!matched && segment != k_dos_int21_vector_segment && segment != 0x0600) return 0;
  }
#endif
  if (base > UINT32_MAX || offset > UINT32_MAX - (uint32_t)base ||
      !daze_kvm_range_fits(memory->machine->guest_size, (uint32_t)base + offset, size))
    return 0;
  *address = (uint32_t)base + offset;
  return 1;
}

static int int21_kvm_guest_read(void *context, uint16_t segment, uint16_t offset, void *bytes,
                                size_t size) {
  const DazeInt21KvmGuestMemory *memory = context;
  uint32_t address;
  if (!int21_kvm_guest_address(memory, segment, offset, size, &address)) return 0;
  memcpy(bytes, (const uint8_t *)memory->machine->guest + address, size);
  return 1;
}

static int int21_kvm_guest_write(void *context, uint16_t segment, uint16_t offset,
                                 const void *bytes, size_t size) {
  const DazeInt21KvmGuestMemory *memory = context;
  uint32_t address;
  if (!int21_kvm_guest_address(memory, segment, offset, size, &address)) return 0;
  memcpy((uint8_t *)memory->machine->guest + address, bytes, size);
  return 1;
}

typedef struct {
  DazeKvmPreflightBoundaryResult *accounting;
} DazeInt21KvmTransferContext;

static void int21_kvm_transfer_completed(void *context, const DazeDosInt21Request *request,
                                         const DazeDosfsFileResult *file) {
  DazeInt21KvmTransferContext *transfer = context;
  if (transfer == NULL || transfer->accounting == NULL || request == NULL || file == NULL) return;
  if ((uint8_t)(request->ax >> 8) == DAZE_DOS_READ ||
      (uint8_t)(request->ax >> 8) == DAZE_DOS_WRITE) {
    transfer->accounting->copied_byte_count = file->byte_count;
  }
}

static int dispatch_shared_int21_reply(DazeKvmMachine *machine, DazeDosfsFileService *files,
                                       DazeDosProcessState *process_state,
                                       DazeDosMemory *dos_memory, const uint8_t record[24],
                                       uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE],
                                       DazeKvmPreflightBoundaryResult *accounting) {
  const DazeDosInt21Request request = int21_request_from_record(record);
  const uint8_t function = (uint8_t)(request.ax >> 8);
  /* Vector installation still owns backend-specific guest state. */
  if (!daze_dos_int21_is_shared_function(function)) return 0;
  DazeInt21KvmGuestMemory guest_memory = {.machine = machine};
  if (machine == NULL) return -1;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  const int captured =
    machine->vcpu < 0 ||
    (machine->run != NULL
       ? daze_kvm_machine_get_sregs(machine, &guest_memory.sregs) == DAZE_KVM_MACHINE_OK
       : ioctl(machine->vcpu, KVM_GET_SREGS, &guest_memory.sregs) == 0);
  if (!captured) {
    if (machine->run != NULL) return -1;
    guest_memory.sregs = (struct kvm_sregs){0};
  }
#else
  if (machine->run != NULL) return -1;
#endif
  DazeInt21KvmTransferContext transfer = {.accounting = accounting};
  const DazeDosInt21Context context = {
    .files = files,
    .process_state = process_state,
    .dos_memory = dos_memory,
    .guest_memory = {.context = &guest_memory,
                     .read = int21_kvm_guest_read,
                     .write = int21_kvm_guest_write},
    .transfer_completed = int21_kvm_transfer_completed,
    .transfer_context = &transfer,
    .indos_segment = k_dos_int21_vector_segment,
    .indos_offset = k_dos_indos_offset,
    .dbcs_table_segment = 0x0600,
    .sda_segment = k_dos_int21_vector_segment,
    .sda_offset = k_dos_sda_offset,
  };
  DazeDosInt21Result result;
  if (daze_dos_int21_dispatch(&context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK) return -1;
  if (result.disposition == DAZE_DOS_INT21_UNSUPPORTED) return 0;
  if (result.disposition != DAZE_DOS_INT21_HANDLED) return -1;
  if ((result.register_write_mask & DAZE_DOS_INT21_REG_DS) != 0) {
    if (accounting != NULL) {
      accounting->reply_ds = result.ds;
      accounting->reply_ds_present = 1;
    }
    result.register_write_mask &= (uint16_t)~DAZE_DOS_INT21_REG_DS;
  }
  if (!apply_int21_result_to_mailbox(mailbox, &result)) return -1;
  if (accounting != NULL && (result.flag_values & DAZE_DOS_INT21_FLAG_CF) == 0) {
    switch ((uint8_t)(request.ax >> 8)) {
    case DAZE_DOS_CREATE:
    case DAZE_DOS_OPEN:
      accounting->file_handle = result.ax;
      break;
    case DAZE_DOS_SEEK:
      accounting->file_position = ((uint32_t)result.dx << 16) | result.ax;
      break;
    default:
      break;
    }
  }
  if ((uint8_t)(request.ax >> 8) == DAZE_DOS_RESIZE && accounting != NULL)
    accounting->resizes_served++;
  return 1;
}

static int classify_shared_int21_boundary(DazeDosfsFileService *files,
                                          DazeDosProcessState *process_state,
                                          DazeDosMemory *dos_memory, const uint8_t record[24],
                                          DazeDosInt21Result *result) {
  const DazeDosInt21Request request = int21_request_from_record(record);
  const DazeDosInt21Context context = {
    .files = files,
    .process_state = process_state,
    .dos_memory = dos_memory,
  };
  return daze_dos_int21_dispatch(&context, &request, result) == DAZE_DOS_INT21_DISPATCH_OK;
}

DazeKvmPreflightBoundaryDisposition daze_kvm_int21_dispatch(
  DazeKvmMachine *machine, DazeDosfsFileService *files, DazeDosProcessState *process_state,
  DazeDosMemory *dos_memory, const uint8_t record[24],
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE], DazeKvmPreflightBoundaryResult *result) {
  if (result != NULL) *result = (DazeKvmPreflightBoundaryResult){0};
  if (machine == NULL || machine->guest == NULL || files == NULL || record == NULL ||
      mailbox == NULL)
    return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  if ((uint8_t)daze_read_u16(record + 16) != DAZE_INT_DOS)
    return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
  const uint16_t ax = daze_read_u16(record);
  const uint16_t dx = daze_read_u16(record + 6);
  const uint16_t ds = daze_read_u16(record + 8);
  if ((ax >> 8) == DAZE_DOS_TERMINATE || (ax >> 8) == DAZE_DOS_TSR || (ax >> 8) == DAZE_DOS_EXEC) {
    DazeDosInt21Result classification;
    if (!classify_shared_int21_boundary(files, process_state, dos_memory, record, &classification))
      return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    if (classification.disposition == DAZE_DOS_INT21_TERMINATED) {
      return DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED;
    }
    if (classification.disposition == DAZE_DOS_INT21_EXEC) return DAZE_KVM_PREFLIGHT_BOUNDARY_EXEC;
  }
  daze_kvm_runner_gate_reply_init(record, mailbox);
  const int shared_reply =
    dispatch_shared_int21_reply(machine, files, process_state, dos_memory, record, mailbox, result);
  if (shared_reply != 0)
    return shared_reply > 0 ? DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED
                            : DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  switch (ax >> 8) {
  case DAZE_DOS_GET_VECTOR: {
    if (process_state == NULL) return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    const uint8_t vector = (uint8_t)ax;
    daze_write_u16(mailbox + 2, process_state->dos_vector_offset[vector]);
    daze_write_u16(mailbox + 12, process_state->dos_vector_segment[vector]);
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  case DAZE_DOS_FILE_ATTR:
    return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
  case DAZE_DOS_SET_VECTOR: {
    if (process_state == NULL) return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    const uint8_t vector = (uint8_t)ax;
    const uint32_t ivt = (uint32_t)vector * 4u;
    if (!daze_kvm_range_fits(machine->guest_size, ivt, 4))
      return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    daze_write_u16((uint8_t *)machine->guest + ivt, dx);
    daze_write_u16((uint8_t *)machine->guest + ivt + 2, ds);
    process_state->dos_vector_offset[vector] = dx;
    process_state->dos_vector_segment[vector] = ds;
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  default:
    return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
  }
}
