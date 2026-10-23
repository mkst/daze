#include "runner_private.h"

#include "kvm_bytes.h"
#include "runner_resume.h"

#include <stdio.h>

static void frame_record(const DazeKvmRunnerGateFrame *frame, uint8_t record[24]) {
  daze_write_u16(record, frame->ax);
  daze_write_u16(record + 2, frame->bx);
  daze_write_u16(record + 4, frame->cx);
  daze_write_u16(record + 6, frame->dx);
  daze_write_u16(record + 8, frame->ds);
  daze_write_u16(record + 10, frame->es);
  daze_write_u16(record + 12, frame->si);
  daze_write_u16(record + 14, frame->di);
  daze_write_u16(record + 16, frame->vector);
  daze_write_u16(record + 18, frame->return_ip);
  daze_write_u16(record + 20, frame->return_cs);
  daze_write_u16(record + 22, frame->flags);
}

int main(void) {
  /* The EXEC request parks at the runner's 21h gate. After its synthetic
   * success reply, this image immediately asks DOS to terminate. */
  static uint8_t bytes[0x2a] = {
    'M',  'Z',  0x2a, 0, 1, 0, 0,    0, 2, 0, 0, 0, 0, 0, 0,    0, 0xfe, 0xff,
    0,    0,    0,    0, 0, 0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0xb8, 0, 0x4b, /* mov ax,0x4b00 */
    0xcd, 0x21,                                                          /* int 0x21 */
    0xb8, 0,    0x4c,                                                    /* mov ax,0x4c00 */
    0xcd, 0x21};                                                         /* int 0x21 */
  static DazeImage image = {bytes, sizeof(bytes)};
  static DazeMzHeader header = {.header_paragraphs = 2,
                                .initial_sp = 0xfffe,
                                .module_size = sizeof(bytes),
                                .image_offset = 0x20,
                                .image_size = 10,
                                .relocation_offset = 0x1c};
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  const DazeKvmRunnerGenericPreflightRequest request = {
    .process = {.image = &image,
                .header = &header,
                .command_tail = "",
                .guest_path = "C:\\TOOL.EXE",
                .psp_segment = 0x0100,
                .environment_segment = 0x0200,
                .dpmi_entry_segment = 0x0300,
                .dos_vector_segment = 0x0400,
                .load_segment = 0x0500,
                .guest_size = 0x40000,
                .mounts = &mounts,
                .handles = &handles,
                .files = &files},
  };
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, request.process.guest_size);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;

  DazeKvmRunnerGenericPreflightResult first;
  if (daze_kvm_runner_preflight_to_generic_boundary(&machine, &request, &first) !=
        DAZE_KVM_GENERIC_PREFLIGHT_EXEC ||
      first.request_vector != 0x21 || first.request_ax != 0x4b00) {
    fprintf(stderr, "initial request=%02x/%04x disposition=%d\n", first.request_vector,
            first.request_ax, first.disposition);
    daze_kvm_machine_destroy(&machine);
    return 1;
  }

  const uint32_t command_tail = ((uint32_t)request.process.psp_segment << 4) + 0x80;
  ((uint8_t *)machine.guest)[command_tail] = 0x7b;
  DazeDosProcessState process_state;
  daze_dos_process_state_init(&process_state, request.process.psp_segment);
  daze_dos_process_state_seed_vectors(&process_state, request.process.dos_vector_segment);
  daze_dos_process_state_set_dta(&process_state, 0x1234, 0x5678);
  DazeDosMemory dos_memory;
  daze_dos_memory_init(&dos_memory, 0x3000, 0xa000);
  DazeDosAllocation *const allocation = daze_dos_memory_allocate(&dos_memory, 8);

  DazeKvmRunnerGateFrame frame;
  uint8_t record[24] = {0};
  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
  const int reply_status =
    daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) == DAZE_KVM_RUNNER_GATE_RESUME_OK
      ? (frame_record(&frame, record), daze_kvm_runner_gate_reply_init(record, reply),
         daze_write_u16(reply, 0),
         daze_write_u16(reply + 14, (uint16_t)(daze_read_u16(reply + 14) & ~1u)),
         daze_kvm_runner_gate_frame_reply(&machine, &frame, reply))
      : DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  DazeKvmRunnerGenericPreflightResult resumed;
  const int status = reply_status == DAZE_KVM_RUNNER_GATE_RESUME_OK
                       ? daze_kvm_runner_resume_to_generic_boundary(
                           &machine, &request, &process_state, &dos_memory, &resumed)
                       : DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
  const int valid =
    allocation != NULL && status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED &&
    resumed.request_vector == 0x21 && resumed.request_ax == 0x4c00 &&
    ((const uint8_t *)machine.guest)[command_tail] == 0x7b && process_state.dta_segment == 0x1234 &&
    process_state.dta_offset == 0x5678 && dos_memory.allocations[0].in_use &&
    dos_memory.allocations[0].segment == 0x3000 && dos_memory.allocations[0].paragraphs == 8;
  const uint8_t sentinel = ((const uint8_t *)machine.guest)[command_tail];
  daze_kvm_machine_destroy(&machine);
  if (!valid) {
    fprintf(stderr, "resume reply=%d status=%d request=%02x/%04x sentinel=%02x dta=%04x:%04x\n",
            reply_status, status, resumed.request_vector, resumed.request_ax, sentinel,
            process_state.dta_segment, process_state.dta_offset);
    return 1;
  }
  puts("KVM runner existing resume: passed");
  return 0;
}
