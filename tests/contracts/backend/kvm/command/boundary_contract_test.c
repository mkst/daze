#include "boundary.h"

static DazeKvmDpmiEntryResult boundary(uint16_t port, uint8_t value) {
  return (DazeKvmDpmiEntryResult){
    .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                    .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                    .pio_size = 1,
                    .pio_count = 1,
                    .pio_port = port,
                    .pio_value = value,
                    .pio_value_present = 1},
  };
}

int main(void) {
  DazeKvmDpmiEntryResult other = {0};
  const DazeKvmDpmiEntryResult shutdown = {.cs = 0xf000,
                                           .rip = 0xfff0,
                                           .rflags = 2,
                                           .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_OTHER}};
  const DazeKvmDpmiEntryResult mediator = boundary(0xf4, 0x31);
  const DazeKvmDpmiEntryResult state = boundary(0xf4, 0x17);
  const DazeKvmDpmiEntryResult raw = boundary(0xf4, 0x18);
  /* 0xa5 belongs to the diagnostic checkpoint runner, not the production
   * command-owner runner boundary. It must not make diagnostic machinery a
   * normal command-execution protocol. */
  const DazeKvmDpmiEntryResult diagnostic_runner = boundary(0xf4, 0xa5);
  const DazeKvmDpmiEntryResult unknown = boundary(0xf4, 0xff);
  const DazeKvmDpmiEntryResult wrong_port = boundary(0x1234, 0x31);
  return daze_kvm_command_boundary_classify(&mediator) != DAZE_KVM_COMMAND_BOUNDARY_MEDIATOR ||
         daze_kvm_command_boundary_classify(&state) != DAZE_KVM_COMMAND_BOUNDARY_STATE ||
         daze_kvm_command_boundary_classify(&raw) != DAZE_KVM_COMMAND_BOUNDARY_RAW ||
         daze_kvm_command_boundary_classify(&diagnostic_runner) !=
           DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED ||
         daze_kvm_command_boundary_classify(&unknown) != DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED ||
         daze_kvm_command_boundary_classify(&wrong_port) != DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED ||
         daze_kvm_command_boundary_classify(&shutdown) != DAZE_KVM_COMMAND_BOUNDARY_OTHER ||
         daze_kvm_command_boundary_classify(&other) != DAZE_KVM_COMMAND_BOUNDARY_OTHER;
}
