#include "boundary.h"

#include "interrupt_vector.h"
#include "mediator.h"
#include "port.h"
#include "raw_switch.h"
#include "kvm_state_save_gate.h"

DazeKvmCommandBoundaryKind
daze_kvm_command_boundary_classify(const DazeKvmDpmiEntryResult *boundary) {
  if (boundary == NULL || boundary->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
      boundary->observation.pio_direction != DAZE_KVM_DPMI_ENTRY_PIO_OUT ||
      boundary->observation.pio_size != 1 || boundary->observation.pio_count != 1 ||
      !boundary->observation.pio_value_present)
    return DAZE_KVM_COMMAND_BOUNDARY_OTHER;
  if (boundary->observation.pio_port != DAZE_PORT_GATE) return DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED;
  switch ((uint8_t)boundary->observation.pio_value) {
  case DAZE_KVM_DPMI_MEDIATOR_MARKER:
    return DAZE_KVM_COMMAND_BOUNDARY_MEDIATOR;
  case DAZE_KVM_STATE_SAVE_GATE_MARKER:
    return DAZE_KVM_COMMAND_BOUNDARY_STATE;
  case DAZE_KVM_RAW_SWITCH_GATE_MARKER:
    return DAZE_KVM_COMMAND_BOUNDARY_RAW;
  case DAZE_INT_BIOS_VIDEO:
  case DAZE_INT_BIOS_EQUIPMENT:
  case DAZE_INT_BIOS_TIME:
  case DAZE_INT_DOS:
  case DAZE_INT_MULTIPLEX:
  case DAZE_INT_DPMI_ENTRY:
    return DAZE_KVM_COMMAND_BOUNDARY_RUNNER;
  default:
    return DAZE_KVM_COMMAND_BOUNDARY_UNSUPPORTED;
  }
}
