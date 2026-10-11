#ifndef DAZE_KVM_DPMI_MEDIATOR_TEST_DRIVER_H
#define DAZE_KVM_DPMI_MEDIATOR_TEST_DRIVER_H

#include "mediator.h"
#include "machine.h"

#include <stdint.h>

/* Test-only constructed guest layout shared by the mediator contract callers. */
typedef struct {
  uint32_t guest_size;
  uint32_t gdt_address;
  uint32_t gdt_size;
  uint32_t idt_address;
  uint32_t ldt_address;
  uint32_t ldt_size;
  uint32_t record_address;
  uint32_t mailbox_address;
  uint32_t capture_address;
} DazeKvmDpmiMediatorTestLayout;

enum {
  DAZE_KVM_DPMI_TEST_LDT_SIZE = 0x200,
  DAZE_KVM_DPMI_TEST_VECTOR_COUNT = 256,
  DAZE_KVM_DPMI_TEST_CAPTURE_AX_OFFSET = 0,
  DAZE_KVM_DPMI_TEST_CAPTURE_DI_OFFSET = 4,
  DAZE_KVM_DPMI_TEST_CAPTURE_ES_OFFSET = 8,
  DAZE_KVM_DPMI_TEST_CAPTURE_FLAGS_OFFSET = 12,
  DAZE_KVM_DPMI_TEST_CAPTURE_BX_OFFSET = 16,
  DAZE_KVM_DPMI_TEST_CAPTURE_CX_OFFSET = 20,
  DAZE_KVM_DPMI_TEST_CAPTURE_SI_OFFSET = 24,
  DAZE_KVM_DPMI_TEST_CAPTURE_DX_OFFSET = 28,
};

typedef struct {
  uint32_t initial_edi;
  uint16_t initial_es;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint16_t es;
  uint32_t eflags;
} DazeKvmDpmiMediatorTestSnapshot;

typedef struct {
  DazeKvmMachine machine;
  DazeKvmDpmiMediator mediator;
  DazeKvmDpmiMediatorTestLayout layout;
  DazeDpmiLinearMemory linear_memory;
  DazeDosMemory dos_memory;
  uint8_t ldt_used[DAZE_KVM_DPMI_TEST_LDT_SIZE / 8];
  uint16_t real_mode_vector_segment[DAZE_KVM_DPMI_TEST_VECTOR_COUNT];
  uint16_t real_mode_vector_offset[DAZE_KVM_DPMI_TEST_VECTOR_COUNT];
  int virtual_interrupts_enabled;
  int machine_initialized;
} DazeKvmDpmiMediatorTestFixture;

int daze_kvm_dpmi_mediator_test_fixture_init(DazeKvmDpmiMediatorTestFixture *fixture,
                                             DazeKvmDpmiStateSaveEndpoints state_save_endpoints,
                                             DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints);
void daze_kvm_dpmi_mediator_test_fixture_destroy(DazeKvmDpmiMediatorTestFixture *fixture);

/* Starts one live protected-mode INT 31h request and stops at the mediator
 * PIO boundary.  Kept public for the mediator contract's unsupported-row
 * atomicity check; normal callers should use run(). */
int daze_kvm_dpmi_mediator_test_begin(DazeKvmDpmiMediatorTestFixture *fixture,
                                      const DazeDpmiRequest *request, uint16_t *port,
                                      uint8_t *marker);

/* Executes the real PIO/record/mailbox/IRETD exchange and snapshots the
 * caller-visible state after the guest returns from INT 31h. */
int daze_kvm_dpmi_mediator_test_run(DazeKvmDpmiMediatorTestFixture *fixture,
                                    const DazeDpmiRequest *request,
                                    DazeKvmDpmiMediatorTestSnapshot *snapshot);

#endif
