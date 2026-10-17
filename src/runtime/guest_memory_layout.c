#include "guest_memory_layout.h"

#include "linear_memory.h"
#include "transition_artifacts.h"

#include <stddef.h>
#include <stdio.h>

static const char *const k_owner_names[DAZE_GUEST_OWNER_COUNT] = {
  "MZ image",
  "PSP",
  "environment",
  "DPMI entry stub",
  "DOS vector gate",
  "DOS IRET stub",
  "DOS SDA/InDOS",
  "DOS DBCS table",
  "BIOS configuration table",
  "DPMI GDT",
  "DPMI LDT",
  "DPMI locked stack",
  "KVM exception return",
  "KVM exception delivery",
  "DPMI client arena",
  "conventional allocator",
  "KVM runner gate arena",
  "KVM runner record",
  "KVM runner mailbox",
  "KVM RM return bridge",
  "KVM RM entry",
  "KVM write batch",
};

const char *daze_guest_owner_name(DazeGuestOwner owner) {
  if (owner < 0 || owner >= DAZE_GUEST_OWNER_COUNT) return "none";
  return k_owner_names[owner];
}

int daze_guest_layout_format_named(char *out, size_t out_size, const char *name, uint32_t address,
                                   uint32_t size) {
  if ((out == NULL && out_size != 0) || name == NULL) return -1;
  const uint64_t end = (uint64_t)address + size;
  return snprintf(out, out_size, "%s [%08x..%08llx)", name, address, (unsigned long long)end);
}

int daze_guest_layout_format_range(char *out, size_t out_size, DazeGuestRange range) {
  return daze_guest_layout_format_named(out, out_size, daze_guest_owner_name(range.owner),
                                        range.address, range.size);
}

int daze_guest_owner_persistent(DazeGuestOwner owner) {
  switch (owner) {
  case DAZE_GUEST_OWNER_PSP:
  case DAZE_GUEST_OWNER_ENVIRONMENT:
  case DAZE_GUEST_OWNER_DPMI_ENTRY_STUB:
  case DAZE_GUEST_OWNER_DPMI_GDT:
  case DAZE_GUEST_OWNER_DPMI_LDT:
  case DAZE_GUEST_OWNER_DPMI_LOCKED_STACK:
  case DAZE_GUEST_OWNER_KVM_EXCEPTION_RETURN:
  case DAZE_GUEST_OWNER_KVM_EXCEPTION_DELIVERY:
  case DAZE_GUEST_OWNER_KVM_RUNNER_GATE_ARENA:
  case DAZE_GUEST_OWNER_KVM_RUNNER_RECORD:
  case DAZE_GUEST_OWNER_KVM_RUNNER_MAILBOX:
  case DAZE_GUEST_OWNER_KVM_RM_RETURN_BRIDGE:
  case DAZE_GUEST_OWNER_KVM_RM_ENTRY:
  case DAZE_GUEST_OWNER_KVM_WRITE_BATCH:
    return 1;
  case DAZE_GUEST_OWNER_IMAGE:
  case DAZE_GUEST_OWNER_DOS_VECTOR_GATE:
  case DAZE_GUEST_OWNER_DOS_VECTOR_IRET:
  case DAZE_GUEST_OWNER_DOS_SDA:
  case DAZE_GUEST_OWNER_DOS_DBCS_TABLE:
  case DAZE_GUEST_OWNER_BIOS_CONFIG_TABLE:
  case DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA:
  case DAZE_GUEST_OWNER_CONVENTIONAL_ALLOCATOR:
  case DAZE_GUEST_OWNER_COUNT: /* == DAZE_GUEST_OWNER_NONE */
    return 0;
  }
  return 0;
}

int daze_guest_layout_init(DazeGuestLayout *layout) {
  if (layout == NULL) return 0;
  layout->count = 0;
  return 1;
}

static int add_range(DazeGuestLayout *layout, uint32_t address, uint32_t size,
                     DazeGuestOwner owner) {
  if (layout == NULL || layout->count >= DAZE_GUEST_LAYOUT_MAX_RANGES) return 0;
  layout->ranges[layout->count] = (DazeGuestRange){address, size, owner};
  layout->count++;
  return 1;
}

int daze_guest_layout_add_stable(DazeGuestLayout *layout) {
  if (layout == NULL) return 0;
  return add_range(layout, (uint32_t)k_psp_segment << 4, k_dos_psp_size, DAZE_GUEST_OWNER_PSP) &&
         add_range(layout, (uint32_t)k_dpmi_entry_segment << 4, k_dos_dpmi_entry_stub_size,
                   DAZE_GUEST_OWNER_DPMI_ENTRY_STUB) &&
         add_range(layout, (uint32_t)k_dos_int21_vector_segment << 4, k_dos_vector_gate_size,
                   DAZE_GUEST_OWNER_DOS_VECTOR_GATE) &&
         add_range(layout,
                   ((uint32_t)k_dos_int21_vector_segment << 4) + k_dos_vector_gate_iret_offset,
                   k_dos_vector_gate_iret_size, DAZE_GUEST_OWNER_DOS_VECTOR_IRET) &&
         add_range(layout, ((uint32_t)k_dos_int21_vector_segment << 4) + k_dos_sda_offset,
                   k_dos_sda_size, DAZE_GUEST_OWNER_DOS_SDA) &&
         add_range(layout, (uint32_t)k_dos_dbcs_table_segment << 4, k_dos_dbcs_table_size,
                   DAZE_GUEST_OWNER_DOS_DBCS_TABLE) &&
         add_range(layout, k_bios_config_table, k_bios_config_table_size,
                   DAZE_GUEST_OWNER_BIOS_CONFIG_TABLE) &&
         add_range(layout, k_dpmi_gdt_address, DAZE_DPMI_TRANSITION_GDT_SIZE,
                   DAZE_GUEST_OWNER_DPMI_GDT) &&
         add_range(layout, k_dpmi_ldt_address, DAZE_DPMI_TRANSITION_LDT_SIZE,
                   DAZE_GUEST_OWNER_DPMI_LDT) &&
         add_range(layout, k_dpmi_exception_locked_stack_base, k_dpmi_exception_locked_stack_size,
                   DAZE_GUEST_OWNER_DPMI_LOCKED_STACK) &&
         add_range(layout, k_kvm_exception_return_linear, k_kvm_exception_return_size,
                   DAZE_GUEST_OWNER_KVM_EXCEPTION_RETURN) &&
         add_range(layout, k_kvm_exception_delivery_linear, k_kvm_exception_delivery_size,
                   DAZE_GUEST_OWNER_KVM_EXCEPTION_DELIVERY) &&
         add_range(layout, k_dpmi_rm_return_bridge, k_dpmi_rm_return_bridge_size,
                   DAZE_GUEST_OWNER_KVM_RM_RETURN_BRIDGE) &&
         add_range(layout, k_dpmi_rm_entry_reserved_linear, k_dpmi_rm_entry_size,
                   DAZE_GUEST_OWNER_KVM_RM_ENTRY) &&
         add_range(layout, k_kvm_write_batch_code, k_kvm_write_batch_size,
                   DAZE_GUEST_OWNER_KVM_WRITE_BATCH);
}

int daze_guest_layout_add_image(DazeGuestLayout *layout, uint32_t image_address,
                                uint32_t image_size) {
  return add_range(layout, image_address, image_size, DAZE_GUEST_OWNER_IMAGE);
}

int daze_guest_layout_add_environment(DazeGuestLayout *layout, uint32_t environment_size) {
  return add_range(layout, (uint32_t)k_environment_segment << 4, environment_size,
                   DAZE_GUEST_OWNER_ENVIRONMENT);
}

int daze_guest_layout_add_dpmi_client_arena(DazeGuestLayout *layout, uint32_t first_base,
                                            uint32_t limit) {
  if (first_base >= limit) return 0;
  return add_range(layout, first_base, limit - first_base, DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA);
}

int daze_guest_layout_add_conventional_allocator(DazeGuestLayout *layout,
                                                 uint16_t allocation_start) {
  const uint32_t start = (uint32_t)allocation_start << 4;
  const uint32_t end = (uint32_t)k_dos_conventional_end_segment << 4;
  if (start > end) return 0;
  return add_range(layout, start, end - start, DAZE_GUEST_OWNER_CONVENTIONAL_ALLOCATOR);
}

int daze_guest_layout_add_kvm_runner(DazeGuestLayout *layout, uint32_t guest_size) {
  if (layout == NULL) return 0;
  const uint32_t gate = daze_kvm_runner_gate_linear(guest_size);
  const uint32_t record = daze_kvm_runner_gate_record_linear(guest_size);
  const uint32_t mailbox = daze_kvm_runner_gate_mailbox_linear(guest_size);
  return add_range(layout, gate, daze_kvm_runner_gate_end(guest_size) - gate,
                   DAZE_GUEST_OWNER_KVM_RUNNER_GATE_ARENA) &&
         add_range(layout, record, DAZE_KVM_RUNNER_GATE_RECORD_SIZE,
                   DAZE_GUEST_OWNER_KVM_RUNNER_RECORD) &&
         add_range(layout, mailbox, DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE,
                   DAZE_GUEST_OWNER_KVM_RUNNER_MAILBOX);
}

static void set_failure(DazeGuestLaunchFailure *failure, DazeGuestLaunchFailureKind kind,
                        DazeGuestRange first, DazeGuestRange second) {
  if (failure == NULL) return;
  failure->kind = kind;
  failure->first = first;
  failure->second = second;
}

static const DazeGuestRange k_no_range = {0, 0, DAZE_GUEST_OWNER_NONE};

int daze_guest_layout_validate_ranges(const DazeGuestRange *ranges, size_t count,
                                      uint32_t guest_size, DazeGuestLaunchFailure *failure) {
  if (ranges == NULL || guest_size == 0) {
    set_failure(failure, DAZE_GUEST_LAUNCH_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  for (size_t index = 0; index < count; ++index) {
    if (!daze_guest_range_fits(guest_size, ranges[index].address, ranges[index].size)) {
      set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST, ranges[index], k_no_range);
      return 0;
    }
  }
  for (size_t first = 0; first < count; ++first) {
    for (size_t second = 0; second < first; ++second) {
      if (daze_guest_ranges_overlap(ranges[first].address, ranges[first].size,
                                    ranges[second].address, ranges[second].size)) {
        set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OVERLAP, ranges[second], ranges[first]);
        return 0;
      }
    }
  }
  return 1;
}

/* Use 64-bit arithmetic until paragraph bounds are checked. */
static uint64_t expected_allocation_start(uint64_t image_end) {
  uint64_t paragraphs = (image_end + 15u) >> 4;
  if (paragraphs < k_dos_conventional_floor_segment) paragraphs = k_dos_conventional_floor_segment;
  if (paragraphs > k_dos_conventional_end_segment) paragraphs = k_dos_conventional_end_segment;
  return paragraphs;
}

int daze_guest_layout_build_launch(DazeGuestLayout *layout, const DazeGuestLaunchInput *input,
                                   uint16_t allocation_start, DazeGuestLaunchFailure *failure) {
  if (layout == NULL || input == NULL || input->guest_size == 0) {
    set_failure(failure, DAZE_GUEST_LAUNCH_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  if (input->image_size > UINT32_MAX) {
    set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST,
                (DazeGuestRange){input->image_address, UINT32_MAX, DAZE_GUEST_OWNER_IMAGE},
                k_no_range);
    return 0;
  }
  const uint32_t image_size = (uint32_t)input->image_size;
  const uint64_t image_end = (uint64_t)input->image_address + image_size;
  if (!daze_guest_range_fits(input->guest_size, input->image_address, image_size)) {
    set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST,
                (DazeGuestRange){input->image_address, image_size, DAZE_GUEST_OWNER_IMAGE},
                k_no_range);
    return 0;
  }
  const uint32_t resident_end = (uint32_t)image_end;
  uint32_t first_base = 0;
  if (!daze_dpmi_linear_memory_first_base_after(resident_end, input->linear_min_address,
                                                input->linear_limit, &first_base)) {
    set_failure(failure, DAZE_GUEST_LAUNCH_NO_LINEAR_ARENA,
                (DazeGuestRange){resident_end, 0, DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA}, k_no_range);
    return 0;
  }
  if (expected_allocation_start(image_end) != allocation_start) {
    const uint32_t start = (uint32_t)allocation_start << 4;
    const uint32_t end = (uint32_t)k_dos_conventional_end_segment << 4;
    const DazeGuestRange passed = {start, start <= end ? end - start : 0,
                                   DAZE_GUEST_OWNER_CONVENTIONAL_ALLOCATOR};
    set_failure(failure, DAZE_GUEST_LAUNCH_ALLOCATION_MISMATCH, passed, k_no_range);
    return 0;
  }
  if (input->environment_size > k_dos_environment_max_size) {
    set_failure(failure, DAZE_GUEST_LAUNCH_BAD_INPUT,
                (DazeGuestRange){(uint32_t)k_environment_segment << 4, k_dos_environment_max_size,
                                 DAZE_GUEST_OWNER_ENVIRONMENT},
                k_no_range);
    return 0;
  }
  uint32_t environment_size = (uint32_t)input->environment_size;
  if (!daze_guest_layout_init(layout) || !daze_guest_layout_add_stable(layout) ||
      layout->count != DAZE_GUEST_LAYOUT_STABLE_COUNT ||
      !daze_guest_layout_add_image(layout, input->image_address, image_size) ||
      !daze_guest_layout_add_environment(layout, environment_size) ||
      !daze_guest_layout_add_dpmi_client_arena(layout, first_base, input->linear_limit) ||
      !daze_guest_layout_add_conventional_allocator(layout, allocation_start)) {
    set_failure(failure, DAZE_GUEST_LAUNCH_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  return 1;
}

int daze_guest_launch_layout_valid(const DazeGuestLaunchInput *input, uint16_t allocation_start,
                                   DazeGuestLaunchFailure *failure) {
  DazeGuestLayout layout;
  if (!daze_guest_layout_build_launch(&layout, input, allocation_start, failure)) return 0;
  const uint32_t image_size = (uint32_t)input->image_size;
  DazeGuestLaunchFailure stable_failure = {DAZE_GUEST_LAUNCH_VALID, k_no_range, k_no_range};
  if (!daze_guest_layout_validate_ranges(layout.ranges, DAZE_GUEST_LAYOUT_STABLE_COUNT,
                                         input->guest_size, &stable_failure)) {
    set_failure(failure, stable_failure.kind, stable_failure.first, stable_failure.second);
    return 0;
  }
  /* Resident images may span service bytes that are reinstalled on demand. */
  for (size_t index = 0; index < layout.count; ++index) {
    if (layout.ranges[index].owner == DAZE_GUEST_OWNER_IMAGE) continue;
    if (!daze_guest_owner_persistent(layout.ranges[index].owner)) continue;
    if (daze_guest_ranges_overlap(input->image_address, image_size, layout.ranges[index].address,
                                  layout.ranges[index].size)) {
      set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OVERLAP, layout.ranges[index],
                  (DazeGuestRange){input->image_address, image_size, DAZE_GUEST_OWNER_IMAGE});
      return 0;
    }
  }
  /* Arena and conventional allocator overlap is permitted because their allocation
   * policies share low RAM. */
  for (size_t index = 0; index < layout.count; ++index) {
    if (!daze_guest_range_fits(input->guest_size, layout.ranges[index].address,
                               layout.ranges[index].size)) {
      set_failure(failure, DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST, layout.ranges[index], k_no_range);
      return 0;
    }
  }
  set_failure(failure, DAZE_GUEST_LAUNCH_VALID, k_no_range, k_no_range);
  return 1;
}
