#include "process_layout.h"

#include "guest_memory_layout.h"

#include <stdio.h>

static DazeKvmProcessLayout valid_layout(void) {
  static const DazeKvmGuestRange ranges[] = {{0x2000, 0x100}, {0x3000, 0x200}};
  return (DazeKvmProcessLayout){.guest_size = 0x40000,
                                .image_size = 0x3000,
                                .psp_segment = 0x0ff0,
                                .environment_segment = 0x0700,
                                .dpmi_entry_segment = 0x0200,
                                .dos_vector_segment = 0x0300,
                                .load_segment = 0x1000,
                                .reserved_ranges = ranges,
                                .reserved_range_count = sizeof(ranges) / sizeof(ranges[0])};
}

static int check(int condition, const char *message, int *pass) {
  if (!condition) fprintf(stderr, "KVM process layout contract failed: %s\n", message);
  *pass &= condition;
  return condition;
}

int main(void) {
  int pass = 1;
  DazeKvmProcessLayoutFailure failure = {DAZE_KVM_PROCESS_LAYOUT_VALID, {0, 0}, {0, 0}};
  DazeKvmProcessLayout layout = valid_layout();
  check(daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_VALID,
        "valid layout accepted", &pass);
  layout.image_size = 0x40000;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST &&
          failure.first.address == 0x10000,
        "oversized image names the image range", &pass);
  layout = valid_layout();
  layout.psp_segment = 0x4000;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST &&
          failure.first.address == 0x40000 && failure.first.size == 0,
        "out-of-guest segment names the paragraph", &pass);
  layout = valid_layout();
  layout.reserved_ranges = (const DazeKvmGuestRange[]){{0x10000, 0x20}};
  layout.reserved_range_count = 1;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP &&
          failure.first.address == 0x10000 && failure.second.address == 0x10000,
        "image/reserved overlap names both ranges", &pass);
  layout = valid_layout();
  layout.reserved_ranges = (const DazeKvmGuestRange[]){{0x2000, 0x200}, {0x2100, 0x100}};
  layout.reserved_range_count = 2;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP,
        "reserved/reserved overlap rejected", &pass);
  layout = valid_layout();
  layout.reserved_ranges = (const DazeKvmGuestRange[]){{0x3fff0, 0x20}};
  layout.reserved_range_count = 1;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST,
        "range past guest end rejected", &pass);
  layout = valid_layout();
  layout.reserved_ranges = NULL;
  layout.reserved_range_count = 1;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_BAD_INPUT,
        "dangling range list rejected", &pass);
  layout = valid_layout();
  layout.reserved_ranges = (const DazeKvmGuestRange[]){{0x2000, 0}};
  layout.reserved_range_count = 1;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RESERVED_EMPTY,
        "empty reservation rejected", &pass);

  /* The gate arena must sit above the conventional allocator ceiling so DOS allocations
   * cannot overwrite it. */
  DazeGuestLayout runner;
  check(daze_guest_layout_init(&runner) &&
          daze_guest_layout_add_kvm_runner(&runner, (uint32_t)k_memory_size) && runner.count == 3,
        "runner triple builds for a full-size guest", &pass);
  const uint32_t conventional_end = (uint32_t)k_dos_conventional_end_segment << 4;
  check(runner.ranges[0].address >= conventional_end,
        "runner gate arena escapes conventional scratch", &pass);
  layout = valid_layout();
  layout.guest_size = (uint32_t)k_memory_size;
  DazeKvmGuestRange live[3];
  for (size_t index = 0; index < 3; ++index)
    live[index] = (DazeKvmGuestRange){runner.ranges[index].address, runner.ranges[index].size};
  layout.reserved_ranges = live;
  layout.reserved_range_count = 3;
  check(daze_kvm_process_layout_valid(&layout, &failure), "live runner ranges accepted", &pass);

  /* A resident image spanning the runner record/mailbox is rejected before
   * any guest execution: the per-boundary record write would clobber it. */
  layout = valid_layout();
  layout.guest_size = (uint32_t)k_memory_size;
  layout.image_size = 0x90000;
  layout.reserved_ranges = live;
  layout.reserved_range_count = 3;
  check(!daze_kvm_process_layout_valid(&layout, &failure) &&
          failure.kind == DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP &&
          failure.first.address == 0x10000 && failure.second.address == 0x9f000,
        "image over runner record rejected", &pass);
  return pass ? 0 : 1;
}
