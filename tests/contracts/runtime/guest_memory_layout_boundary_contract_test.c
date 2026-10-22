#include "guest_memory_layout.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <string.h>

int main(void) {
  DazeGuestLayout stable, runner, layout;
  assert(daze_guest_layout_init(&stable));
  assert(daze_guest_layout_add_stable(&stable));
  assert(daze_guest_layout_init(&runner));
  assert(daze_guest_layout_add_kvm_runner(&runner, k_memory_size));
  for (size_t free_slots = 0; free_slots < stable.count; ++free_slots) {
    memset(&layout, 0x5a, sizeof(layout));
    layout.count = DAZE_GUEST_LAYOUT_MAX_RANGES - free_slots;
    size_t initial = layout.count;
    DazeGuestRange sentinel = layout.ranges[0];
    assert(!daze_guest_layout_add_stable(&layout));
    assert(layout.count == DAZE_GUEST_LAYOUT_MAX_RANGES);
    assert(memcmp(&sentinel, &layout.ranges[0], sizeof(sentinel)) == 0);
    for (size_t i = 0; i < free_slots; ++i)
      assert(memcmp(&layout.ranges[initial + i], &stable.ranges[i], sizeof(sentinel)) == 0);
  }
  for (size_t free_slots = 0; free_slots < runner.count; ++free_slots) {
    layout.count = DAZE_GUEST_LAYOUT_MAX_RANGES - free_slots;
    size_t initial = layout.count;
    assert(!daze_guest_layout_add_kvm_runner(&layout, k_memory_size));
    assert(layout.count == DAZE_GUEST_LAYOUT_MAX_RANGES);
    for (size_t i = 0; i < free_slots; ++i)
      assert(memcmp(&layout.ranges[initial + i], &runner.ranges[i], sizeof(DazeGuestRange)) == 0);
  }
  assert(!daze_guest_layout_init(NULL));
  assert(!daze_guest_layout_add_stable(NULL));
  assert(!daze_guest_layout_add_kvm_runner(NULL, k_memory_size));
  assert(!daze_guest_layout_add_image(NULL, 0, 1));
  assert(!daze_guest_layout_add_environment(NULL, 1));
  assert(!daze_guest_layout_add_dpmi_client_arena(&layout, 10, 10));
  assert(!daze_guest_layout_add_conventional_allocator(&layout, 0xffff));
  assert(!daze_guest_layout_add_image(&layout, 0, 1));
  assert(!daze_guest_layout_add_environment(&layout, 1));
  assert(!daze_guest_layout_add_dpmi_client_arena(&layout, 0, 1));
  assert(!daze_guest_layout_add_conventional_allocator(&layout, 0x3000));
  assert(strcmp(daze_guest_owner_name((DazeGuestOwner)-1), "none") == 0);
  assert(!daze_guest_owner_persistent((DazeGuestOwner)-1));
  assert(daze_guest_layout_format_named(NULL, 1, "x", 0, 1) == -1);
  assert(daze_guest_layout_format_named(NULL, 0, NULL, 0, 1) == -1);
  char text[64];
  assert(daze_guest_layout_format_named(text, sizeof(text), "x", UINT32_MAX, 1) > 0);
  assert(strcmp(text, "x [ffffffff..100000000)") == 0);
  assert(daze_guest_layout_format_named(NULL, 0, "x", UINT32_MAX, 1) == (int)strlen(text));
  DazeGuestLaunchInput input = {k_memory_size, 0x10000, 0x1234, 512, 0x50000, 0xfd0000};
  DazeGuestLaunchFailure failure;
  assert(!daze_guest_layout_build_launch(NULL, &input, 0x3000, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_BAD_INPUT);
  assert(!daze_guest_layout_build_launch(&layout, NULL, 0x3000, &failure));
  input.guest_size = 0;
  assert(!daze_guest_layout_build_launch(&layout, &input, 0x3000, &failure));
  input.guest_size = k_memory_size;
#if SIZE_MAX > UINT32_MAX
  input.image_size = (size_t)UINT32_MAX + 1;
  assert(!daze_guest_layout_build_launch(&layout, &input, 0x3000, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST);
  assert(failure.first.owner == DAZE_GUEST_OWNER_IMAGE && failure.first.size == UINT32_MAX);
#endif
  input.image_size = k_memory_size;
  assert(!daze_guest_layout_build_launch(&layout, &input, 0x3000, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST);
  input.image_size = 0x1234;
  assert(!daze_guest_layout_build_launch(&layout, &input, 0xffff, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_ALLOCATION_MISMATCH && failure.first.size == 0);
  input.guest_size = 0x20000;
  assert(!daze_guest_launch_layout_valid(&input, 0x3000, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST);
  assert(failure.first.owner == DAZE_GUEST_OWNER_DPMI_GDT);
  input.guest_size = k_memory_size;
  input.linear_limit = UINT32_MAX;
  assert(!daze_guest_launch_layout_valid(&input, 0x3000, &failure));
  assert(failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST);
  assert(failure.first.owner == DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA);
  return 0;
}
