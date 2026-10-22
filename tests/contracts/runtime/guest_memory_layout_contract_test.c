#include "guest_memory_layout.h"
#include "linear_memory.h"

#include <stdio.h>
#include <string.h>

static int check(int condition, const char *message, int *pass) {
  if (!condition) fprintf(stderr, "guest-memory-layout contract failed: %s\n", message);
  *pass &= condition;
  return condition;
}

static DazeGuestLaunchInput valid_input(void) {
  return (DazeGuestLaunchInput){.guest_size = (uint32_t)k_memory_size,
                                .image_address = (uint32_t)k_load_segment << 4,
                                .image_size = 0x1234,
                                .environment_size = k_dos_environment_max_size,
                                .linear_min_address = k_dpmi_linear_min_address,
                                .linear_limit = k_dpmi_linear_arena_limit};
}

/* allocation_start mirrors launch.c for the valid input above:
 * end 0x11234 -> paragraphs 0x1123 -> floored to 0x3000. */
static const uint16_t k_valid_allocation_start = 0x3000;

int main(void) {
  int pass = 1;
  DazeGuestLaunchFailure failure = {
    DAZE_GUEST_LAUNCH_VALID, {0, 0, DAZE_GUEST_OWNER_NONE}, {0, 0, DAZE_GUEST_OWNER_NONE}};

  check(daze_guest_range_fits(0x800000, 0, 0), "empty range at zero fits", &pass);
  check(daze_guest_range_fits(0x800000, 0x800000, 0), "empty range at guest end fits", &pass);
  check(!daze_guest_range_fits(0x800000, 0x800001, 0), "address past guest rejected", &pass);
  check(!daze_guest_range_fits(0x800000, 0x7fffff, 2), "wrapped end rejected", &pass);
  check(!daze_guest_range_fits(0x800000, 0x7f0000, 0x10001), "oversized range rejected", &pass);
  check(daze_guest_range_fits(0x800000, 0x7f0000, 0x10000), "end-at-boundary fits", &pass);

  check(!daze_guest_ranges_overlap(0xff00, 256, 0x10000, 0x1234),
        "PSP/image adjacency does not overlap", &pass);
  check(!daze_guest_ranges_overlap(0x1000, 0, 0x1000, 0x10), "empty range never overlaps", &pass);
  check(daze_guest_ranges_overlap(0x1000, 0x10, 0x100f, 0x10), "one-byte overlap detected", &pass);
  check(daze_guest_ranges_overlap(0x1000, 0x100, 0x1020, 0x10), "containment overlaps", &pass);
  check(daze_guest_ranges_overlap(0x2000, 0x100, 0x2000, 0x100), "identical ranges overlap", &pass);
  check(!daze_guest_ranges_overlap(0xffffff00u, 0x100, 0, 0x100),
        "wrapped addresses do not alias low memory", &pass);

  for (int owner = 0; owner < DAZE_GUEST_OWNER_COUNT; ++owner)
    check(daze_guest_owner_name((DazeGuestOwner)owner) != NULL, "owner has a name", &pass);
  check(daze_guest_owner_persistent(DAZE_GUEST_OWNER_PSP), "PSP is persistent", &pass);
  check(daze_guest_owner_persistent(DAZE_GUEST_OWNER_DPMI_GDT), "GDT is persistent", &pass);
  check(!daze_guest_owner_persistent(DAZE_GUEST_OWNER_BIOS_CONFIG_TABLE),
        "BIOS table is reinstallable", &pass);
  check(!daze_guest_owner_persistent(DAZE_GUEST_OWNER_DOS_VECTOR_GATE), "DOS gate is reinstallable",
        &pass);

  DazeGuestLayout stable;
  check(daze_guest_layout_init(&stable) && daze_guest_layout_add_stable(&stable) &&
          stable.count == DAZE_GUEST_LAYOUT_STABLE_COUNT,
        "stable range count", &pass);
  check(daze_guest_owner_persistent(DAZE_GUEST_OWNER_KVM_RM_RETURN_BRIDGE),
        "callback return bridge is persistent", &pass);
  check(daze_guest_owner_persistent(DAZE_GUEST_OWNER_KVM_EXCEPTION_RETURN),
        "exception return helper is persistent", &pass);
  check(daze_guest_owner_persistent(DAZE_GUEST_OWNER_KVM_EXCEPTION_DELIVERY),
        "exception delivery helper is persistent", &pass);
  check(daze_guest_layout_validate_ranges(stable.ranges, stable.count, (uint32_t)k_memory_size,
                                          &failure),
        "stable set is internally consistent", &pass);

  DazeGuestLaunchInput input = valid_input();
  check(daze_guest_launch_layout_valid(&input, k_valid_allocation_start, &failure),
        "normal launch layout accepted", &pass);

  DazeDpmiLinearMemory compiler_memory;
  uint32_t compiler_base = 0, compiler_handle = 0, resized_base = 0;
  daze_dpmi_linear_memory_init(&compiler_memory, k_dpmi_linear_min_address,
                               k_dpmi_linear_arena_limit);
  check(
    daze_dpmi_linear_memory_allocate(&compiler_memory, 0x170000, &compiler_base,
                                     &compiler_handle) &&
      daze_dpmi_linear_memory_resize(&compiler_memory, compiler_handle, 0x790000, &resized_base) &&
      daze_dpmi_linear_memory_resize(&compiler_memory, compiler_handle, 0x8f0000, &resized_base) &&
      resized_base == compiler_base,
    "CC1PSX large-input block grows past the former memory ceiling", &pass);
  const uint32_t arena_size = k_dpmi_linear_arena_limit - compiler_base;
  check(
    daze_dpmi_linear_memory_resize(&compiler_memory, compiler_handle, arena_size, &resized_base),
    "compiler block can reach the reserved-region boundary", &pass);
  const DazeDpmiLinearMemory full_memory = compiler_memory;
  check(!daze_dpmi_linear_memory_resize(&compiler_memory, compiler_handle, arena_size + 1,
                                        &resized_base) &&
          memcmp(&full_memory, &compiler_memory, sizeof(full_memory)) == 0,
        "growth into host-owned memory is rejected without changing the allocation", &pass);

  /* A resident compiler image legitimately spans the reinstallable BIOS table
   * at 0x1F100; only durable ranges reject the image. */
  input = valid_input();
  input.image_size = 0x100000;
  check(daze_guest_launch_layout_valid(&input, 0xa000, &failure),
        "image over reinstallable bytes accepted", &pass);

  /* The image still fits the guest here, but no page-aligned arena base
   * remains below the locked stack. */
  input = valid_input();
  input.image_size = k_dpmi_linear_arena_limit - input.image_address;
  check(!daze_guest_launch_layout_valid(&input, 0xa000, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_NO_LINEAR_ARENA &&
          failure.first.owner == DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA,
        "missing linear arena rejected", &pass);

  input = valid_input();
  input.image_size = (size_t)k_memory_size;
  check(!daze_guest_launch_layout_valid(&input, 0xa000, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST &&
          failure.first.owner == DAZE_GUEST_OWNER_IMAGE,
        "oversized image rejected", &pass);

  input = valid_input();
  input.image_address = 0xfe00;
  input.image_size = 0x200;
  check(!daze_guest_launch_layout_valid(&input, 0x3000, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_RANGE_OVERLAP &&
          ((failure.first.owner == DAZE_GUEST_OWNER_PSP &&
            failure.second.owner == DAZE_GUEST_OWNER_IMAGE) ||
           (failure.first.owner == DAZE_GUEST_OWNER_IMAGE &&
            failure.second.owner == DAZE_GUEST_OWNER_PSP)),
        "image over PSP rejected with both owners", &pass);

  input = valid_input();
  check(!daze_guest_launch_layout_valid(&input, 0x4000, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_ALLOCATION_MISMATCH &&
          failure.first.owner == DAZE_GUEST_OWNER_CONVENTIONAL_ALLOCATOR,
        "allocation mismatch rejected", &pass);

  input = valid_input();
  input.environment_size = k_dos_environment_max_size + 1;
  check(!daze_guest_launch_layout_valid(&input, k_valid_allocation_start, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_BAD_INPUT,
        "oversized environment rejected", &pass);

  DazeGuestRange colliding[] = {{0x3000, 0x100, DAZE_GUEST_OWNER_DOS_VECTOR_GATE},
                                {0x3050, 0x100, DAZE_GUEST_OWNER_DOS_SDA}};
  check(!daze_guest_layout_validate_ranges(colliding, 2, (uint32_t)k_memory_size, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_RANGE_OVERLAP &&
          failure.first.owner == DAZE_GUEST_OWNER_DOS_VECTOR_GATE &&
          failure.second.owner == DAZE_GUEST_OWNER_DOS_SDA,
        "overlapping pair reports both ranges in order", &pass);

  DazeGuestRange outside[] = {{k_dpmi_gdt_address, 0x10001, DAZE_GUEST_OWNER_DPMI_GDT}};
  check(!daze_guest_layout_validate_ranges(outside, 1, (uint32_t)k_memory_size, &failure) &&
          failure.kind == DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST &&
          failure.first.owner == DAZE_GUEST_OWNER_DPMI_GDT,
        "range past guest end rejected", &pass);

  /* The KVM runner triple in fixed [gate arena, record, mailbox] order, from
   * the single shared computation: upper placements on a full-size guest,
   * low-memory fallbacks on a small one. */
  DazeGuestLayout runner;
  check(daze_guest_layout_init(&runner) &&
          daze_guest_layout_add_kvm_runner(&runner, (uint32_t)k_memory_size) && runner.count == 3 &&
          runner.ranges[0].address == 0xa0000 && runner.ranges[0].size == 256 * 180 &&
          runner.ranges[0].owner == DAZE_GUEST_OWNER_KVM_RUNNER_GATE_ARENA &&
          runner.ranges[1].address == 0x9f000 && runner.ranges[1].size == 24 &&
          runner.ranges[1].owner == DAZE_GUEST_OWNER_KVM_RUNNER_RECORD &&
          runner.ranges[2].address == 0x9f020 && runner.ranges[2].size == 16 &&
          runner.ranges[2].owner == DAZE_GUEST_OWNER_KVM_RUNNER_MAILBOX,
        "full-size guest uses upper runner placements", &pass);
  check(daze_guest_layout_init(&runner) && daze_guest_layout_add_kvm_runner(&runner, 0x80000) &&
          runner.count == 3 && runner.ranges[0].address == 0x30000 &&
          runner.ranges[1].address == 0x3f000 && runner.ranges[2].address == 0x3f020,
        "small guest uses fallback runner placements", &pass);

  /* A launch layout plus the runner triple fits one description object. */
  DazeGuestLayout assembled;
  check(daze_guest_layout_init(&assembled) && daze_guest_layout_add_stable(&assembled) &&
          daze_guest_layout_add_image(&assembled, 0x10000, 0x1234) &&
          daze_guest_layout_add_environment(&assembled, k_dos_environment_max_size) &&
          daze_guest_layout_add_dpmi_client_arena(&assembled, 0x50000, k_dpmi_linear_arena_limit) &&
          daze_guest_layout_add_conventional_allocator(&assembled, 0x3000) &&
          daze_guest_layout_add_kvm_runner(&assembled, (uint32_t)k_memory_size) &&
          assembled.count == DAZE_GUEST_LAYOUT_STABLE_COUNT + 7,
        "launch plus runner ranges share one layout", &pass);

  /* One range renders as "owner [aaaaaaaa..bbbbbbbb)" with both ends shown.
   * Both validation-failure reporters format through here, so this pins the
   * exact text a collision report carries for each of its two ranges. */
  char line[64];
  check(daze_guest_layout_format_range(
          line, sizeof(line), (DazeGuestRange){0x10000, 0x1234, DAZE_GUEST_OWNER_IMAGE}) > 0 &&
          strcmp(line, "MZ image [00010000..00011234)") == 0,
        "image range formats exactly", &pass);
  check(daze_guest_layout_format_range(
          line, sizeof(line), (DazeGuestRange){0x9f000, 24, DAZE_GUEST_OWNER_KVM_RUNNER_RECORD}) >
            0 &&
          strcmp(line, "KVM runner record [0009f000..0009f018)") == 0,
        "runner range formats exactly", &pass);
  check(daze_guest_layout_format_range(
          NULL, 0, (DazeGuestRange){0x3000, 3, DAZE_GUEST_OWNER_DOS_VECTOR_GATE}) > 0,
        "format measures without a buffer", &pass);
  check(daze_guest_layout_format_range(
          line, 10, (DazeGuestRange){0x3000, 3, DAZE_GUEST_OWNER_DOS_VECTOR_GATE}) > 0 &&
          memcmp(line, "DOS vecto", 9) == 0 && line[9] == '\0',
        "format truncates safely", &pass);

  /* The shared launch builder agrees with the validator on good and bad
   * inputs, carrying the same coarse failure. */
  DazeGuestLayout built;
  DazeGuestLaunchInput good = valid_input();
  DazeGuestLaunchFailure build_failure = {
    DAZE_GUEST_LAUNCH_VALID, {0, 0, DAZE_GUEST_OWNER_NONE}, {0, 0, DAZE_GUEST_OWNER_NONE}};
  check(daze_guest_layout_build_launch(&built, &good, k_valid_allocation_start, &build_failure) &&
          built.count == DAZE_GUEST_LAYOUT_STABLE_COUNT + 4,
        "launch builder assembles the stable set plus per-run ranges", &pass);
  DazeGuestLaunchInput bad_arena = valid_input();
  bad_arena.image_size = k_dpmi_linear_arena_limit - bad_arena.image_address;
  check(!daze_guest_layout_build_launch(&built, &bad_arena, 0xa000, &build_failure) &&
          build_failure.kind == DAZE_GUEST_LAUNCH_NO_LINEAR_ARENA,
        "launch builder reports a missing arena", &pass);

  return pass ? 0 : 1;
}
