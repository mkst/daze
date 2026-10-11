#ifndef DAZE_GUEST_MEMORY_LAYOUT_H
#define DAZE_GUEST_MEMORY_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

/* Persistent ranges must survive image loading. DOS/BIOS service bytes are reinstalled
 * on demand and may overlap a resident image. The DPMI client arena and conventional
 * allocator intentionally share low RAM. */

enum {
  /* The 16-bit LGDT entry sequence requires descriptor tables below 16 MiB. */
  k_memory_size = 16 * 1024 * 1024,
  /* GO32 retains startup state below 0x50000 after its MZ image ends; client allocations
   * must start above it. */
  k_dpmi_linear_min_address = 0x50000,
  k_load_segment = 0x1000,
  k_psp_segment = k_load_segment - 0x10,
  k_environment_segment = 0x0700,
  /* No double-byte code page is exposed, so the DBCS table contains only its zero
   * terminator. */
  k_dos_dbcs_table_segment = 0x0600,
  k_dpmi_entry_segment = 0x0200,
  k_dos_int21_vector_segment = 0x0300,
  /* InDOS storage must remain clear of the INT 21h and IRET stubs. */
  k_dos_sda_offset = 0x001f,
  k_dos_indos_offset = 0x0020,
  k_dos_sda_size = 2,
  k_dpmi_gdt_address = k_memory_size - 0x10000,
  k_dpmi_ldt_address = k_memory_size - 0x20000,
  k_dpmi_rm_trampoline_linear = 0x2140,
  k_dpmi_rm_target_linear = 0x2160,
  k_dpmi_rm_gate_linear = 0x2300,
  k_dpmi_rm_gate_segment = 0x0230,
  k_bios_config_table = 0x1f100,
  k_pm_reentry_wrapper = 0x2180,
  k_pm_reentry_state = 0x2200,
  /* A 0300h continuation may retain full 32-bit registers and EIP, so it needs separate
   * code and state from the 16-bit wrapper. */
  k_pm_reentry32_wrapper = 0x2240,
  k_pm_reentry32_state = 0x22c0,
  k_dpmi_return_stack_segment = 0x0040,
  k_dpmi_return_stack_sp = 0x0be0,
  /* Unicorn 2.1.4 does not deliver #NP through the IDT. Use a host-owned
   * 16-bit gateway in selector 0028h (base 2000h), clear of the DPMI
   * trampoline and re-entry state, to load the locked stack in guest code. */
  k_dpmi_exception_gateway_selector = 0x0028,
  k_dpmi_exception_gateway_offset = 0x0380,
  k_dpmi_exception_gateway_linear = 0x02380,
  k_dpmi_exception_saved_ax_offset = 0x03a0,
  k_dpmi_exception_handler_pointer_offset = 0x03a2,
  k_dpmi_exception_gateway_span = 0x030,
  /* The client arena ends at the host-owned 4 KiB locked stack's base,
   * keeping both the stack and the higher LDT out of client allocations. */
  k_dpmi_exception_locked_stack_selector = 0x0048,
  k_dpmi_exception_locked_stack_base = k_memory_size - 0x30000,
  k_dpmi_exception_locked_stack_limit = 0x0fff,
  k_dpmi_exception_locked_stack_sp = 0x0ff0,
  k_dpmi_linear_arena_limit = k_dpmi_exception_locked_stack_base,
  k_dos_psp_size = 256,
  k_dos_environment_max_size = 512,
  k_dos_dpmi_entry_stub_size = 3,
  k_dos_vector_gate_size = 3,
  k_dos_vector_gate_iret_offset = 0x10,
  k_dos_vector_gate_iret_size = 1,
  k_dos_dbcs_table_size = 2,
  k_bios_config_table_size = 8,
  k_dpmi_exception_locked_stack_size = 0x1000,
  k_dos_conventional_floor_segment = 0x3000,
  k_dos_conventional_end_segment = 0xa000,
  /* The gate arena sits above the conventional allocator ceiling to avoid DOS
   * allocations. Record and mailbox are rewritten per boundary but must not overlap the
   * loaded image. */
  DAZE_KVM_RUNNER_GATE_UPPER_LINEAR = 0xa0000,
  DAZE_KVM_RUNNER_GATE_FALLBACK_LINEAR = 0x30000,
  DAZE_KVM_RUNNER_GATE_STRIDE = 180,
  DAZE_KVM_RUNNER_GATE_COUNT = 256,
  DAZE_KVM_RUNNER_GATE_RECORD_SIZE = 24,
  DAZE_KVM_RUNNER_GATE_RECORD_LINEAR = 0x9f000,
  DAZE_KVM_RUNNER_GATE_RECORD_FALLBACK_LINEAR = 0x3f000,
  DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE = 16,
  /* Reserve the longest trampoline variant; the BIOS reload stub shares this scratch
   * area. */
  k_dpmi_rm_trampoline_max_size = 25,
  k_dpmi_rm_target_size = 4,
  k_dpmi_rm_gate_max_size = 15,
  k_pm_reentry_wrapper_size = 84,
  k_pm_reentry_state_size = 32,
  k_pm_reentry32_wrapper_size = 115,
  k_pm_reentry32_state_size = 0x36,
  k_dpmi_return_stack_use_size = 6,
  k_bios_reload_stub_size = 12,
};

/* Durable owners must survive normal real-mode execution, so a resident
 * image must never span them. Reinstallable service bytes (DOS gate, IRET,
 * SDA/InDOS, DBCS table, BIOS table) are rewritten by their service when
 * required and are excluded from image-overlap rejection. */
typedef enum {
  DAZE_GUEST_OWNER_IMAGE = 0,
  DAZE_GUEST_OWNER_PSP,
  DAZE_GUEST_OWNER_ENVIRONMENT,
  DAZE_GUEST_OWNER_DPMI_ENTRY_STUB,
  DAZE_GUEST_OWNER_DOS_VECTOR_GATE,
  DAZE_GUEST_OWNER_DOS_VECTOR_IRET,
  DAZE_GUEST_OWNER_DOS_SDA,
  DAZE_GUEST_OWNER_DOS_DBCS_TABLE,
  DAZE_GUEST_OWNER_BIOS_CONFIG_TABLE,
  DAZE_GUEST_OWNER_DPMI_GDT,
  DAZE_GUEST_OWNER_DPMI_LDT,
  DAZE_GUEST_OWNER_DPMI_LOCKED_STACK,
  DAZE_GUEST_OWNER_DPMI_CLIENT_ARENA,
  DAZE_GUEST_OWNER_CONVENTIONAL_ALLOCATOR,
  DAZE_GUEST_OWNER_KVM_RUNNER_GATE_ARENA,
  DAZE_GUEST_OWNER_KVM_RUNNER_RECORD,
  DAZE_GUEST_OWNER_KVM_RUNNER_MAILBOX,
  DAZE_GUEST_OWNER_COUNT,
  DAZE_GUEST_OWNER_NONE = DAZE_GUEST_OWNER_COUNT,
} DazeGuestOwner;

typedef struct {
  uint32_t address;
  uint32_t size;
  DazeGuestOwner owner;
} DazeGuestRange;

enum { DAZE_GUEST_LAYOUT_MAX_RANGES = 20 };

enum { DAZE_GUEST_LAYOUT_STABLE_COUNT = 10 };

typedef struct {
  DazeGuestRange ranges[DAZE_GUEST_LAYOUT_MAX_RANGES];
  size_t count;
} DazeGuestLayout;

typedef struct {
  uint32_t guest_size;
  uint32_t image_address;
  size_t image_size;
  /* Actual size when known, else k_dos_environment_max_size as a
   * conservative bound (the loader's env buffer can never exceed it). */
  size_t environment_size;
  uint32_t linear_min_address;
  uint32_t linear_limit;
} DazeGuestLaunchInput;

typedef enum {
  DAZE_GUEST_LAUNCH_VALID = 0,
  DAZE_GUEST_LAUNCH_BAD_INPUT,
  /* first names the range that does not fit; second is NONE. */
  DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST,
  /* first/second name the overlapping pair in layout order. */
  DAZE_GUEST_LAUNCH_RANGE_OVERLAP,
  /* No page-aligned arena base exists below the limit; first carries the
   * attempted arena (address=resident end, size=0). */
  DAZE_GUEST_LAUNCH_NO_LINEAR_ARENA,
  /* allocation_start disagrees with the image end; first carries the passed
   * conventional range. */
  DAZE_GUEST_LAUNCH_ALLOCATION_MISMATCH,
} DazeGuestLaunchFailureKind;

typedef struct {
  DazeGuestLaunchFailureKind kind;
  DazeGuestRange first;
  DazeGuestRange second;
} DazeGuestLaunchFailure;

/* Empty ranges fit (including at address == guest_size) and never overlap.
 * Sums use 64-bit arithmetic so wrapped 32-bit ends cannot alias. */
static inline int daze_guest_range_fits(uint32_t guest_size, uint32_t address, uint32_t size) {
  return address <= guest_size && (uint64_t)size <= (uint64_t)guest_size - address;
}

static inline int daze_guest_ranges_overlap(uint32_t first_address, uint32_t first_size,
                                            uint32_t second_address, uint32_t second_size) {
  return (uint64_t)first_address < (uint64_t)second_address + second_size &&
         (uint64_t)second_address < (uint64_t)first_address + first_size;
}

const char *daze_guest_owner_name(DazeGuestOwner owner);
int daze_guest_owner_persistent(DazeGuestOwner owner);

/* Returns snprintf-style length; short buffers remain NUL-terminated and range ends
 * widen past 32 bits rather than truncating. */
int daze_guest_layout_format_range(char *out, size_t out_size, DazeGuestRange range);

int daze_guest_layout_format_named(char *out, size_t out_size, const char *name, uint32_t address,
                                   uint32_t size);

int daze_guest_layout_init(DazeGuestLayout *layout);
int daze_guest_layout_add_stable(DazeGuestLayout *layout);
int daze_guest_layout_add_image(DazeGuestLayout *layout, uint32_t image_address,
                                uint32_t image_size);
int daze_guest_layout_add_environment(DazeGuestLayout *layout, uint32_t environment_size);
int daze_guest_layout_add_dpmi_client_arena(DazeGuestLayout *layout, uint32_t first_base,
                                            uint32_t limit);
int daze_guest_layout_add_conventional_allocator(DazeGuestLayout *layout,
                                                 uint16_t allocation_start);
/* Runner ranges are ordered gate arena, record, mailbox; validators depend on that
 * order. */
int daze_guest_layout_add_kvm_runner(DazeGuestLayout *layout, uint32_t guest_size);

/* Invalid layout leaves a coarse failure reason; launch validation and diagnostics use
 * the same description. */
int daze_guest_layout_build_launch(DazeGuestLayout *layout, const DazeGuestLaunchInput *input,
                                   uint16_t allocation_start, DazeGuestLaunchFailure *failure);

static inline uint32_t daze_kvm_runner_gate_linear(size_t guest_size) {
  const uint32_t gate_size = DAZE_KVM_RUNNER_GATE_COUNT * DAZE_KVM_RUNNER_GATE_STRIDE;
  return guest_size >= DAZE_KVM_RUNNER_GATE_UPPER_LINEAR + gate_size
           ? DAZE_KVM_RUNNER_GATE_UPPER_LINEAR
           : DAZE_KVM_RUNNER_GATE_FALLBACK_LINEAR;
}

static inline uint32_t daze_kvm_runner_gate_end(size_t guest_size) {
  return daze_kvm_runner_gate_linear(guest_size) +
         DAZE_KVM_RUNNER_GATE_COUNT * DAZE_KVM_RUNNER_GATE_STRIDE;
}

static inline uint32_t daze_kvm_runner_gate_record_linear(size_t guest_size) {
  return guest_size >= DAZE_KVM_RUNNER_GATE_RECORD_LINEAR + DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE
           ? DAZE_KVM_RUNNER_GATE_RECORD_LINEAR
           : DAZE_KVM_RUNNER_GATE_RECORD_FALLBACK_LINEAR;
}

static inline uint32_t daze_kvm_runner_gate_mailbox_linear(size_t guest_size) {
  return daze_kvm_runner_gate_record_linear(guest_size) + 0x20;
}

/* Fits every range in the guest and rejects any overlap within the given
 * set. Callers checking the full launch layout must add arena/allocator
 * relations separately (see daze_guest_launch_layout_valid): those two
 * intentionally share low RAM with each other and with reinstallable
 * service bytes. */
int daze_guest_layout_validate_ranges(const DazeGuestRange *ranges, size_t count,
                                      uint32_t guest_size, DazeGuestLaunchFailure *failure);

/* Full launch check: stable-set consistency, image fit, image against every
 * persistent range, linear arena after resident_image_end clear of GDT/LDT,
 * and allocation_start matching the image end with checked arithmetic. No
 * guest execution may precede it. Returns 1 when valid, else 0 with *failure
 * set (when failure != NULL). */
int daze_guest_launch_layout_valid(const DazeGuestLaunchInput *input, uint16_t allocation_start,
                                   DazeGuestLaunchFailure *failure);

#endif
