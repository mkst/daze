#ifndef DAZE_KVM_PROCESS_LAYOUT_H
#define DAZE_KVM_PROCESS_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t address;
  size_t size;
} DazeKvmGuestRange;

/* Segments specify real-mode process locations, not protected selectors.
 * reserved_ranges is borrowed for validation. */
typedef struct {
  uint32_t guest_size, image_size;
  uint16_t psp_segment, environment_segment, dpmi_entry_segment;
  uint16_t dos_vector_segment, load_segment;
  const DazeKvmGuestRange *reserved_ranges;
  size_t reserved_range_count;
} DazeKvmProcessLayout;

typedef enum {
  DAZE_KVM_PROCESS_LAYOUT_VALID = 0,
  DAZE_KVM_PROCESS_LAYOUT_BAD_INPUT,
  /* first names the range (or segment paragraph, with size 0) that does not
   * fit; second is empty. */
  DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST,
  /* first names the empty reservation; second is empty. The validator never
   * accepts zero-size reservations. */
  DAZE_KVM_PROCESS_LAYOUT_RESERVED_EMPTY,
  /* first/second name the overlapping pair in check order (the image is
   * checked against each reserved range in turn). */
  DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP,
} DazeKvmProcessLayoutFailureKind;

typedef struct {
  DazeKvmProcessLayoutFailureKind kind;
  DazeKvmGuestRange first, second;
} DazeKvmProcessLayoutFailure;

/* Range validation only; does not install bytes or execute the guest. On
 * failure with failure != NULL, reports which ranges collided so the caller
 * can reject loudly with names and addresses. */
int daze_kvm_process_layout_valid(const DazeKvmProcessLayout *layout,
                                  DazeKvmProcessLayoutFailure *failure);

#endif
