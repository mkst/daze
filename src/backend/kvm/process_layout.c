#include "process_layout.h"

#include "kvm_range.h"

static void set_failure(DazeKvmProcessLayoutFailure *failure, DazeKvmProcessLayoutFailureKind kind,
                        DazeKvmGuestRange first, DazeKvmGuestRange second) {
  if (failure == NULL) return;
  failure->kind = kind;
  failure->first = first;
  failure->second = second;
}

static const DazeKvmGuestRange k_no_range = {0, 0};

int daze_kvm_process_layout_valid(const DazeKvmProcessLayout *layout,
                                  DazeKvmProcessLayoutFailure *failure) {
  if (layout == NULL || layout->guest_size == 0 || layout->image_size == 0 ||
      (layout->reserved_range_count != 0 && layout->reserved_ranges == NULL)) {
    set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  const uint32_t image_address = (uint32_t)layout->load_segment << 4;
  const uint16_t segments[] = {layout->psp_segment, layout->environment_segment,
                               layout->dpmi_entry_segment, layout->dos_vector_segment,
                               layout->load_segment};
  if (!daze_kvm_range_fits(layout->guest_size, image_address, layout->image_size)) {
    set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST,
                (DazeKvmGuestRange){image_address, layout->image_size}, k_no_range);
    return 0;
  }
  for (size_t index = 0; index < sizeof(segments) / sizeof(segments[0]); ++index)
    if ((uint32_t)segments[index] * 16u >= layout->guest_size) {
      set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST,
                  (DazeKvmGuestRange){(uint32_t)segments[index] * 16u, 0}, k_no_range);
      return 0;
    }
  const DazeKvmGuestRange image = {image_address, layout->image_size};
  for (size_t first = 0; first < layout->reserved_range_count; ++first) {
    const DazeKvmGuestRange current = layout->reserved_ranges[first];
    if (current.size == 0) {
      set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RESERVED_EMPTY, current, k_no_range);
      return 0;
    }
    if (!daze_kvm_range_fits(layout->guest_size, current.address, current.size)) {
      set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST, current, k_no_range);
      return 0;
    }
    if (daze_kvm_ranges_overlap(image.address, image.size, current.address, current.size)) {
      set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP, image, current);
      return 0;
    }
    for (size_t second = 0; second < first; ++second)
      if (daze_kvm_ranges_overlap(current.address, current.size,
                                  layout->reserved_ranges[second].address,
                                  layout->reserved_ranges[second].size)) {
        set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP, layout->reserved_ranges[second],
                    current);
        return 0;
      }
  }
  set_failure(failure, DAZE_KVM_PROCESS_LAYOUT_VALID, k_no_range, k_no_range);
  return 1;
}
