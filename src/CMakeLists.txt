# Pedantic C11 is the default for libraries/tests; launcher uses C11 without -Wpedantic.
function(daze_configure_c11_pedantic_target target visibility)
  target_compile_features(${target} ${visibility} c_std_11)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endfunction()

function(daze_configure_c11_target target visibility)
  target_compile_features(${target} ${visibility} c_std_11)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
endfunction()

add_library(daze_dosfs STATIC
  dos/fs/dosfs.c
  dos/fs/file_service.c
  dos/process_state.c
)

daze_configure_c11_pedantic_target(daze_dosfs PUBLIC)

# Shared DOS policy; backend CPU hooks and gate/mailbox transport remain separate.
add_library(daze_dos_int21_service STATIC
  dos/int21_service.c
  dos/country.c
  dos/file_time.c
  dos/find_result.c
  dos/file_attrs.c
  dos/fcb.c
  dos/date.c
)
daze_configure_c11_pedantic_target(daze_dos_int21_service PUBLIC)
target_link_libraries(daze_dos_int21_service PUBLIC daze_dosfs daze_dos_memory)

add_library(daze_metrics STATIC
  metrics/metrics.c
)

add_library(daze_mz_layout STATIC
  loader/mz_layout.c
)
daze_configure_c11_pedantic_target(daze_mz_layout PUBLIC)

daze_configure_c11_pedantic_target(daze_metrics PUBLIC)

add_library(daze_dos_memory STATIC
  dos/memory.c
)

daze_configure_c11_pedantic_target(daze_dos_memory PUBLIC)

add_library(daze_dpmi_descriptor STATIC
  dpmi/descriptor.c
)

daze_configure_c11_pedantic_target(daze_dpmi_descriptor PUBLIC)

# Shared legacy frame serialization and placement validation; no guest-memory writes.
add_library(daze_dpmi_exception_frame STATIC
  dpmi/exception_frame.c
)
daze_configure_c11_pedantic_target(daze_dpmi_exception_frame PUBLIC)

add_library(daze_dpmi_linear_memory STATIC
  dpmi/linear_memory.c
)

daze_configure_c11_pedantic_target(daze_dpmi_linear_memory PUBLIC)

add_library(daze_kvm_process_layout STATIC backend/kvm/process_layout.c)
daze_configure_c11_pedantic_target(daze_kvm_process_layout PUBLIC)

# Shared guest-memory ownership inventory and launch-time validation. Links
# the DPMI linear allocator only as the single source of arena-base truth.
add_library(daze_guest_memory_layout STATIC runtime/guest_memory_layout.c)
daze_configure_c11_pedantic_target(daze_guest_memory_layout PUBLIC)
target_link_libraries(daze_guest_memory_layout PRIVATE daze_dpmi_linear_memory)

# Shared DPMI request/result services used by Unicorn dispatch and the KVM mediator.
add_library(daze_dpmi_request STATIC
  dpmi/request.c
)
daze_configure_c11_pedantic_target(daze_dpmi_request PUBLIC)
target_link_libraries(daze_dpmi_request PUBLIC daze_dpmi_descriptor daze_dpmi_linear_memory daze_dos_memory)

add_library(daze_dpmi_alternate_state STATIC
  dpmi/alternate_state.c
)
daze_configure_c11_pedantic_target(daze_dpmi_alternate_state PUBLIC)

option(DAZE_BUILD_STATIC "Build a fully static executable for distribution" OFF)

set(DAZE_UNICORN_BACKEND "AUTO" CACHE STRING
  "Build the Unicorn backend (AUTO, ON, or OFF)")
set_property(CACHE DAZE_UNICORN_BACKEND PROPERTY STRINGS AUTO ON OFF)
string(TOUPPER "${DAZE_UNICORN_BACKEND}" DAZE_UNICORN_BACKEND)
if(NOT DAZE_UNICORN_BACKEND MATCHES "^(AUTO|ON|OFF)$")
  message(FATAL_ERROR "DAZE_UNICORN_BACKEND must be AUTO, ON, or OFF")
endif()

include(CheckCSourceCompiles)
check_c_source_compiles("\
  #if !defined(__linux__) || !(defined(__x86_64__) || defined(__i386__))\n\
  #error KVM is supported only on Linux/x86\n\
  #endif\n\
  int main(void) { return 0; }\n"
  DAZE_TARGET_HAS_KVM)

set(DAZE_HAS_UNICORN OFF)
if(NOT DAZE_UNICORN_BACKEND STREQUAL "OFF")
  find_path(UNICORN_INCLUDE_DIR unicorn/unicorn.h
    HINTS "${CMAKE_SOURCE_DIR}/unicorn/include")

  set(_daze_saved_library_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
  if(DAZE_BUILD_STATIC)
    # Static Daze needs Unicorn's combined libunicorn.a archive.
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  endif()
  find_library(UNICORN_LIBRARY unicorn
    HINTS "${CMAKE_SOURCE_DIR}/unicorn/lib")
  set(CMAKE_FIND_LIBRARY_SUFFIXES "${_daze_saved_library_suffixes}")

  if(UNICORN_INCLUDE_DIR AND UNICORN_LIBRARY)
    set(DAZE_HAS_UNICORN ON)
  endif()
endif()

if(DAZE_UNICORN_BACKEND STREQUAL "ON" AND NOT DAZE_HAS_UNICORN)
  if(DAZE_BUILD_STATIC)
    set(missing_hint
      " A static build needs Unicorn's combined libunicorn.a archive "
      "(build Unicorn with UNICORN_LEGACY_STATIC_ARCHIVE=ON).")
  else()
    set(missing_hint " Install Unicorn or set UNICORN_INCLUDE_DIR and CMAKE_LIBRARY_PATH.")
  endif()
  message(FATAL_ERROR "Unicorn was requested but its headers/library were not found.${missing_hint}")
endif()

if(NOT DAZE_HAS_UNICORN AND NOT DAZE_TARGET_HAS_KVM)
  message(FATAL_ERROR
    "No usable backend can be built: Unicorn is disabled or unavailable and KVM requires a "
    "Linux/x86 target. Enable/install Unicorn or target Linux/x86 for a KVM-only build.")
endif()

if(DAZE_HAS_UNICORN)
  message(STATUS "Daze backends: Unicorn and KVM (where supported)")
  # Static Unicorn archives have link requirements of their own.
  set(DAZE_UNICORN_LINK_LIBRARIES "${UNICORN_LIBRARY}")
  if(DAZE_BUILD_STATIC OR UNICORN_LIBRARY MATCHES "\\.a$")
    list(APPEND DAZE_UNICORN_LINK_LIBRARIES m pthread dl)
  endif()
else()
  message(STATUS "Daze backends: KVM only")
  set(DAZE_UNICORN_LINK_LIBRARIES "")
endif()

# Internal targets share private include roots within this directory; none is exported or installed.
# Vendored Unicorn headers are third-party, not ours: SYSTEM keeps host-compiler
# warnings (e.g. clang -Wnewline-eof) out of headers we do not own.
if(DAZE_HAS_UNICORN)
  include_directories(SYSTEM "${UNICORN_INCLUDE_DIR}")
endif()
include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/diagnostic"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/transition"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/gate"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/dpmi"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/command"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/unicorn"
  "${CMAKE_CURRENT_SOURCE_DIR}/dos"
  "${CMAKE_CURRENT_SOURCE_DIR}/dos/fs"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime"
  "${CMAKE_CURRENT_SOURCE_DIR}/dpmi"
  "${CMAKE_CURRENT_SOURCE_DIR}/loader"
  "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm"
  "${CMAKE_CURRENT_SOURCE_DIR}/arch"
  "${CMAKE_CURRENT_SOURCE_DIR}/bios"
  "${CMAKE_CURRENT_SOURCE_DIR}/metrics"
)

add_library(daze_backend_selection STATIC runtime/backend_selection.c runtime/backend_request.c)
daze_configure_c11_pedantic_target(daze_backend_selection PUBLIC)

add_library(daze_kvm_machine_candidate STATIC backend/kvm/machine_candidate.c)
daze_configure_c11_pedantic_target(daze_kvm_machine_candidate PUBLIC)
target_link_libraries(daze_kvm_machine_candidate PUBLIC daze_backend_selection)

add_library(daze_kvm_machine_diagnostic STATIC backend/kvm/machine_diagnostic.c)
daze_configure_c11_pedantic_target(daze_kvm_machine_diagnostic PUBLIC)

add_library(daze_kvm_candidate_observation STATIC backend/kvm/diagnostic/candidate_observation.c)
daze_configure_c11_pedantic_target(daze_kvm_candidate_observation PUBLIC)
target_link_libraries(daze_kvm_candidate_observation PUBLIC
  daze_kvm_machine daze_kvm_machine_candidate daze_kvm_machine_diagnostic
)

add_library(daze_kvm_prepared_request STATIC backend/kvm/prepared_request.c)
daze_configure_c11_pedantic_target(daze_kvm_prepared_request PUBLIC)
target_link_libraries(daze_kvm_prepared_request PUBLIC daze_kvm_runner)

add_library(daze_kvm_command_result STATIC backend/kvm/command/result.c)
daze_configure_c11_pedantic_target(daze_kvm_command_result PUBLIC)

add_library(daze_command_result STATIC runtime/command_result.c)
daze_configure_c11_pedantic_target(daze_command_result PUBLIC)

add_library(daze_dpmi_process_state STATIC dpmi/process_state.c)
daze_configure_c11_pedantic_target(daze_dpmi_process_state PUBLIC)
target_link_libraries(daze_dpmi_process_state PUBLIC daze_dpmi_linear_memory)

add_library(daze_kvm_machine STATIC backend/kvm/machine.c)
daze_configure_c11_pedantic_target(daze_kvm_machine PUBLIC)

add_library(daze_kvm_child_context STATIC backend/kvm/child_context.c)
target_link_libraries(daze_kvm_child_context PUBLIC daze_dpmi_descriptor)
daze_configure_c11_pedantic_target(daze_kvm_child_context PUBLIC)
target_link_libraries(daze_kvm_child_context PUBLIC daze_kvm_machine daze_dosfs daze_dos_memory)

add_library(daze_kvm_write_batch STATIC backend/kvm/write_batch.c)
daze_configure_c11_pedantic_target(daze_kvm_write_batch PUBLIC)
target_link_libraries(daze_kvm_write_batch PUBLIC daze_kvm_machine daze_dosfs daze_guest_memory_layout)

add_library(daze_kvm_runner STATIC
  backend/kvm/runner/runner.c
  backend/kvm/int21_adapter.c
  backend/kvm/bios_adapter.c
  loader/image.c
  dpmi/advertisement.c
  dos/date.c
  dos/fcb.c
  dos/find_result.c
  dos/exec_request.c
  dos/exec_psp.c
  dos/exec_image.c
  dos/exec_loader.c
  dos/file_attrs.c
  dos/file_time.c
  dos/country.c
  bios/timer.c
  bios/rtc.c
)
daze_configure_c11_pedantic_target(daze_kvm_runner PUBLIC)
target_link_libraries(daze_kvm_runner PUBLIC
  daze_kvm_write_batch daze_kvm_machine daze_kvm_runner_gate_resume daze_dos_int21_service daze_dosfs daze_dos_memory daze_mz_layout daze_kvm_process_layout daze_guest_memory_layout
)

add_library(daze_kvm_dpmi_entry STATIC backend/kvm/dpmi/entry.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_entry PUBLIC)
target_link_libraries(daze_kvm_dpmi_entry PUBLIC daze_kvm_machine daze_kvm_runner)

# Prepares process state and validates writes without executing the vCPU.
add_library(daze_kvm_dpmi_transition_state STATIC backend/kvm/dpmi/transition_state.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_transition_state PUBLIC)
target_link_libraries(daze_kvm_dpmi_transition_state PUBLIC
  daze_dpmi_linear_memory daze_dpmi_request daze_metrics daze_dpmi_process_state
)

# Validates/copies artifacts after state preparation; does not execute the vCPU.
add_library(daze_kvm_dpmi_transition_writer STATIC backend/kvm/dpmi/transition_writer.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_transition_writer PUBLIC)
target_link_libraries(daze_kvm_dpmi_transition_writer PUBLIC daze_kvm_dpmi_transition_state)

# Resumes a guest IRET with a caller reply; service policy remains outside this helper.
add_library(daze_kvm_runner_gate_resume STATIC backend/kvm/gate/runner_resume.c)
daze_configure_c11_pedantic_target(daze_kvm_runner_gate_resume PUBLIC)
target_link_libraries(daze_kvm_runner_gate_resume PUBLIC daze_kvm_machine)

add_library(daze_kvm_transition_plan STATIC
  backend/kvm/transition/plan.c
  dpmi/transition_artifacts.c
)
daze_configure_c11_pedantic_target(daze_kvm_transition_plan PUBLIC)
target_link_libraries(daze_kvm_transition_plan PUBLIC daze_dpmi_linear_memory daze_guest_memory_layout)

add_library(daze_kvm_command_owner STATIC backend/kvm/command/owner.c backend/kvm/command/boundary.c)
daze_configure_c11_pedantic_target(daze_kvm_command_owner PUBLIC)
target_link_libraries(daze_kvm_command_owner PUBLIC
  daze_kvm_runner daze_kvm_child_context daze_kvm_dpmi_entry daze_kvm_transition_plan
  daze_kvm_dpmi_transition_writer daze_kvm_protected_gate daze_kvm_state_save_gate
  daze_kvm_raw_switch_gate daze_kvm_runner_gate_resume daze_kvm_rm_procedure
)

# Pure normal-runtime configuration builder. It owns no KVM machine and is
# tested independently of KVM device availability.
add_library(daze_kvm_normal_transition_config STATIC backend/kvm/transition/normal_config.c)
daze_configure_c11_pedantic_target(daze_kvm_normal_transition_config PUBLIC)
target_link_libraries(daze_kvm_normal_transition_config PUBLIC daze_kvm_command_owner daze_guest_memory_layout)
target_link_libraries(daze_kvm_command_owner PUBLIC daze_kvm_normal_transition_config)

# Normal-placement composition from prepared launch facts to the KVM owner.
add_library(daze_kvm_normal_operation STATIC backend/kvm/normal_operation.c)
daze_configure_c11_pedantic_target(daze_kvm_normal_operation PUBLIC)
target_link_libraries(daze_kvm_normal_operation PUBLIC
  daze_kvm_normal_transition_config daze_kvm_command_result
)

# Runs the prepared normal KVM operation after the launcher selects KVM.
add_library(daze_kvm_selected_operation STATIC backend/kvm/selected_operation.c)
daze_configure_c11_pedantic_target(daze_kvm_selected_operation PUBLIC)
target_link_libraries(daze_kvm_selected_operation PUBLIC daze_kvm_normal_operation)

add_library(daze_kvm_selection_diagnostic STATIC backend/kvm/diagnostic/selection.c)
daze_configure_c11_pedantic_target(daze_kvm_selection_diagnostic PUBLIC)
target_link_libraries(daze_kvm_selection_diagnostic PUBLIC
  daze_kvm_candidate_observation daze_kvm_selected_operation
)

add_library(daze_kvm_selection_metrics STATIC backend/kvm/diagnostic/selection_metrics.c)
daze_configure_c11_pedantic_target(daze_kvm_selection_metrics PUBLIC)
target_link_libraries(daze_kvm_selection_metrics PUBLIC daze_kvm_selection_diagnostic)

# Shared 0301h Call Real Mode Procedure frame contract. It owns the bounded
# parse, far-return, and frame write-back semantics used by both the mediator
# (device-free) and the KVM real-mode reflection.
add_library(daze_dpmi_rm_frame STATIC dpmi/rm_frame.c)
daze_configure_c11_pedantic_target(daze_dpmi_rm_frame PUBLIC)

# Constructed protected-mode PIO/mailbox mediation. This verifies a KVM guest
# receives shared DPMI results through its own IRETD, without selecting a
# runtime backend or extending the ASPSX checkpoint.
add_library(daze_kvm_dpmi_mediator STATIC backend/kvm/dpmi/mediator.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_mediator PUBLIC)
target_link_libraries(daze_kvm_dpmi_mediator PUBLIC daze_dpmi_request daze_dpmi_rm_frame)

# This continuation-only gate retains the protected machine established by
# the transition and exchanges one caller-owned mediator record.
add_library(daze_kvm_protected_gate STATIC backend/kvm/gate/protected.c backend/kvm/gate/legacy_exception.c)
daze_configure_c11_pedantic_target(daze_kvm_protected_gate PUBLIC)
target_link_libraries(daze_kvm_protected_gate PUBLIC daze_kvm_dpmi_entry daze_kvm_dpmi_mediator daze_dpmi_exception_frame)

# The caller-owned real-mode reflection for one parsed 0301h request. It runs
# the real-mode procedure on the parked gate's vCPU, serves real-mode INTs
# through the same runner gate contract as preflight, and resumes the gate to
# its protected client after the far return.
add_library(daze_kvm_rm_procedure STATIC backend/kvm/rm_procedure.c)
daze_configure_c11_pedantic_target(daze_kvm_rm_procedure PUBLIC)
target_link_libraries(daze_kvm_rm_procedure PUBLIC
  daze_kvm_machine daze_kvm_dpmi_entry daze_kvm_dpmi_mediator daze_kvm_runner_gate_resume
  daze_dpmi_request daze_dpmi_descriptor daze_kvm_write_batch
)

add_library(daze_kvm_state_save_gate STATIC backend/kvm/gate/state_save.c)
daze_configure_c11_pedantic_target(daze_kvm_state_save_gate PUBLIC)
target_link_libraries(daze_kvm_state_save_gate PUBLIC daze_kvm_dpmi_entry daze_dpmi_alternate_state)

add_library(daze_kvm_raw_switch_gate STATIC backend/kvm/gate/raw_switch.c)
daze_configure_c11_pedantic_target(daze_kvm_raw_switch_gate PUBLIC)
target_link_libraries(daze_kvm_raw_switch_gate PUBLIC daze_kvm_dpmi_entry daze_dpmi_alternate_state)

add_executable(daze
  main.c
  runtime/launch.c
  runtime/backend_runner.c
  runtime/runtime_main.c
  dpmi/transition_artifacts.c
  dpmi/advertisement.c
  dos/date.c
  dos/fcb.c
  dos/find_result.c
  dos/exec_request.c
  dos/exec_psp.c
  dos/exec_image.c
  dos/exec_loader.c
  dos/file_attrs.c
  dos/file_time.c
  dos/country.c
  loader/image.c
  bios/timer.c
  bios/rtc.c
)

if(DAZE_HAS_UNICORN)
  target_sources(daze PRIVATE
    backend/unicorn/unicorn_run.c
    backend/unicorn/unicorn_image.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
    backend/unicorn/unicorn_registers.c
    backend/unicorn/bios_adapter.c
  )
endif()

daze_configure_c11_target(daze PRIVATE)
target_compile_definitions(daze PRIVATE DAZE_VERSION="${DAZE_VERSION}")
if(DAZE_HAS_UNICORN)
  target_compile_definitions(daze PRIVATE DAZE_HAS_UNICORN=1)
else()
  target_compile_definitions(daze PRIVATE DAZE_HAS_UNICORN=0)
endif()
target_link_libraries(daze PRIVATE
  daze_backend_selection
  daze_command_result
  daze_dosfs
  daze_dos_int21_service
  daze_dos_memory
  daze_dpmi_descriptor
  daze_dpmi_exception_frame
  daze_dpmi_linear_memory
  daze_dpmi_request
  daze_dpmi_process_state
  daze_kvm_prepared_request
  daze_kvm_candidate_observation
  daze_kvm_selected_operation
  daze_kvm_selection_diagnostic
  daze_kvm_selection_metrics
  daze_guest_memory_layout
  daze_mz_layout
  daze_metrics
  ${DAZE_UNICORN_LINK_LIBRARIES}
)

if(DAZE_BUILD_STATIC)
  # Link the C runtime statically; static backend dependencies are linked separately.
  target_link_options(daze PRIVATE -static -static-libgcc)
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(daze PRIVATE -s)
  endif()
endif()

# Keep Daze runnable when Unicorn is supplied from a local build tree. A
# statically linked binary has no runtime library path requirement.
if(NOT DAZE_BUILD_STATIC AND DAZE_HAS_UNICORN)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  set_target_properties(daze PROPERTIES
    BUILD_RPATH "${UNICORN_LIBRARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
else()
  set_target_properties(daze PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()

add_subdirectory("${CMAKE_SOURCE_DIR}/tests" "${CMAKE_BINARY_DIR}/tests")
