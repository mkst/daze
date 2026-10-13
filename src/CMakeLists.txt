# Pedantic C11 is the default for libraries/tests; launcher uses C11 without -Wpedantic.
function(daze_configure_c11_pedantic_target target visibility)
  target_compile_features(${target} ${visibility} c_std_11)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endfunction()

function(daze_configure_c11_target target visibility)
  target_compile_features(${target} ${visibility} c_std_11)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
endfunction()

function(daze_register_simple_contract_test name target)
if(BUILD_TESTING)
    add_test(NAME "${name}" COMMAND "${target}")
endif()

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

if(BUILD_TESTING)
  add_executable(int21_service_contract_test
    dos/int21_service_contract_test.c
  )
  daze_configure_c11_pedantic_target(int21_service_contract_test PRIVATE)
  target_link_libraries(int21_service_contract_test PRIVATE daze_dos_int21_service)
  daze_register_simple_contract_test(int21-service-contract int21_service_contract_test)
  add_executable(int21_boundary_contract_test dos/int21_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(int21_boundary_contract_test PRIVATE)
  target_link_libraries(int21_boundary_contract_test PRIVATE daze_dos_int21_service)
  daze_register_simple_contract_test(int21-boundary-contract int21_boundary_contract_test)
endif()


add_library(daze_metrics STATIC
  metrics/metrics.c
)

if(BUILD_TESTING)
  add_executable(metrics_contract_test metrics/metrics_contract_test.c)
  daze_configure_c11_pedantic_target(metrics_contract_test PRIVATE)
  target_link_libraries(metrics_contract_test PRIVATE daze_metrics)
  daze_register_simple_contract_test(metrics-contract metrics_contract_test)
endif()

add_library(daze_mz_layout STATIC
  loader/mz_layout.c
)
daze_configure_c11_pedantic_target(daze_mz_layout PUBLIC)

if(BUILD_TESTING)
  add_executable(byte_order_contract_test
    arch/byte_order_contract_test.c
  )
  daze_configure_c11_pedantic_target(byte_order_contract_test PRIVATE)
  add_test(NAME byte-order-contract COMMAND byte_order_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(mz_layout_contract_test
    loader/mz_layout_contract_test.c
  )
  daze_configure_c11_pedantic_target(mz_layout_contract_test PRIVATE)
  target_link_libraries(mz_layout_contract_test PRIVATE daze_mz_layout)
  add_test(NAME mz-layout-contract COMMAND mz_layout_contract_test)
endif()


daze_configure_c11_pedantic_target(daze_metrics PUBLIC)

add_library(daze_dos_memory STATIC
  dos/memory.c
)

daze_configure_c11_pedantic_target(daze_dos_memory PUBLIC)

if(BUILD_TESTING)
  add_executable(dos_memory_contract_test
    dos/memory_contract_test.c
  )
  daze_configure_c11_pedantic_target(dos_memory_contract_test PRIVATE)
  target_link_libraries(dos_memory_contract_test PRIVATE daze_dos_memory)
  add_test(NAME dos-memory-contract COMMAND dos_memory_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(raw_vector_projection_contract_test
    runtime/raw_vector_projection_contract_test.c
  )
  daze_configure_c11_pedantic_target(raw_vector_projection_contract_test PRIVATE)
  target_link_libraries(raw_vector_projection_contract_test PRIVATE daze_dos_memory daze_dpmi_descriptor)
  daze_register_simple_contract_test(raw-vector-projection-contract raw_vector_projection_contract_test)
endif()


add_library(daze_dpmi_descriptor STATIC
  dpmi/descriptor.c
)

daze_configure_c11_pedantic_target(daze_dpmi_descriptor PUBLIC)

if(BUILD_TESTING)
  add_executable(dpmi_descriptor_contract_test
    dpmi/descriptor_contract_test.c
  )
  daze_configure_c11_pedantic_target(dpmi_descriptor_contract_test PRIVATE)
  target_link_libraries(dpmi_descriptor_contract_test PRIVATE daze_dpmi_descriptor)
  add_test(NAME dpmi-descriptor-contract COMMAND dpmi_descriptor_contract_test)
endif()


# Shared legacy frame serialization and placement validation; no guest-memory writes.
add_library(daze_dpmi_exception_frame STATIC
  dpmi/exception_frame.c
)
daze_configure_c11_pedantic_target(daze_dpmi_exception_frame PUBLIC)

if(BUILD_TESTING)
  add_executable(dpmi_exception_frame_contract_test
    dpmi/exception_frame_contract_test.c
  )
  daze_configure_c11_pedantic_target(dpmi_exception_frame_contract_test PRIVATE)
  target_link_libraries(dpmi_exception_frame_contract_test PRIVATE daze_dpmi_exception_frame)
  add_test(NAME dpmi-exception-frame-contract COMMAND dpmi_exception_frame_contract_test)
endif()


add_library(daze_dpmi_linear_memory STATIC
  dpmi/linear_memory.c
)

daze_configure_c11_pedantic_target(daze_dpmi_linear_memory PUBLIC)
if(TARGET dpmi_descriptor_contract_test)
target_link_libraries(dpmi_descriptor_contract_test PRIVATE daze_dpmi_linear_memory)
endif()

if(BUILD_TESTING)
  add_executable(dpmi_linear_memory_contract_test
    dpmi/linear_memory_contract_test.c
  )
  daze_configure_c11_pedantic_target(dpmi_linear_memory_contract_test PRIVATE)
  target_link_libraries(dpmi_linear_memory_contract_test PRIVATE daze_dpmi_linear_memory)
  add_test(NAME dpmi-linear-memory-contract COMMAND dpmi_linear_memory_contract_test)
endif()


add_library(daze_kvm_process_layout STATIC backend/kvm/process_layout.c)
daze_configure_c11_pedantic_target(daze_kvm_process_layout PUBLIC)
if(BUILD_TESTING)
  add_executable(kvm_process_layout_contract_test backend/kvm/process_layout_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_process_layout_contract_test PRIVATE)
  target_link_libraries(kvm_process_layout_contract_test PRIVATE daze_kvm_process_layout
                                                                 daze_guest_memory_layout)
  daze_register_simple_contract_test(kvm-process-layout-contract kvm_process_layout_contract_test)
endif()

# Shared-vs-KVM range boundary equivalence. Both helpers are header-inline,
# so this test links no library; it pins identical fits/overlap semantics.
if(BUILD_TESTING)
  add_executable(kvm_range_equivalence_contract_test backend/kvm/range_equivalence_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_range_equivalence_contract_test PRIVATE)
  daze_register_simple_contract_test(kvm-range-equivalence-contract kvm_range_equivalence_contract_test)
endif()

# Direct pin for the runner preflight gate: a past inversion here rejected
# every valid request while the suite stayed green.
if(BUILD_TESTING)
  add_executable(kvm_runner_process_valid_contract_test backend/kvm/runner/process_valid_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_runner_process_valid_contract_test PRIVATE)
  target_link_libraries(kvm_runner_process_valid_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-runner-process-valid-contract kvm_runner_process_valid_contract_test)
  add_executable(kvm_runner_boundary_contract_test backend/kvm/runner/boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_runner_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_runner_boundary_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-runner-boundary-contract kvm_runner_boundary_contract_test)
  add_executable(kvm_runner_execution_boundary_contract_test backend/kvm/runner/execution_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_runner_execution_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_runner_execution_boundary_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-runner-execution-boundary-contract kvm_runner_execution_boundary_contract_test)
  set_tests_properties(kvm-runner-execution-boundary-contract PROPERTIES
    LABELS "contract;local;requires-kvm" SKIP_RETURN_CODE 77 TIMEOUT 10)
endif()

# Shared guest-memory ownership inventory and launch-time validation. Links
# the DPMI linear allocator only as the single source of arena-base truth.
add_library(daze_guest_memory_layout STATIC runtime/guest_memory_layout.c)
daze_configure_c11_pedantic_target(daze_guest_memory_layout PUBLIC)
target_link_libraries(daze_guest_memory_layout PRIVATE daze_dpmi_linear_memory)
if(BUILD_TESTING)
  add_executable(guest_memory_layout_contract_test runtime/guest_memory_layout_contract_test.c)
  daze_configure_c11_pedantic_target(guest_memory_layout_contract_test PRIVATE)
  target_link_libraries(guest_memory_layout_contract_test PRIVATE daze_guest_memory_layout)
  daze_register_simple_contract_test(guest-memory-layout-contract guest_memory_layout_contract_test)
  add_executable(guest_memory_layout_boundary_contract_test runtime/guest_memory_layout_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(guest_memory_layout_boundary_contract_test PRIVATE)
  target_link_libraries(guest_memory_layout_boundary_contract_test PRIVATE daze_guest_memory_layout)
  daze_register_simple_contract_test(guest-memory-layout-boundary-contract guest_memory_layout_boundary_contract_test)
endif()


# Shared DPMI request/result services used by Unicorn dispatch and the KVM mediator.
add_library(daze_dpmi_request STATIC
  dpmi/request.c
)
daze_configure_c11_pedantic_target(daze_dpmi_request PUBLIC)
target_link_libraries(daze_dpmi_request PUBLIC daze_dpmi_descriptor daze_dpmi_linear_memory daze_dos_memory)

if(BUILD_TESTING)
  add_executable(dpmi_request_contract_test
    dpmi/request_contract_test.c
  )
  daze_configure_c11_pedantic_target(dpmi_request_contract_test PRIVATE)
  target_link_libraries(dpmi_request_contract_test PRIVATE daze_dpmi_request)
  add_test(NAME dpmi-request-contract COMMAND dpmi_request_contract_test)
endif()


add_library(daze_dpmi_alternate_state STATIC
  dpmi/alternate_state.c
)
daze_configure_c11_pedantic_target(daze_dpmi_alternate_state PUBLIC)

if(BUILD_TESTING)
  add_executable(dpmi_alternate_state_contract_test
    dpmi/alternate_state_contract_test.c
  )
  daze_configure_c11_pedantic_target(dpmi_alternate_state_contract_test PRIVATE)
  target_link_libraries(dpmi_alternate_state_contract_test PRIVATE daze_dpmi_alternate_state)
  daze_register_simple_contract_test(dpmi-alternate-state-contract dpmi_alternate_state_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dosfs_contract_test
    dos/fs/dosfs_contract_test.c
  )
  daze_configure_c11_pedantic_target(dosfs_contract_test PRIVATE)
  target_link_libraries(dosfs_contract_test PRIVATE daze_dosfs)
  add_test(NAME dosfs-contract COMMAND dosfs_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_process_state_contract_test dos/process_state_contract_test.c)
  daze_configure_c11_pedantic_target(dos_process_state_contract_test PRIVATE)
  target_link_libraries(dos_process_state_contract_test PRIVATE daze_dosfs)
  daze_register_simple_contract_test(dos-process-state-contract dos_process_state_contract_test)
endif()


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
  "${CMAKE_SOURCE_DIR}/tests/unit/support"
)

if(BUILD_TESTING)
  add_executable(image_process_contract_test
    loader/image_process_contract_test.c
    loader/image.c
  )
  daze_configure_c11_pedantic_target(image_process_contract_test PRIVATE)
  add_test(NAME image-process-contract COMMAND image_process_contract_test)
endif()


add_library(daze_backend_selection STATIC runtime/backend_selection.c runtime/backend_request.c)
daze_configure_c11_pedantic_target(daze_backend_selection PUBLIC)
if(BUILD_TESTING)
  add_executable(backend_selection_contract_test runtime/backend_selection_contract_test.c)
  daze_configure_c11_pedantic_target(backend_selection_contract_test PRIVATE)
  target_link_libraries(backend_selection_contract_test PRIVATE daze_backend_selection)
  daze_register_simple_contract_test(backend-selection-contract backend_selection_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(backend_request_contract_test runtime/backend_request_contract_test.c)
  daze_configure_c11_pedantic_target(backend_request_contract_test PRIVATE)
  target_link_libraries(backend_request_contract_test PRIVATE daze_backend_selection)
  daze_register_simple_contract_test(backend-request-contract backend_request_contract_test)
endif()


add_library(daze_kvm_machine_candidate STATIC backend/kvm/machine_candidate.c)
daze_configure_c11_pedantic_target(daze_kvm_machine_candidate PUBLIC)
target_link_libraries(daze_kvm_machine_candidate PUBLIC daze_backend_selection)
if(BUILD_TESTING)
  add_executable(kvm_machine_candidate_contract_test backend/kvm/machine_candidate_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_machine_candidate_contract_test PRIVATE)
  target_link_libraries(kvm_machine_candidate_contract_test PRIVATE daze_kvm_machine_candidate)
  daze_register_simple_contract_test(kvm-machine-candidate-contract kvm_machine_candidate_contract_test)
endif()


add_library(daze_kvm_machine_diagnostic STATIC backend/kvm/machine_diagnostic.c)
daze_configure_c11_pedantic_target(daze_kvm_machine_diagnostic PUBLIC)
if(BUILD_TESTING)
  add_executable(kvm_machine_diagnostic_contract_test backend/kvm/machine_diagnostic_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_machine_diagnostic_contract_test PRIVATE)
  target_link_libraries(kvm_machine_diagnostic_contract_test PRIVATE daze_kvm_machine_diagnostic
    daze_kvm_machine_candidate)
  daze_register_simple_contract_test(kvm-machine-diagnostic-contract kvm_machine_diagnostic_contract_test)
endif()


add_library(daze_kvm_candidate_observation STATIC backend/kvm/diagnostic/candidate_observation.c)
daze_configure_c11_pedantic_target(daze_kvm_candidate_observation PUBLIC)
target_link_libraries(daze_kvm_candidate_observation PUBLIC
  daze_kvm_machine daze_kvm_machine_candidate daze_kvm_machine_diagnostic
)
if(BUILD_TESTING)
  add_executable(kvm_candidate_observation_contract_test backend/kvm/diagnostic/candidate_observation_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_candidate_observation_contract_test PRIVATE)
  target_link_libraries(kvm_candidate_observation_contract_test PRIVATE daze_kvm_candidate_observation)
  daze_register_simple_contract_test(kvm-candidate-observation-contract kvm_candidate_observation_contract_test)
  add_test(NAME kvm-candidate-observation-host COMMAND kvm_candidate_observation_contract_test --host)
  set_tests_properties(kvm-candidate-observation-host PROPERTIES SKIP_RETURN_CODE 77)
endif()


add_library(daze_kvm_prepared_request STATIC backend/kvm/prepared_request.c)
daze_configure_c11_pedantic_target(daze_kvm_prepared_request PUBLIC)
target_link_libraries(daze_kvm_prepared_request PUBLIC daze_kvm_runner)
if(BUILD_TESTING)
  add_executable(kvm_prepared_request_contract_test backend/kvm/prepared_request_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_prepared_request_contract_test PRIVATE)
  target_link_libraries(kvm_prepared_request_contract_test PRIVATE daze_kvm_prepared_request)
  daze_register_simple_contract_test(kvm-prepared-request-contract kvm_prepared_request_contract_test)
endif()


add_library(daze_kvm_command_result STATIC backend/kvm/command/result.c)
daze_configure_c11_pedantic_target(daze_kvm_command_result PUBLIC)
if(BUILD_TESTING)
  add_executable(kvm_command_result_contract_test backend/kvm/command/result_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_command_result_contract_test PRIVATE)
  target_link_libraries(kvm_command_result_contract_test PRIVATE daze_kvm_command_result)
  daze_register_simple_contract_test(kvm-command-result-contract kvm_command_result_contract_test)
endif()


add_library(daze_command_result STATIC runtime/command_result.c)
daze_configure_c11_pedantic_target(daze_command_result PUBLIC)
if(BUILD_TESTING)
  add_executable(command_result_contract_test runtime/command_result_contract_test.c)
  daze_configure_c11_pedantic_target(command_result_contract_test PRIVATE)
  target_link_libraries(command_result_contract_test PRIVATE daze_command_result)
  daze_register_simple_contract_test(command-result-contract command_result_contract_test)
endif()


add_library(daze_dpmi_process_state STATIC dpmi/process_state.c)
daze_configure_c11_pedantic_target(daze_dpmi_process_state PUBLIC)
target_link_libraries(daze_dpmi_process_state PUBLIC daze_dpmi_linear_memory)
if(BUILD_TESTING)
  add_executable(dpmi_process_state_contract_test dpmi/dpmi_process_state_contract_test.c)
  daze_configure_c11_pedantic_target(dpmi_process_state_contract_test PRIVATE)
  target_link_libraries(dpmi_process_state_contract_test PRIVATE daze_dpmi_process_state)
  daze_register_simple_contract_test(dpmi-process-state-contract dpmi_process_state_contract_test)
endif()


add_library(daze_kvm_machine STATIC backend/kvm/machine.c)
daze_configure_c11_pedantic_target(daze_kvm_machine PUBLIC)
if(BUILD_TESTING)
  add_executable(kvm_machine_contract_test backend/kvm/machine_contract_test.c loader/image.c)
  daze_configure_c11_pedantic_target(kvm_machine_contract_test PRIVATE)
  target_link_libraries(kvm_machine_contract_test PRIVATE daze_kvm_machine)
  add_test(NAME kvm-machine-contract COMMAND kvm_machine_contract_test)
  set_tests_properties(kvm-machine-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_executable(kvm_machine_sync_contract_test backend/kvm/machine_sync_contract_test.c)
  add_executable(kvm_machine_boundary_contract_test backend/kvm/machine_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_machine_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_machine_boundary_contract_test PRIVATE daze_kvm_machine)
  daze_register_simple_contract_test(kvm-machine-boundary-contract kvm_machine_boundary_contract_test)
  set_tests_properties(kvm-machine-boundary-contract PROPERTIES SKIP_RETURN_CODE 77 LABELS "contract;local;requires-kvm")
  daze_configure_c11_pedantic_target(kvm_machine_sync_contract_test PRIVATE)
  target_link_libraries(kvm_machine_sync_contract_test PRIVATE daze_kvm_machine)
  add_test(NAME kvm-machine-sync-contract COMMAND kvm_machine_sync_contract_test)
  set_tests_properties(kvm-machine-sync-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_test(NAME kvm-machine-invalid COMMAND kvm_machine_contract_test --invalid)
endif()


if(BUILD_TESTING)
  add_executable(kvm_machine_snapshot_contract_test backend/kvm/machine_snapshot_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_machine_snapshot_contract_test PRIVATE)
  target_link_libraries(kvm_machine_snapshot_contract_test PRIVATE daze_kvm_machine)
  add_test(NAME kvm-machine-snapshot-contract COMMAND kvm_machine_snapshot_contract_test)
  set_tests_properties(kvm-machine-snapshot-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


add_library(daze_kvm_child_context STATIC backend/kvm/child_context.c)
target_link_libraries(daze_kvm_child_context PUBLIC daze_dpmi_descriptor)
daze_configure_c11_pedantic_target(daze_kvm_child_context PUBLIC)
target_link_libraries(daze_kvm_child_context PUBLIC daze_kvm_machine daze_dosfs daze_dos_memory)
if(BUILD_TESTING)
  add_executable(kvm_child_context_contract_test backend/kvm/child_context_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_child_context_contract_test PRIVATE)
  target_link_libraries(kvm_child_context_contract_test PRIVATE daze_kvm_child_context)
  add_test(NAME kvm-child-context-contract COMMAND kvm_child_context_contract_test)
  set_tests_properties(kvm-child-context-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_executable(kvm_child_context_boundary_contract_test backend/kvm/child_context_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_child_context_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_child_context_boundary_contract_test PRIVATE daze_kvm_child_context)
  daze_register_simple_contract_test(kvm-child-context-boundary-contract kvm_child_context_boundary_contract_test)
  add_test(NAME kvm-child-context-table-contract COMMAND kvm_child_context_boundary_contract_test --kvm)
  set_tests_properties(kvm-child-context-table-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


if(BUILD_TESTING)
  add_executable(kvm_machine_init_observability_contract_test
    backend/kvm/machine_init_observability_contract_test.c
  )
  daze_configure_c11_pedantic_target(kvm_machine_init_observability_contract_test PRIVATE)
  target_link_libraries(kvm_machine_init_observability_contract_test PRIVATE daze_kvm_machine)
  add_test(NAME kvm-machine-init-observability COMMAND kvm_machine_init_observability_contract_test)
  set_tests_properties(kvm-machine-init-observability PROPERTIES SKIP_RETURN_CODE 77)
endif()


if(BUILD_TESTING)
  add_test(NAME kvm-machine-stub-boundary
    COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only
            -Wall -Wextra -Wpedantic -Werror
            -U__linux__ -U__linux -Ulinux
            "-I${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm"
            "-I${CMAKE_CURRENT_SOURCE_DIR}/runtime"
            "-I${CMAKE_CURRENT_SOURCE_DIR}/metrics"
            "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/machine.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/backend/kvm/machine_init_observability_contract_test.c"
  )
endif()


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
  daze_kvm_machine daze_kvm_runner_gate_resume daze_dos_int21_service daze_dosfs daze_dos_memory daze_mz_layout daze_kvm_process_layout daze_guest_memory_layout
)

if(BUILD_TESTING AND DAZE_HAS_UNICORN)
  add_executable(int21_adapter_contract_test
    dos/int21_adapter_contract_test.c
  )
  daze_configure_c11_pedantic_target(int21_adapter_contract_test PRIVATE)
  target_link_libraries(int21_adapter_contract_test PRIVATE
    daze_dos_int21_service daze_kvm_runner ${DAZE_UNICORN_LINK_LIBRARIES}
  )
  daze_register_simple_contract_test(int21-adapter-contract int21_adapter_contract_test)
endif()


add_library(daze_kvm_dpmi_entry STATIC backend/kvm/dpmi/entry.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_entry PUBLIC)
target_link_libraries(daze_kvm_dpmi_entry PUBLIC daze_kvm_machine daze_kvm_runner)
if(BUILD_TESTING)
  add_executable(kvm_dpmi_entry_contract_test backend/kvm/dpmi/entry_contract_test.c)
  add_executable(kvm_virtual_interrupt_contract_test backend/kvm/gate/virtual_interrupt_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_virtual_interrupt_contract_test PRIVATE)
  target_link_libraries(kvm_virtual_interrupt_contract_test PRIVATE daze_kvm_protected_gate daze_kvm_child_context)
  add_test(NAME kvm-virtual-interrupt-contract COMMAND kvm_virtual_interrupt_contract_test)
  set_tests_properties(kvm-virtual-interrupt-contract PROPERTIES SKIP_RETURN_CODE 77)
  daze_configure_c11_pedantic_target(kvm_dpmi_entry_contract_test PRIVATE)
  target_link_libraries(kvm_dpmi_entry_contract_test PRIVATE daze_kvm_dpmi_entry daze_kvm_protected_gate)
  add_executable(kvm_entry_observation_contract_test backend/kvm/dpmi/entry_observation_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_entry_observation_contract_test PRIVATE)
  target_link_libraries(kvm_entry_observation_contract_test PRIVATE daze_kvm_dpmi_entry)
  daze_register_simple_contract_test(kvm-entry-observation-contract kvm_entry_observation_contract_test)
  add_test(NAME kvm-dpmi-entry-contract COMMAND kvm_dpmi_entry_contract_test)
  set_tests_properties(kvm-dpmi-entry-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


# Prepares process state and validates writes without executing the vCPU.
add_library(daze_kvm_dpmi_transition_state STATIC backend/kvm/dpmi/transition_state.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_transition_state PUBLIC)
target_link_libraries(daze_kvm_dpmi_transition_state PUBLIC
  daze_dpmi_linear_memory daze_dpmi_request daze_metrics daze_dpmi_process_state
)
if(BUILD_TESTING)
  add_executable(kvm_dpmi_transition_state_contract_test
    backend/kvm/dpmi/transition_state_contract_test.c
  )
  daze_configure_c11_pedantic_target(kvm_dpmi_transition_state_contract_test PRIVATE)
  target_link_libraries(kvm_dpmi_transition_state_contract_test PRIVATE daze_kvm_dpmi_transition_state)
  daze_register_simple_contract_test(kvm-dpmi-transition-state-contract kvm_dpmi_transition_state_contract_test)
endif()


# Validates/copies artifacts after state preparation; does not execute the vCPU.
add_library(daze_kvm_dpmi_transition_writer STATIC backend/kvm/dpmi/transition_writer.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_transition_writer PUBLIC)
target_link_libraries(daze_kvm_dpmi_transition_writer PUBLIC daze_kvm_dpmi_transition_state)
if(BUILD_TESTING)
  add_executable(kvm_dpmi_transition_writer_contract_test
    backend/kvm/dpmi/transition_writer_contract_test.c
  )
  daze_configure_c11_pedantic_target(kvm_dpmi_transition_writer_contract_test PRIVATE)
  target_link_libraries(kvm_dpmi_transition_writer_contract_test PRIVATE daze_kvm_dpmi_transition_writer)
  daze_register_simple_contract_test(kvm-dpmi-transition-writer-contract kvm_dpmi_transition_writer_contract_test)
endif()


# Resumes a guest IRET with a caller reply; service policy remains outside this helper.
add_library(daze_kvm_runner_gate_resume STATIC backend/kvm/gate/runner_resume.c)
daze_configure_c11_pedantic_target(daze_kvm_runner_gate_resume PUBLIC)
target_link_libraries(daze_kvm_runner_gate_resume PUBLIC daze_kvm_machine)
if(BUILD_TESTING)
  add_executable(kvm_runner_gate_resume_contract_test
    backend/kvm/gate/runner_resume_contract_test.c
  )
  daze_configure_c11_pedantic_target(kvm_runner_gate_resume_contract_test PRIVATE)
  target_link_libraries(kvm_runner_gate_resume_contract_test PRIVATE daze_kvm_runner_gate_resume)
  add_test(NAME kvm-runner-gate-resume-contract COMMAND kvm_runner_gate_resume_contract_test)
  set_tests_properties(kvm-runner-gate-resume-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_executable(kvm_runner_resume_boundary_contract_test backend/kvm/gate/runner_resume_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_runner_resume_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_runner_resume_boundary_contract_test PRIVATE daze_kvm_runner_gate_resume)
  daze_register_simple_contract_test(kvm-runner-resume-boundary-contract kvm_runner_resume_boundary_contract_test)
  add_test(NAME kvm-runner-resume-cpu-boundary-contract COMMAND kvm_runner_resume_boundary_contract_test --kvm)
  set_tests_properties(kvm-runner-resume-cpu-boundary-contract PROPERTIES LABELS "contract;local;requires-kvm" SKIP_RETURN_CODE 77 TIMEOUT 10)
endif()


# Same-machine wake-and-gate re-presentation: reaches the gate-resume HLT
# successor, then wakes the halted vCPU via KVM_INTERRUPT into a pre-installed
# guest IVT[0x30] handler that re-presents the gate-equivalent frame and lands
# in protected mode at its own terminal.
if(BUILD_TESTING)
  add_executable(kvm_hlt_wake_gate_contract_test backend/kvm/gate/hlt_wake_gate_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_hlt_wake_gate_contract_test PRIVATE)
  target_link_libraries(kvm_hlt_wake_gate_contract_test PRIVATE
    daze_kvm_runner_gate_resume daze_kvm_dpmi_entry
  )
  add_test(NAME kvm-hlt-wake-gate-contract COMMAND kvm_hlt_wake_gate_contract_test)
  set_tests_properties(kvm-hlt-wake-gate-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


if(BUILD_TESTING)
  add_executable(kvm_preflight_boundary_broker_contract_test
    backend/kvm/diagnostic/preflight_boundary_broker_contract_test.c
  )
  daze_configure_c11_pedantic_target(kvm_preflight_boundary_broker_contract_test PRIVATE)
  target_link_libraries(kvm_preflight_boundary_broker_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-preflight-boundary-broker-contract kvm_preflight_boundary_broker_contract_test)
  add_executable(kvm_int21_boundary_contract_test backend/kvm/int21_boundary_contract_test.c)
  add_executable(kvm_bios_boundary_contract_test backend/kvm/bios_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_bios_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_bios_boundary_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-bios-boundary-contract kvm_bios_boundary_contract_test)
  daze_configure_c11_pedantic_target(kvm_int21_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_int21_boundary_contract_test PRIVATE daze_kvm_runner)
  daze_register_simple_contract_test(kvm-int21-boundary-contract kvm_int21_boundary_contract_test)
  add_test(NAME kvm-int21-cpu-translation-contract COMMAND kvm_int21_boundary_contract_test --kvm)
  set_tests_properties(kvm-int21-cpu-translation-contract PROPERTIES LABELS "contract;local;requires-kvm" SKIP_RETURN_CODE 77 TIMEOUT 10)
endif()


if(BUILD_TESTING)
  add_executable(kvm_generic_preflight_contract_test backend/kvm/diagnostic/generic_preflight_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_generic_preflight_contract_test PRIVATE)
  target_link_libraries(kvm_generic_preflight_contract_test PRIVATE daze_kvm_runner)
  add_test(NAME kvm-generic-preflight-contract COMMAND kvm_generic_preflight_contract_test)
  set_tests_properties(kvm-generic-preflight-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


if(BUILD_TESTING)
  add_executable(kvm_runner_resume_existing_contract_test
    backend/kvm/diagnostic/runner_resume_existing_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_runner_resume_existing_contract_test PRIVATE)
  target_link_libraries(kvm_runner_resume_existing_contract_test PRIVATE daze_kvm_runner)
  add_test(NAME kvm-runner-resume-existing-contract COMMAND kvm_runner_resume_existing_contract_test)
  set_tests_properties(kvm-runner-resume-existing-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


add_library(daze_kvm_transition_plan STATIC
  backend/kvm/transition/plan.c
  dpmi/transition_artifacts.c
)
daze_configure_c11_pedantic_target(daze_kvm_transition_plan PUBLIC)
target_link_libraries(daze_kvm_transition_plan PUBLIC daze_dpmi_linear_memory daze_guest_memory_layout)
if(BUILD_TESTING)
  add_executable(kvm_transition_plan_contract_test backend/kvm/transition/plan_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_transition_plan_contract_test PRIVATE)
  target_link_libraries(kvm_transition_plan_contract_test PRIVATE daze_kvm_transition_plan)
  daze_register_simple_contract_test(kvm-transition-plan-contract kvm_transition_plan_contract_test)
endif()


add_library(daze_kvm_command_owner STATIC backend/kvm/command/owner.c backend/kvm/command/boundary.c)
daze_configure_c11_pedantic_target(daze_kvm_command_owner PUBLIC)
target_link_libraries(daze_kvm_command_owner PUBLIC
  daze_kvm_runner daze_kvm_child_context daze_kvm_dpmi_entry daze_kvm_transition_plan
  daze_kvm_dpmi_transition_writer daze_kvm_protected_gate daze_kvm_state_save_gate
  daze_kvm_raw_switch_gate daze_kvm_runner_gate_resume daze_kvm_rm_procedure
)
if(BUILD_TESTING)
  add_executable(kvm_command_boundary_contract_test backend/kvm/command/boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_command_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_command_boundary_contract_test PRIVATE daze_kvm_command_owner)
  daze_register_simple_contract_test(kvm-command-boundary-contract kvm_command_boundary_contract_test)
endif()

if(BUILD_TESTING)
  add_executable(kvm_command_owner_contract_test backend/kvm/command/owner_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_command_owner_contract_test PRIVATE)
  target_link_libraries(kvm_command_owner_contract_test PRIVATE daze_kvm_command_owner daze_kvm_command_result)
  add_executable(kvm_owner_input_contract_test backend/kvm/command/owner_input_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_owner_input_contract_test PRIVATE)
  target_link_libraries(kvm_owner_input_contract_test PRIVATE daze_kvm_command_owner)
  daze_register_simple_contract_test(kvm-owner-input-contract kvm_owner_input_contract_test)
  add_executable(kvm_owner_boundary_contract_test backend/kvm/command/owner_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_owner_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_owner_boundary_contract_test PRIVATE daze_kvm_command_owner)
  daze_register_simple_contract_test(kvm-owner-boundary-contract kvm_owner_boundary_contract_test)
  add_test(NAME kvm-command-owner-contract COMMAND kvm_command_owner_contract_test)
  set_tests_properties(kvm-command-owner-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_test(NAME kvm-command-owner-trace-contract COMMAND kvm_command_owner_contract_test --trace-contract)
  set_tests_properties(kvm-command-owner-trace-contract PROPERTIES
    SKIP_RETURN_CODE 77 LABELS "local;contract;requires-kvm")
endif()

if(BUILD_TESTING)
  add_executable(kvm_command_exec_reply_contract_test backend/kvm/command/exec_reply_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_command_exec_reply_contract_test PRIVATE)
  target_link_libraries(kvm_command_exec_reply_contract_test PRIVATE daze_kvm_command_owner)
  add_test(NAME kvm-command-exec-reply-contract COMMAND kvm_command_exec_reply_contract_test)
  set_tests_properties(kvm-command-exec-reply-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(BUILD_TESTING)
  add_executable(kvm_exec_parent_lifecycle_contract_test
    backend/kvm/command/exec_parent_lifecycle_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_exec_parent_lifecycle_contract_test PRIVATE)
  target_link_libraries(kvm_exec_parent_lifecycle_contract_test PRIVATE daze_kvm_command_owner daze_kvm_command_result)
  add_test(NAME kvm-exec-parent-lifecycle-contract COMMAND kvm_exec_parent_lifecycle_contract_test)
  set_tests_properties(kvm-exec-parent-lifecycle-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_test(NAME kvm-exec-owner-trace-contract COMMAND kvm_exec_parent_lifecycle_contract_test --trace-contract)
  set_tests_properties(kvm-exec-owner-trace-contract PROPERTIES
    SKIP_RETURN_CODE 77 LABELS "local;contract;requires-kvm")
endif()


# Pure normal-runtime configuration builder. It owns no KVM machine and is
# tested independently of KVM device availability.
add_library(daze_kvm_normal_transition_config STATIC backend/kvm/transition/normal_config.c)
daze_configure_c11_pedantic_target(daze_kvm_normal_transition_config PUBLIC)
target_link_libraries(daze_kvm_normal_transition_config PUBLIC daze_kvm_command_owner daze_guest_memory_layout)
target_link_libraries(daze_kvm_command_owner PUBLIC daze_kvm_normal_transition_config)
if(BUILD_TESTING)
  add_executable(kvm_normal_transition_config_contract_test
    backend/kvm/transition/normal_config_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_normal_transition_config_contract_test PRIVATE)
  target_link_libraries(kvm_normal_transition_config_contract_test PRIVATE daze_kvm_normal_transition_config)
  daze_register_simple_contract_test(kvm-normal-transition-config-contract kvm_normal_transition_config_contract_test)
endif()


# Normal-placement composition from prepared launch facts to the KVM owner.
add_library(daze_kvm_normal_operation STATIC backend/kvm/normal_operation.c)
daze_configure_c11_pedantic_target(daze_kvm_normal_operation PUBLIC)
target_link_libraries(daze_kvm_normal_operation PUBLIC
  daze_kvm_normal_transition_config daze_kvm_command_result
)
if(BUILD_TESTING)
  add_executable(kvm_normal_operation_contract_test backend/kvm/normal_operation_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_normal_operation_contract_test PRIVATE)
  target_link_libraries(kvm_normal_operation_contract_test PRIVATE
    daze_kvm_normal_operation daze_kvm_prepared_request
  )
  daze_register_simple_contract_test(kvm-normal-operation-contract kvm_normal_operation_contract_test)
  add_executable(kvm_normal_operation_boundary_contract_test
    backend/kvm/normal_operation_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_normal_operation_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_normal_operation_boundary_contract_test PRIVATE daze_kvm_normal_operation)
  daze_register_simple_contract_test(kvm-normal-operation-boundary-contract
    kvm_normal_operation_boundary_contract_test)
  add_executable(kvm_normal_operation_execution_contract_test
    backend/kvm/normal_operation_execution_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_normal_operation_execution_contract_test PRIVATE)
  target_link_libraries(kvm_normal_operation_execution_contract_test PRIVATE daze_kvm_normal_operation)
  daze_register_simple_contract_test(kvm-normal-operation-execution-contract
    kvm_normal_operation_execution_contract_test)
  set_tests_properties(kvm-normal-operation-execution-contract PROPERTIES
    SKIP_RETURN_CODE 77 LABELS "local;contract;requires-kvm" TIMEOUT 10)
endif()


# Runs the prepared normal KVM operation after the launcher selects KVM.
add_library(daze_kvm_selected_operation STATIC backend/kvm/selected_operation.c)
daze_configure_c11_pedantic_target(daze_kvm_selected_operation PUBLIC)
target_link_libraries(daze_kvm_selected_operation PUBLIC daze_kvm_normal_operation)
if(BUILD_TESTING)
  add_executable(kvm_selected_operation_contract_test backend/kvm/selected_operation_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_selected_operation_contract_test PRIVATE)
  target_link_libraries(kvm_selected_operation_contract_test PRIVATE daze_kvm_selected_operation)
  daze_register_simple_contract_test(kvm-selected-operation-contract kvm_selected_operation_contract_test)
endif()


add_library(daze_kvm_selection_diagnostic STATIC backend/kvm/diagnostic/selection.c)
daze_configure_c11_pedantic_target(daze_kvm_selection_diagnostic PUBLIC)
target_link_libraries(daze_kvm_selection_diagnostic PUBLIC
  daze_kvm_candidate_observation daze_kvm_selected_operation
)
if(BUILD_TESTING)
  add_executable(kvm_selection_diagnostic_contract_test backend/kvm/diagnostic/selection_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_selection_diagnostic_contract_test PRIVATE)
  target_link_libraries(kvm_selection_diagnostic_contract_test PRIVATE daze_kvm_selection_diagnostic)
  daze_register_simple_contract_test(kvm-selection-diagnostic-contract kvm_selection_diagnostic_contract_test)
endif()


add_library(daze_kvm_selection_metrics STATIC backend/kvm/diagnostic/selection_metrics.c)
daze_configure_c11_pedantic_target(daze_kvm_selection_metrics PUBLIC)
target_link_libraries(daze_kvm_selection_metrics PUBLIC daze_kvm_selection_diagnostic)
if(BUILD_TESTING)
  add_executable(kvm_selection_metrics_contract_test backend/kvm/diagnostic/selection_metrics_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_selection_metrics_contract_test PRIVATE)
  target_link_libraries(kvm_selection_metrics_contract_test PRIVATE daze_kvm_selection_metrics)
  daze_register_simple_contract_test(kvm-selection-metrics-contract kvm_selection_metrics_contract_test)
endif()


# Shared 0301h Call Real Mode Procedure frame contract. It owns the bounded
# parse, far-return, and frame write-back semantics used by both the mediator
# (device-free) and the KVM real-mode reflection.
add_library(daze_dpmi_rm_frame STATIC dpmi/rm_frame.c)
daze_configure_c11_pedantic_target(daze_dpmi_rm_frame PUBLIC)
if(BUILD_TESTING)
  add_executable(dpmi_rm_frame_contract_test dpmi/rm_frame_contract_test.c)
  daze_configure_c11_pedantic_target(dpmi_rm_frame_contract_test PRIVATE)
  target_link_libraries(dpmi_rm_frame_contract_test PRIVATE daze_dpmi_rm_frame)
  daze_register_simple_contract_test(dpmi-rm-frame-contract dpmi_rm_frame_contract_test)
endif()


# Constructed protected-mode PIO/mailbox mediation. This verifies a KVM guest
# receives shared DPMI results through its own IRETD, without selecting a
# runtime backend or extending the ASPSX checkpoint.
add_library(daze_kvm_dpmi_mediator STATIC backend/kvm/dpmi/mediator.c)
daze_configure_c11_pedantic_target(daze_kvm_dpmi_mediator PUBLIC)
target_link_libraries(daze_kvm_dpmi_mediator PUBLIC daze_dpmi_request daze_dpmi_rm_frame)
if(BUILD_TESTING)
  add_library(daze_kvm_dpmi_mediator_test_driver STATIC ../tests/unit/support/mediator_test_driver.c)
  daze_configure_c11_pedantic_target(daze_kvm_dpmi_mediator_test_driver PUBLIC)
  target_link_libraries(daze_kvm_dpmi_mediator_test_driver PUBLIC daze_kvm_dpmi_mediator daze_kvm_machine)
  add_executable(kvm_dpmi_mediator_contract_test backend/kvm/dpmi/mediator_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_dpmi_mediator_contract_test PRIVATE)
  target_link_libraries(kvm_dpmi_mediator_contract_test PRIVATE daze_kvm_dpmi_mediator_test_driver)
  add_test(NAME kvm-dpmi-mediator-contract COMMAND kvm_dpmi_mediator_contract_test)
  set_tests_properties(kvm-dpmi-mediator-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


# This continuation-only gate retains the protected machine established by
# the transition and exchanges one caller-owned mediator record.
add_library(daze_kvm_protected_gate STATIC backend/kvm/gate/protected.c backend/kvm/gate/legacy_exception.c)
daze_configure_c11_pedantic_target(daze_kvm_protected_gate PUBLIC)
target_link_libraries(daze_kvm_protected_gate PUBLIC daze_kvm_dpmi_entry daze_kvm_dpmi_mediator daze_dpmi_exception_frame)
if(BUILD_TESTING)
  add_executable(kvm_legacy_exception_contract_test backend/kvm/gate/legacy_exception_contract_test.c)
  add_executable(kvm_protected_boundary_contract_test backend/kvm/gate/protected_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_protected_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_protected_boundary_contract_test PRIVATE daze_kvm_protected_gate)
  daze_register_simple_contract_test(kvm-protected-boundary-contract kvm_protected_boundary_contract_test)
  add_executable(kvm_protected_execution_contract_test backend/kvm/gate/protected_execution_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_protected_execution_contract_test PRIVATE)
  target_link_libraries(kvm_protected_execution_contract_test PRIVATE
    daze_kvm_protected_gate daze_kvm_dpmi_mediator_test_driver)
  daze_register_simple_contract_test(kvm-protected-execution-contract kvm_protected_execution_contract_test)
  set_tests_properties(kvm-protected-execution-contract PROPERTIES
    SKIP_RETURN_CODE 77 LABELS "local;contract;requires-kvm" TIMEOUT 10)
  daze_configure_c11_pedantic_target(kvm_legacy_exception_contract_test PRIVATE)
  target_link_libraries(kvm_legacy_exception_contract_test PRIVATE daze_kvm_protected_gate)
  add_test(NAME kvm-legacy-exception-contract COMMAND kvm_legacy_exception_contract_test)
  set_tests_properties(kvm-legacy-exception-contract PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 10)
  add_executable(kvm_legacy_exception_boundary_contract_test backend/kvm/gate/legacy_exception_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_legacy_exception_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_legacy_exception_boundary_contract_test PRIVATE daze_kvm_protected_gate)
  daze_register_simple_contract_test(kvm-legacy-exception-boundary-contract kvm_legacy_exception_boundary_contract_test)
endif()


# A client-selected protected vector needs a gate type matching its target
# descriptor's own D/B bit. Pure: no machine, no live guest, no /dev/kvm.
if(BUILD_TESTING)
  add_executable(kvm_client_gate_width_contract_test backend/kvm/gate/client_gate_width_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_client_gate_width_contract_test PRIVATE)
  target_link_libraries(kvm_client_gate_width_contract_test PRIVATE daze_kvm_protected_gate)
  add_test(NAME kvm-client-gate-width-contract COMMAND kvm_client_gate_width_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(kvm_default_dos_stub_contract_test backend/kvm/gate/default_dos_stub_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_default_dos_stub_contract_test PRIVATE)
  target_link_libraries(kvm_default_dos_stub_contract_test PRIVATE daze_kvm_protected_gate)
  daze_register_simple_contract_test(kvm-default-dos-stub-contract kvm_default_dos_stub_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(kvm_record_mailbox_contract_test backend/kvm/gate/record_mailbox_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_record_mailbox_contract_test PRIVATE)
  target_link_libraries(kvm_record_mailbox_contract_test PRIVATE daze_kvm_protected_gate)
  daze_register_simple_contract_test(kvm-record-mailbox-contract kvm_record_mailbox_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(kvm_idt_gate_contract_test backend/kvm/gate/idt_gate_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_idt_gate_contract_test PRIVATE)
  add_test(NAME kvm-idt-gate-contract COMMAND kvm_idt_gate_contract_test)
endif()


# The caller-owned real-mode reflection for one parsed 0301h request. It runs
# the real-mode procedure on the parked gate's vCPU, serves real-mode INTs
# through the same runner gate contract as preflight, and resumes the gate to
# its protected client after the far return.
add_library(daze_kvm_rm_procedure STATIC backend/kvm/rm_procedure.c)
daze_configure_c11_pedantic_target(daze_kvm_rm_procedure PUBLIC)
target_link_libraries(daze_kvm_rm_procedure PUBLIC
  daze_kvm_machine daze_kvm_dpmi_entry daze_kvm_dpmi_mediator daze_kvm_runner_gate_resume
  daze_dpmi_request
)

add_library(daze_kvm_state_save_gate STATIC backend/kvm/gate/state_save.c)
daze_configure_c11_pedantic_target(daze_kvm_state_save_gate PUBLIC)
target_link_libraries(daze_kvm_state_save_gate PUBLIC daze_kvm_dpmi_entry daze_dpmi_alternate_state)

add_library(daze_kvm_raw_switch_gate STATIC backend/kvm/gate/raw_switch.c)
daze_configure_c11_pedantic_target(daze_kvm_raw_switch_gate PUBLIC)
target_link_libraries(daze_kvm_raw_switch_gate PUBLIC daze_kvm_dpmi_entry daze_dpmi_alternate_state)

if(BUILD_TESTING)
  add_executable(kvm_rm_procedure_contract_test backend/kvm/rm_procedure_contract_test.c)
  add_executable(kvm_rm_procedure_boundary_contract_test backend/kvm/rm_procedure_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_rm_procedure_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_rm_procedure_boundary_contract_test PRIVATE daze_kvm_rm_procedure daze_dpmi_descriptor)
  daze_register_simple_contract_test(kvm-rm-procedure-boundary-contract kvm_rm_procedure_boundary_contract_test)
  daze_configure_c11_pedantic_target(kvm_rm_procedure_contract_test PRIVATE)
  target_link_libraries(kvm_rm_procedure_contract_test PRIVATE daze_kvm_rm_procedure daze_dpmi_descriptor)
  daze_register_simple_contract_test(kvm-rm-procedure-contract kvm_rm_procedure_contract_test)
  set_tests_properties(kvm-rm-procedure-contract PROPERTIES SKIP_RETURN_CODE 77 LABELS "contract;local;requires-kvm" TIMEOUT 10)
  add_executable(kvm_transition_boundary_contract_test backend/kvm/gate/transition_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(kvm_transition_boundary_contract_test PRIVATE)
  target_link_libraries(kvm_transition_boundary_contract_test PRIVATE daze_kvm_raw_switch_gate daze_kvm_state_save_gate daze_dpmi_descriptor)
  daze_register_simple_contract_test(kvm-transition-boundary-contract kvm_transition_boundary_contract_test)
  set_tests_properties(kvm-transition-boundary-contract PROPERTIES SKIP_RETURN_CODE 77 LABELS "contract;local;requires-kvm")
endif()

if(BUILD_TESTING AND DAZE_HAS_UNICORN)
  add_executable(unicorn_registers_contract_test
    backend/unicorn/registers_contract_test.c
    backend/unicorn/unicorn_registers.c
  )
  daze_configure_c11_pedantic_target(unicorn_registers_contract_test PRIVATE)
  target_link_libraries(unicorn_registers_contract_test PRIVATE ${DAZE_UNICORN_LINK_LIBRARIES})
  if(NOT DAZE_BUILD_STATIC)
    get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
    set_target_properties(unicorn_registers_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
  daze_register_simple_contract_test(unicorn-registers-contract unicorn_registers_contract_test)

  add_executable(unicorn_trace_config_contract_test
    backend/unicorn/trace_config_contract_test.c
    backend/unicorn/trace_config.c
  )
  daze_configure_c11_pedantic_target(unicorn_trace_config_contract_test PRIVATE)
  daze_register_simple_contract_test(unicorn-trace-config-contract unicorn_trace_config_contract_test)
endif()


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

if(BUILD_TESTING)
  add_executable(dpmi_host_advertisement_contract_test
    dpmi/advertisement_contract_test.c
    dpmi/advertisement.c
  )
  daze_configure_c11_pedantic_target(dpmi_host_advertisement_contract_test PRIVATE)
  daze_register_simple_contract_test(dpmi-host-advertisement-contract dpmi_host_advertisement_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_date_contract_test
    dos/date_contract_test.c
    dos/date.c
  )
  daze_configure_c11_pedantic_target(dos_date_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-date-contract dos_date_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_fcb_contract_test
    dos/fcb_contract_test.c
    dos/fcb.c
  )
  daze_configure_c11_pedantic_target(dos_fcb_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-fcb-contract dos_fcb_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_country_contract_test
    dos/country_contract_test.c
    dos/country.c
  )
  daze_configure_c11_pedantic_target(dos_country_contract_test PRIVATE)
  target_link_libraries(dos_country_contract_test PRIVATE daze_dos_int21_service)
  daze_register_simple_contract_test(dos-country-contract dos_country_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_find_result_contract_test
    dos/find_result_contract_test.c
    dos/find_result.c
  )
  daze_configure_c11_pedantic_target(dos_find_result_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-find-result-contract dos_find_result_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_exec_request_contract_test
    dos/exec_request_contract_test.c
    dos/exec_request.c
  )
  daze_configure_c11_pedantic_target(dos_exec_request_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-exec-request-contract dos_exec_request_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_exec_psp_contract_test
    dos/exec_psp_contract_test.c
    dos/exec_psp.c
  )
  daze_configure_c11_pedantic_target(dos_exec_psp_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-exec-psp-contract dos_exec_psp_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_exec_image_contract_test
    dos/exec_image_contract_test.c
    dos/exec_image.c
  )
  daze_configure_c11_pedantic_target(dos_exec_image_contract_test PRIVATE)
  target_link_libraries(dos_exec_image_contract_test PRIVATE daze_mz_layout)
  daze_register_simple_contract_test(dos-exec-image-contract dos_exec_image_contract_test)

  add_executable(dos_exec_loader_contract_test
    dos/exec_loader_contract_test.c
    dos/exec_loader.c
    dos/exec_image.c
    loader/image.c
  )
  daze_configure_c11_pedantic_target(dos_exec_loader_contract_test PRIVATE)
  target_link_libraries(dos_exec_loader_contract_test PRIVATE daze_dosfs daze_mz_layout)
  daze_register_simple_contract_test(dos-exec-loader-contract dos_exec_loader_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_file_time_contract_test
    dos/file_time_contract_test.c
    dos/file_time.c
  )
  daze_configure_c11_pedantic_target(dos_file_time_contract_test PRIVATE)
  daze_register_simple_contract_test(dos-file-time-contract dos_file_time_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dos_file_attrs_contract_test
    dos/file_attrs_contract_test.c
    dos/file_attrs.c
  )
  daze_configure_c11_pedantic_target(dos_file_attrs_contract_test PRIVATE)
  target_link_libraries(dos_file_attrs_contract_test PRIVATE daze_dosfs)
  daze_register_simple_contract_test(dos-file-attrs-contract dos_file_attrs_contract_test)
endif()


# The BIOS timer-tick reply is the backend-neutral result shared by Unicorn
# and the KVM preflight broker; keep it honest without any CPU engine.
if(BUILD_TESTING)
  add_executable(bios_timer_contract_test
    bios/timer_contract_test.c
    bios/timer.c
  )
  daze_configure_c11_pedantic_target(bios_timer_contract_test PRIVATE)
  add_test(NAME bios-timer-contract COMMAND bios_timer_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(bios_rtc_contract_test
    bios/rtc_contract_test.c
    bios/rtc.c
  )
  daze_configure_c11_pedantic_target(bios_rtc_contract_test PRIVATE)
  add_test(NAME bios-rtc-contract COMMAND bios_rtc_contract_test)
endif()


if(BUILD_TESTING)
  add_executable(dpmi_transition_artifacts_contract_test
    dpmi/transition_artifacts_contract_test.c
    dpmi/transition_artifacts.c
  )
  daze_configure_c11_pedantic_target(dpmi_transition_artifacts_contract_test PRIVATE)
  daze_register_simple_contract_test(dpmi-transition-artifacts-contract dpmi_transition_artifacts_contract_test)
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

if(BUILD_TESTING)
  add_executable(backend_runner_contract_test runtime/backend_runner_contract_test.c)
  daze_configure_c11_pedantic_target(backend_runner_contract_test PRIVATE)
  target_compile_definitions(backend_runner_contract_test PRIVATE
    DAZE_HAS_UNICORN=$<BOOL:${DAZE_HAS_UNICORN}>)
  target_link_libraries(backend_runner_contract_test PRIVATE daze_kvm_selection_metrics daze_metrics)
  daze_register_simple_contract_test(backend-runner-contract backend_runner_contract_test)

  add_executable(launch_contract_test runtime/launch_contract_test.c runtime/launch.c
    loader/image.c dos/exec_loader.c)
  daze_configure_c11_pedantic_target(launch_contract_test PRIVATE)
  target_link_libraries(launch_contract_test PRIVATE daze_kvm_prepared_request
    daze_guest_memory_layout daze_mz_layout daze_dosfs)
  daze_register_simple_contract_test(launch-preparation-contract launch_contract_test)
  add_executable(launch_boundary_contract_test runtime/launch_boundary_contract_test.c
    loader/image.c dos/exec_loader.c)
  daze_configure_c11_pedantic_target(launch_boundary_contract_test PRIVATE)
  target_link_libraries(launch_boundary_contract_test PRIVATE daze_kvm_prepared_request
    daze_guest_memory_layout daze_mz_layout daze_dosfs)
  daze_register_simple_contract_test(launch-boundary-contract launch_boundary_contract_test)

  add_executable(file_service_contract_test dos/fs/file_service_contract_test.c)
  daze_configure_c11_pedantic_target(file_service_contract_test PRIVATE)
  target_link_libraries(file_service_contract_test PRIVATE daze_dosfs)
  daze_register_simple_contract_test(dos-file-service-contract file_service_contract_test)
  add_executable(dosfs_boundary_contract_test dos/fs/dosfs_boundary_contract_test.c)
  daze_configure_c11_pedantic_target(dosfs_boundary_contract_test PRIVATE)
  target_link_libraries(dosfs_boundary_contract_test PRIVATE daze_dosfs)
  daze_register_simple_contract_test(dosfs-boundary-contract dosfs_boundary_contract_test)

  add_test(NAME backend-cli COMMAND "${CMAKE_COMMAND}"
    -DRUNNER=$<TARGET_FILE:daze>
    "-DEXPECTED_VERSION=${DAZE_VERSION}"
    -P ${CMAKE_SOURCE_DIR}/tests/backend_cli.cmake)

  add_executable(continuation_contract_test runtime/continuation_contract_test.c)
  daze_configure_c11_pedantic_target(continuation_contract_test PRIVATE)
  target_link_libraries(continuation_contract_test PRIVATE daze_kvm_machine)
  set(DAZE_EXPLICIT_BACKENDS kvm)
  if(DAZE_HAS_UNICORN)
    list(PREPEND DAZE_EXPLICIT_BACKENDS unicorn)
  endif()
  foreach(backend IN LISTS DAZE_EXPLICIT_BACKENDS)
    add_test(NAME continuation-${backend}-contract
      COMMAND continuation_contract_test $<TARGET_FILE:daze> ${backend})
    set_tests_properties(continuation-${backend}-contract PROPERTIES TIMEOUT 60)
  endforeach()
  set_tests_properties(continuation-kvm-contract PROPERTIES SKIP_RETURN_CODE 77)
  add_executable(launch_regression_contract_test runtime/launch_regression_contract_test.c)
  daze_configure_c11_pedantic_target(launch_regression_contract_test PRIVATE)
  target_compile_definitions(launch_regression_contract_test PRIVATE
    DAZE_HAS_UNICORN=$<BOOL:${DAZE_HAS_UNICORN}>)
  target_link_libraries(launch_regression_contract_test PRIVATE daze_kvm_machine)
  foreach(backend IN LISTS DAZE_EXPLICIT_BACKENDS)
    add_test(NAME launch-regression-${backend}-contract
      COMMAND launch_regression_contract_test $<TARGET_FILE:daze> ${backend})
    set_tests_properties(launch-regression-${backend}-contract PROPERTIES TIMEOUT 30)
  endforeach()
  add_test(NAME launch-regression-auto-contract
    COMMAND launch_regression_contract_test $<TARGET_FILE:daze> auto)
  set_tests_properties(launch-regression-auto-contract PROPERTIES TIMEOUT 30)
  set_tests_properties(launch-regression-kvm-contract PROPERTIES SKIP_RETURN_CODE 77)
  set_tests_properties(launch-regression-auto-contract PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(backend_smoke_contract_test runtime/backend_smoke_contract_test.c)
  daze_configure_c11_pedantic_target(backend_smoke_contract_test PRIVATE)
  target_compile_definitions(backend_smoke_contract_test PRIVATE
    DAZE_HAS_UNICORN=$<BOOL:${DAZE_HAS_UNICORN}>
    DAZE_HAS_KVM=$<BOOL:${DAZE_TARGET_HAS_KVM}>)
  target_link_libraries(backend_smoke_contract_test PRIVATE daze_kvm_machine)
  foreach(backend IN ITEMS ${DAZE_EXPLICIT_BACKENDS} auto omitted)
    add_test(NAME backend-smoke-${backend}-contract
      COMMAND backend_smoke_contract_test $<TARGET_FILE:daze> ${backend})
    set_tests_properties(backend-smoke-${backend}-contract PROPERTIES TIMEOUT 30)
  endforeach()
  set_tests_properties(backend-smoke-kvm-contract backend-smoke-auto-contract
    backend-smoke-omitted-contract PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(launch_cli_contract_test runtime/launch_cli_contract_test.c)
  daze_configure_c11_pedantic_target(launch_cli_contract_test PRIVATE)
  target_compile_definitions(launch_cli_contract_test PRIVATE
    DAZE_HAS_UNICORN=$<BOOL:${DAZE_HAS_UNICORN}>)
  target_link_libraries(launch_cli_contract_test PRIVATE daze_kvm_machine)
  add_test(NAME launch-setup-contract
    COMMAND launch_cli_contract_test $<TARGET_FILE:daze> setup)
  foreach(backend IN ITEMS ${DAZE_EXPLICIT_BACKENDS} auto omitted)
    add_test(NAME launch-execution-${backend}-contract
      COMMAND launch_cli_contract_test $<TARGET_FILE:daze> ${backend})
    set_tests_properties(launch-execution-${backend}-contract PROPERTIES TIMEOUT 30)
  endforeach()
  set_tests_properties(launch-execution-kvm-contract launch-execution-auto-contract
    launch-execution-omitted-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


# Focused synthetic Unicorn contract for the protected DOS-vector fallback
# continuation. Compiled from the runner core minus the DOS launcher seam;
# the KVM and backend-selection sources are not part of its link.
if(DAZE_HAS_UNICORN)
if(BUILD_TESTING)
  add_executable(protected_dos_continuation_contract_test
    backend/unicorn/protected_dos_continuation_contract_test.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
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
    loader/image.c
    backend/unicorn/unicorn_registers.c
    backend/unicorn/bios_adapter.c
    bios/timer.c
    bios/rtc.c
  )
endif()

if(TARGET protected_dos_continuation_contract_test)
daze_configure_c11_target(protected_dos_continuation_contract_test PRIVATE)
endif()
if(TARGET protected_dos_continuation_contract_test)
target_link_libraries(protected_dos_continuation_contract_test PRIVATE
  daze_dosfs
  daze_dos_int21_service
  daze_dos_memory
  daze_dpmi_descriptor
  daze_dpmi_exception_frame
  daze_dpmi_linear_memory
  daze_dpmi_request
  daze_dpmi_process_state
  daze_dpmi_rm_frame
  daze_mz_layout
  daze_metrics
  ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET protected_dos_continuation_contract_test)
  set_target_properties(protected_dos_continuation_contract_test PROPERTIES
    BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET protected_dos_continuation_contract_test)
daze_register_simple_contract_test(protected-dos-continuation-contract protected_dos_continuation_contract_test)
endif()
if(BUILD_TESTING)
  add_test(NAME unicorn-trace-runtime-contract
    COMMAND protected_dos_continuation_contract_test --trace-contract)
endif()


# Test-only Unicorn driver for observing one dispatched request.
if(BUILD_TESTING)
  add_executable(unicorn_dpmi_dispatch_contract_test
    dpmi/unicorn_dispatch_contract_test.c
    backend/unicorn/dpmi_test_driver.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
    dpmi/transition_artifacts.c
    dpmi/advertisement.c
    dos/date.c dos/fcb.c dos/find_result.c dos/exec_request.c dos/exec_psp.c
    dos/exec_image.c dos/exec_loader.c dos/file_attrs.c dos/file_time.c
    loader/image.c backend/unicorn/unicorn_registers.c backend/unicorn/bios_adapter.c
    bios/timer.c bios/rtc.c
  )
endif()

if(TARGET unicorn_dpmi_dispatch_contract_test)
daze_configure_c11_target(unicorn_dpmi_dispatch_contract_test PRIVATE)
endif()
if(TARGET unicorn_dpmi_dispatch_contract_test)
target_link_libraries(unicorn_dpmi_dispatch_contract_test PRIVATE
  daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
  daze_dpmi_exception_frame daze_dpmi_linear_memory
  daze_dpmi_request daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout
  daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET unicorn_dpmi_dispatch_contract_test)
  set_target_properties(unicorn_dpmi_dispatch_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET unicorn_dpmi_dispatch_contract_test)
daze_register_simple_contract_test(unicorn-dpmi-dispatch-contract unicorn_dpmi_dispatch_contract_test)
get_target_property(unicorn_adapter_contract_sources unicorn_dpmi_dispatch_contract_test SOURCES)
list(REMOVE_ITEM unicorn_adapter_contract_sources dpmi/unicorn_dispatch_contract_test.c)
add_executable(unicorn_adapter_boundary_contract_test
  backend/unicorn/adapter_boundary_contract_test.c ${unicorn_adapter_contract_sources})
daze_configure_c11_target(unicorn_adapter_boundary_contract_test PRIVATE)
target_link_libraries(unicorn_adapter_boundary_contract_test PRIVATE
  daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
  daze_dpmi_exception_frame daze_dpmi_linear_memory daze_dpmi_request
  daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES})
if(NOT DAZE_BUILD_STATIC)
  set_target_properties(unicorn_adapter_boundary_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
endif()
daze_register_simple_contract_test(unicorn-adapter-boundary-contract unicorn_adapter_boundary_contract_test)
add_executable(unicorn_startup_contract_test
  backend/unicorn/startup_contract_test.c ${unicorn_adapter_contract_sources})
daze_configure_c11_target(unicorn_startup_contract_test PRIVATE)
target_link_libraries(unicorn_startup_contract_test PRIVATE
  daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
  daze_dpmi_exception_frame daze_dpmi_linear_memory daze_dpmi_request
  daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES})
if(NOT DAZE_BUILD_STATIC)
  set_target_properties(unicorn_startup_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
endif()
daze_register_simple_contract_test(unicorn-startup-contract unicorn_startup_contract_test)
add_executable(unicorn_runtime_transport_contract_test
  backend/unicorn/runtime_transport_contract_test.c ${unicorn_adapter_contract_sources})
daze_configure_c11_target(unicorn_runtime_transport_contract_test PRIVATE)
target_link_libraries(unicorn_runtime_transport_contract_test PRIVATE
  daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
  daze_dpmi_exception_frame daze_dpmi_linear_memory daze_dpmi_request
  daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES})
if(NOT DAZE_BUILD_STATIC)
  set_target_properties(unicorn_runtime_transport_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
endif()
daze_register_simple_contract_test(unicorn-runtime-transport-contract unicorn_runtime_transport_contract_test)
foreach(boundary run bios_image)
  add_executable(unicorn_${boundary}_boundary_contract_test
    backend/unicorn/${boundary}_boundary_contract_test.c
    backend/unicorn/unicorn_image.c ${unicorn_adapter_contract_sources})
  daze_configure_c11_target(unicorn_${boundary}_boundary_contract_test PRIVATE)
  target_link_libraries(unicorn_${boundary}_boundary_contract_test PRIVATE
    daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
    daze_dpmi_exception_frame daze_dpmi_linear_memory daze_dpmi_request
    daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES})
  if(NOT DAZE_BUILD_STATIC)
    set_target_properties(unicorn_${boundary}_boundary_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
  daze_register_simple_contract_test(unicorn-${boundary}-boundary-contract unicorn_${boundary}_boundary_contract_test)
endforeach()
foreach(boundary int21 int31 runtime)
  set(boundary_sources ${unicorn_adapter_contract_sources})
  if(boundary STREQUAL "runtime")
    list(REMOVE_ITEM boundary_sources backend/unicorn/runtime.c)
  else()
    list(REMOVE_ITEM boundary_sources backend/unicorn/${boundary}_adapter.c)
  endif()
  add_executable(unicorn_${boundary}_residual_contract_test
    backend/unicorn/${boundary}_residual_contract_test.c ${boundary_sources})
  daze_configure_c11_target(unicorn_${boundary}_residual_contract_test PRIVATE)
  target_link_libraries(unicorn_${boundary}_residual_contract_test PRIVATE
    daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
    daze_dpmi_exception_frame daze_dpmi_linear_memory daze_dpmi_request
    daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES})
  if(NOT DAZE_BUILD_STATIC)
    set_target_properties(unicorn_${boundary}_residual_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
  daze_register_simple_contract_test(unicorn-${boundary}-residual-contract unicorn_${boundary}_residual_contract_test)
endforeach()
endif()

# LDT descriptor writes skip the translation-cache flush for fresh slots and
# identical rewrites while keeping it for live mutations.
if(BUILD_TESTING)
  add_executable(unicorn_ldt_flush_scope_contract_test
    dpmi/unicorn_ldt_flush_scope_contract_test.c
    backend/unicorn/dpmi_test_driver.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
    dpmi/transition_artifacts.c
    dpmi/advertisement.c
    dos/date.c dos/fcb.c dos/find_result.c dos/exec_request.c dos/exec_psp.c
    dos/exec_image.c dos/exec_loader.c dos/file_attrs.c dos/file_time.c
    loader/image.c backend/unicorn/unicorn_registers.c backend/unicorn/bios_adapter.c
    bios/timer.c bios/rtc.c
  )
endif()

if(TARGET unicorn_ldt_flush_scope_contract_test)
daze_configure_c11_target(unicorn_ldt_flush_scope_contract_test PRIVATE)
endif()
if(TARGET unicorn_ldt_flush_scope_contract_test)
target_link_libraries(unicorn_ldt_flush_scope_contract_test PRIVATE
  daze_dosfs daze_dos_int21_service daze_dos_memory daze_dpmi_descriptor
  daze_dpmi_exception_frame daze_dpmi_linear_memory
  daze_dpmi_request daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout
  daze_metrics ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET unicorn_ldt_flush_scope_contract_test)
  set_target_properties(unicorn_ldt_flush_scope_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET unicorn_ldt_flush_scope_contract_test)
daze_register_simple_contract_test(unicorn-ldt-flush-scope-contract unicorn_ldt_flush_scope_contract_test)
endif()

# Compares observable replies/state after dispatch through both backend test adapters.
if(BUILD_TESTING)
  add_executable(dpmi_shared_contract_test
    dpmi/shared_contract_test.c
    backend/unicorn/dpmi_test_driver.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
    dpmi/transition_artifacts.c
    dpmi/advertisement.c
    dos/date.c dos/fcb.c dos/find_result.c dos/exec_request.c dos/exec_psp.c
    dos/exec_image.c dos/exec_loader.c dos/file_attrs.c dos/file_time.c
    loader/image.c backend/unicorn/unicorn_registers.c backend/unicorn/bios_adapter.c
    bios/timer.c bios/rtc.c
  )
endif()

if(TARGET dpmi_shared_contract_test)
daze_configure_c11_target(dpmi_shared_contract_test PRIVATE)
endif()
if(TARGET dpmi_shared_contract_test)
target_link_libraries(dpmi_shared_contract_test PRIVATE
  daze_kvm_dpmi_mediator_test_driver daze_dosfs daze_dos_int21_service
  daze_dos_memory daze_dpmi_descriptor daze_dpmi_exception_frame
  daze_dpmi_linear_memory daze_dpmi_request
  daze_dpmi_process_state daze_dpmi_rm_frame daze_mz_layout daze_metrics
  ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET dpmi_shared_contract_test)
  set_target_properties(dpmi_shared_contract_test PROPERTIES BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET dpmi_shared_contract_test)
add_test(NAME dpmi-shared-contract COMMAND dpmi_shared_contract_test)
endif()
if(BUILD_TESTING)
  set_tests_properties(dpmi-shared-contract PROPERTIES SKIP_RETURN_CODE 77)
endif()


# Focused synthetic Unicorn contract for the DPMI 0305h state-procedure return
# frame. Compiled from the same runner core as the continuation contract above;
# the KVM and backend-selection sources are not part of its link.
if(BUILD_TESTING)
  add_executable(state_procedure_frame_contract_test
    backend/unicorn/state_procedure_frame_contract_test.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
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
    loader/image.c
    backend/unicorn/unicorn_registers.c
    backend/unicorn/bios_adapter.c
    bios/timer.c
    bios/rtc.c
  )
endif()

if(TARGET state_procedure_frame_contract_test)
daze_configure_c11_target(state_procedure_frame_contract_test PRIVATE)
endif()
if(TARGET state_procedure_frame_contract_test)
target_link_libraries(state_procedure_frame_contract_test PRIVATE
  daze_dosfs
  daze_dos_int21_service
  daze_dos_memory
  daze_dpmi_descriptor
  daze_dpmi_exception_frame
  daze_dpmi_linear_memory
  daze_dpmi_request
  daze_dpmi_process_state
  daze_dpmi_rm_frame
  daze_mz_layout
  daze_metrics
  ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET state_procedure_frame_contract_test)
  set_target_properties(state_procedure_frame_contract_test PROPERTIES
    BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET state_procedure_frame_contract_test)
daze_register_simple_contract_test(state-procedure-frame-contract state_procedure_frame_contract_test)
endif()

# Focused synthetic Unicorn contract for the DPMI legacy exception-entry
# transfer seam. It drives the product's own classifier, gateway writer, frame
# builder, entry hook and resume convention, so it links the same runner core as
# the state-procedure frame contract above; the KVM and backend-selection
# sources are not part of its link.
if(BUILD_TESTING)
  add_executable(exception_entry_transfer_contract_test
    backend/unicorn/exception_entry_transfer_contract_test.c
    backend/unicorn/runtime.c
    backend/unicorn/trace_config.c
    backend/unicorn/int21_adapter.c
    backend/unicorn/int31_adapter.c
    backend/unicorn/dpmi_setup.c
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
    loader/image.c
    backend/unicorn/unicorn_registers.c
    backend/unicorn/bios_adapter.c
    bios/timer.c
    bios/rtc.c
  )
endif()

if(TARGET exception_entry_transfer_contract_test)
daze_configure_c11_target(exception_entry_transfer_contract_test PRIVATE)
endif()
if(TARGET exception_entry_transfer_contract_test)
target_link_libraries(exception_entry_transfer_contract_test PRIVATE
  daze_dosfs
  daze_dos_int21_service
  daze_dos_memory
  daze_dpmi_descriptor
  daze_dpmi_exception_frame
  daze_dpmi_linear_memory
  daze_dpmi_request
  daze_dpmi_process_state
  daze_dpmi_rm_frame
  daze_mz_layout
  daze_metrics
  ${DAZE_UNICORN_LINK_LIBRARIES}
)
endif()
if(NOT DAZE_BUILD_STATIC)
  get_filename_component(UNICORN_LIBRARY_DIR "${UNICORN_LIBRARY}" DIRECTORY)
  if(TARGET exception_entry_transfer_contract_test)
  set_target_properties(exception_entry_transfer_contract_test PROPERTIES
    BUILD_RPATH "${UNICORN_LIBRARY_DIR}")
  endif()
endif()
if(TARGET exception_entry_transfer_contract_test)
daze_register_simple_contract_test(exception-entry-transfer-contract exception_entry_transfer_contract_test)
endif()
if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-production-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  set_tests_properties(exception-entry-transfer-production-contract PROPERTIES
    ENVIRONMENT "DAZE_DPMI_EXCEPTION_PRODUCTION_CONTRACT=1")
endif()

if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-return-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-retry-present-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  set_tests_properties(exception-entry-transfer-retry-present-contract PROPERTIES
    ENVIRONMENT "DAZE_DPMI_EXCEPTION_RETRY_PRESENT=1")
endif()

if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-repeated-fault-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  set_tests_properties(exception-entry-transfer-repeated-fault-contract PROPERTIES
    ENVIRONMENT "DAZE_DPMI_EXCEPTION_REPEATED_FAULT=1")
endif()

if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-nested-delivery-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  set_tests_properties(exception-entry-transfer-nested-delivery-contract PROPERTIES
    ENVIRONMENT "DAZE_DPMI_EXCEPTION_NESTED_DELIVERY=1")
endif()

if(BUILD_TESTING)
  add_test(NAME exception-entry-transfer-lret-contract
    COMMAND exception_entry_transfer_contract_test)
endif()

if(BUILD_TESTING)
  set_tests_properties(exception-entry-transfer-lret-contract PROPERTIES
    ENVIRONMENT "DAZE_DPMI_EXCEPTION_LRET=1")
endif()
endif()


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

# Trailing newlines are a portability requirement, not a style nit: clang
# rejects newline-less files under -Wnewline-eof with -Wpedantic -Werror.
# clang-format has no config knob for this (it always emits the newline), so
# this lightweight check is the enforcement. It covers host-compiled sources
# only; historical application inputs live in the external corpus.
file(GLOB_RECURSE DAZE_TRAILING_NEWLINE_FILES CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/src/*.c"
  "${CMAKE_SOURCE_DIR}/src/*.h"
  "${CMAKE_SOURCE_DIR}/tests/unit/support/*.c"
  "${CMAKE_SOURCE_DIR}/tests/unit/support/*.h"
)
if(BUILD_TESTING)
  add_test(NAME trailing-newline-check
    COMMAND "${CMAKE_COMMAND}"
      "-DNEWLINE_CHECK_FILES=${DAZE_TRAILING_NEWLINE_FILES}"
      -P "${CMAKE_SOURCE_DIR}/tests/check_trailing_newlines.cmake"
  )
endif()

# Unit tests: these always run with the normal test presets.
if(BUILD_TESTING)
  set_tests_properties(
    dos-memory-contract
    dpmi-descriptor-contract
    dpmi-linear-memory-contract
    dpmi-request-contract
    bios-timer-contract
    bios-rtc-contract
    image-process-contract
    mz-layout-contract
    dosfs-contract
    trailing-newline-check
    PROPERTIES LABELS "unit"
  )
endif()


if(BUILD_TESTING)
  get_property(daze_tests DIRECTORY PROPERTY TESTS)
  foreach(test IN LISTS daze_tests)
    get_property(labels TEST "${test}" PROPERTY LABELS)
    if("integration" IN_LIST labels)
      set_property(TEST "${test}" APPEND PROPERTY LABELS external)
    else()
      set_property(TEST "${test}" APPEND PROPERTY LABELS local)
      if(test MATCHES "^(continuation-|launch-regression-|backend-smoke-|unicorn-trace-runtime-)")
        set_property(TEST "${test}" APPEND PROPERTY LABELS smoke)
      elseif(test STREQUAL "backend-cli" OR test STREQUAL "trailing-newline-check")
        set_property(TEST "${test}" APPEND PROPERTY LABELS check)
      else()
        set_property(TEST "${test}" APPEND PROPERTY LABELS contract)
      endif()
      get_property(skip_code TEST "${test}" PROPERTY SKIP_RETURN_CODE)
      if(skip_code STREQUAL "77")
        set_property(TEST "${test}" APPEND PROPERTY LABELS requires-kvm)
      endif()
    endif()
  endforeach()
endif()

include("${CMAKE_SOURCE_DIR}/cmake/ExternalTests.cmake")
