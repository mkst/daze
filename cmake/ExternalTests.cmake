option(DAZE_EXTERNAL_TESTS "Register the pinned external DOS application suite" OFF)
set(DAZE_TESTS_DIR "" CACHE PATH "Checkout of the pinned daze-tests corpus")
set(DAZE_EXTERNAL_BACKENDS "" CACHE STRING "Required backends (empty selects all compiled backends)")
set(DAZE_TEST_CACHE "${CMAKE_BINARY_DIR}/fixture-cache" CACHE PATH "Downloaded external fixture cache")

if(NOT BUILD_TESTING)
  if(DAZE_EXTERNAL_TESTS)
    message(FATAL_ERROR "DAZE_EXTERNAL_TESTS requires BUILD_TESTING")
  endif()
  return()
endif()

if(NOT DAZE_EXTERNAL_TESTS)
  add_test(NAME external-tests-not-configured COMMAND "${CMAKE_COMMAND}"
    -P "${CMAKE_SOURCE_DIR}/tests/external_tests_not_configured.cmake")
  set_tests_properties(external-tests-not-configured PROPERTIES LABELS "integration;external")
  return()
endif()

if(NOT EXISTS "${DAZE_TESTS_DIR}/daze_tests.py")
  message(FATAL_ERROR "Set DAZE_TESTS_DIR to the pinned corpus; see tests/README.md")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(available_backends "")
if(DAZE_HAS_UNICORN)
  list(APPEND available_backends unicorn)
endif()
if(DAZE_TARGET_HAS_KVM)
  list(APPEND available_backends kvm auto omitted)
endif()
set(selected_backends "${DAZE_EXTERNAL_BACKENDS}")
if(NOT selected_backends)
  set(selected_backends "${available_backends}")
endif()
foreach(backend IN LISTS selected_backends)
  if(NOT backend IN_LIST available_backends)
    message(FATAL_ERROR "External backend ${backend} is not supported by this build")
  endif()
endforeach()

file(GLOB_RECURSE corpus_inputs CONFIGURE_DEPENDS
  "${DAZE_TESTS_DIR}/cases/*.yaml" "${DAZE_TESTS_DIR}/golden/*" "${DAZE_TESTS_DIR}/sources/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${corpus_inputs} "${DAZE_TESTS_DIR}/daze_tests.py" "${DAZE_TESTS_DIR}/fixtures.yaml"
  "${DAZE_TESTS_DIR}/required.yaml" "${DAZE_TESTS_DIR}/requirements.txt"
  "${CMAKE_SOURCE_DIR}/tools/daze-tests.json" "${CMAKE_SOURCE_DIR}/tools/external_tests.py")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/external_tests.py"
  generate --corpus "${DAZE_TESTS_DIR}" --backends ${selected_backends}
  --output "${CMAKE_BINARY_DIR}/external-tests.cmake"
  --manifest "${CMAKE_BINARY_DIR}/external-tests.json"
  --evidence-dir "${CMAKE_BINARY_DIR}/external-evidence"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "External test registration failed: ${output}${error}\nTo diagnose the corpus checkout, run: python3 ${CMAKE_SOURCE_DIR}/tools/external_tests.py check --corpus \"${DAZE_TESTS_DIR}\"")
endif()
message(STATUS "${output}")
get_property(before DIRECTORY PROPERTY TESTS)
include("${CMAKE_BINARY_DIR}/external-tests.cmake")
get_property(after DIRECTORY PROPERTY TESTS)
foreach(test IN LISTS after)
  if(NOT test IN_LIST before)
    set_property(TEST "${test}" APPEND PROPERTY LABELS integration external)
    set_tests_properties("${test}" PROPERTIES RUN_SERIAL TRUE
      ENVIRONMENT "DAZE_TEST_CACHE=${DAZE_TEST_CACHE};PYTHONDONTWRITEBYTECODE=1")
  endif()
endforeach()
