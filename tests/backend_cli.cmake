# CLI-facing backend-selection policy. The omitted option must be parsed as
# --backend auto and an invalid --backend value must be rejected before any
# guest is launched (the MZ path is never even opened).
if(NOT DEFINED RUNNER)
  message(FATAL_ERROR "RUNNER is required")
endif()
if(NOT DEFINED EXPECTED_VERSION)
  message(FATAL_ERROR "EXPECTED_VERSION is required")
endif()

execute_process(
  COMMAND "${RUNNER}" --version
  RESULT_VARIABLE version_result
  OUTPUT_VARIABLE version_stdout
  ERROR_VARIABLE version_stderr
)
if(NOT version_result EQUAL 0 OR
   NOT version_stdout STREQUAL "daze ${EXPECTED_VERSION}\n" OR
   NOT version_stderr STREQUAL "")
  message(FATAL_ERROR "--version output mismatch (exit ${version_result})\n"
    "stderr: ${version_stderr}\nstdout: ${version_stdout}")
endif()

execute_process(
  COMMAND "${RUNNER}" --backend definitely-invalid NO_SUCH.EXE
  RESULT_VARIABLE invalid_result
  OUTPUT_VARIABLE invalid_stdout
  ERROR_VARIABLE invalid_stderr
)
if(invalid_result EQUAL 0 OR
   NOT invalid_stderr MATCHES "invalid --backend value: definitely-invalid" OR
   invalid_stderr MATCHES "NO_SUCH")
  message(FATAL_ERROR "invalid --backend value was not rejected cleanly "
    "(exit ${invalid_result})\n${invalid_stderr}\n${invalid_stdout}")
endif()

execute_process(
  COMMAND "${RUNNER}" --backend
  RESULT_VARIABLE missing_result
  OUTPUT_VARIABLE missing_stdout
  ERROR_VARIABLE missing_stderr
)
if(missing_result EQUAL 0 OR NOT missing_stderr MATCHES "--backend requires")
  message(FATAL_ERROR "missing --backend value was not rejected cleanly "
    "(exit ${missing_result})\n${missing_stderr}\n${missing_stdout}")
endif()

# An omitted option must behave exactly like an explicit --backend auto: same
# error for an unopenable MZ (also proving no guest is launched for either).
execute_process(
  COMMAND "${RUNNER}" NO_SUCH.EXE
  RESULT_VARIABLE omitted_result
  OUTPUT_VARIABLE omitted_stdout
  ERROR_VARIABLE omitted_stderr
)
execute_process(
  COMMAND "${RUNNER}" --backend auto NO_SUCH.EXE
  RESULT_VARIABLE auto_result
  OUTPUT_VARIABLE auto_stdout
  ERROR_VARIABLE auto_stderr
)
if(NOT omitted_result EQUAL auto_result OR NOT omitted_stderr STREQUAL auto_stderr)
  message(FATAL_ERROR "omitted option differs from --backend auto "
    "(omitted exit ${omitted_result}\n${omitted_stderr}; auto exit ${auto_result}\n${auto_stderr})")
endif()
