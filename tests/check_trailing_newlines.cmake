# Fails when any listed source file lacks a trailing newline. Host compilers
# reject such files (notably clang with -Wnewline-eof under -Wpedantic
# -Werror), so this keeps the tree safe for every configured compiler.
# Invoked as:
#   cmake -DNEWLINE_CHECK_FILES="a;b;..." -P check_trailing_newlines.cmake
set(missing "")
foreach(candidate IN LISTS NEWLINE_CHECK_FILES)
  file(READ "${candidate}" content)
  if(NOT content STREQUAL "" AND NOT content MATCHES "\n$")
    list(APPEND missing "${candidate}")
  endif()
endforeach()
if(NOT missing STREQUAL "")
  string(REPLACE ";" "\n  " formatted "${missing}")
  message(FATAL_ERROR "Files missing a trailing newline:\n  ${formatted}")
endif()
