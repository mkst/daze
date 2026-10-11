cmake_minimum_required(VERSION 3.25)

project(daze LANGUAGES C)

if(NOT DEFINED DAZE_VERSION OR DAZE_VERSION STREQUAL "")
    execute_process(
        COMMAND git describe --tags --always --dirty --match "[0-9]*"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE DAZE_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()

if(DAZE_VERSION STREQUAL "")
    set(DAZE_VERSION "unknown")
endif()

include(CTest)

add_subdirectory(src)
