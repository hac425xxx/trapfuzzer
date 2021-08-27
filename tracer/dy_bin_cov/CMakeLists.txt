cmake_minimum_required(VERSION 2.6)


project(bincov)

set(DynamoRIO_LOG_COMPATIBILITY on)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

if (STATIC_LIBRARY)
  set(libtype STATIC)
else()
  set(libtype SHARED)
endif ()

add_library(bincov ${libtype}
  bin_coverage.c
  )

configure_DynamoRIO_client(bincov)
use_DynamoRIO_extension(bincov drmgr)
use_DynamoRIO_extension(bincov drx)
use_DynamoRIO_extension(bincov drcontainers)
use_DynamoRIO_extension(bincov drreg)
use_DynamoRIO_extension(bincov drwrap)
use_DynamoRIO_extension(bincov drsyms)


# VS2015 Fix
if (NOT (MSVC_VERSION LESS 1900))
  target_link_libraries(bincov "libucrt.lib")
  target_link_libraries(bincov "libvcruntime.lib")
endif()