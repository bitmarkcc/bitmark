# Bitmark: build WAMR's AOT runtime as a static library (libvmlib.a) for the
# dynamic-algo execution engine. AOT runtime only -- no interpreter, no JIT, no
# AOT compiler (wamrc/LLVM is a separate offline tool), no WASI/libc (consensus
# verifier modules are freestanding, import-free). See doc/dynamic-algo-mining.md
# sec 8. Pinned to WAMR commit b70d708 (see BITMARK-VENDOR.txt).
cmake_minimum_required(VERSION 3.14)
project(bitmark_wamr C ASM)

set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Platform: honor a value from the parent build, else derive from the OS.
if(NOT WAMR_BUILD_PLATFORM)
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(WAMR_BUILD_PLATFORM "darwin")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(WAMR_BUILD_PLATFORM "windows")
  else()
    set(WAMR_BUILD_PLATFORM "linux")
  endif()
endif()

# Target arch: honor a non-empty WAMR_BUILD_TARGET from the parent build (bitmark's
# configure passes one derived from $host_cpu; an empty value lands here), else
# derive it from the CMake system processor.
if(NOT WAMR_BUILD_TARGET)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _wamr_proc)
  if(_wamr_proc MATCHES "^(x86_64|amd64)$")
    set(WAMR_BUILD_TARGET "X86_64")
  elseif(_wamr_proc MATCHES "^(i.86|x86)$")
    set(WAMR_BUILD_TARGET "X86_32")
  elseif(_wamr_proc MATCHES "^(aarch64|arm64)$")
    set(WAMR_BUILD_TARGET "AARCH64")
  elseif(_wamr_proc MATCHES "^arm")
    set(WAMR_BUILD_TARGET "ARM")
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WAMR_BUILD_TARGET "X86_64")
  else()
    set(WAMR_BUILD_TARGET "X86_32")
  endif()
endif()
message(STATUS "bitmark WAMR: AOT runtime for platform=${WAMR_BUILD_PLATFORM} target=${WAMR_BUILD_TARGET}")

# AOT runtime only.
set(WAMR_BUILD_AOT 1)
set(WAMR_BUILD_INTERP 0)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_JIT 0)        # LLVM JIT off (would pull core/iwasm/compilation)
set(WAMR_BUILD_FAST_JIT 0)
if(NOT DEFINED WAMR_BUILD_SIMD)
  set(WAMR_BUILD_SIMD 1)
endif()

# No host-provided imports: consensus verifier modules are freestanding.
set(WAMR_BUILD_LIBC_BUILTIN 0)
set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_LIB_PTHREAD 0)
set(WAMR_BUILD_MULTI_MODULE 0)
set(WAMR_BUILD_GC 0)
set(WAMR_BUILD_STRINGREF 0)
set(WAMR_BUILD_LIB_WASI_THREADS 0)

include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
set_target_properties(vmlib PROPERTIES POSITION_INDEPENDENT_CODE ON)
