cmake_minimum_required(VERSION 3.14)
project(blind_xmss_longfellow CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
FetchContent_Declare(
  longfellow
  GIT_REPOSITORY https://github.com/google/longfellow-zk.git
  GIT_TAG        5f348de0bedcc49fe3800a57f6bf2eecd0389391
)
FetchContent_MakeAvailable(longfellow)
set(LONGFELLOW_LIB "${longfellow_SOURCE_DIR}/lib")

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED libzstd)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" BL_ARCH)
if(BL_ARCH MATCHES "x86_64")
  set(BL_ARCH_FLAGS -mpclmul)
elseif(BL_ARCH MATCHES "arm64|aarch64")
  if(APPLE)
    set(BL_ARCH_FLAGS -mcpu=apple-m1 -march=armv8-a+crypto)
  else()
    set(BL_ARCH_FLAGS -march=armv8-a+crypto)
  endif()
endif()

add_library(longfellow_min STATIC
  ${LONGFELLOW_LIB}/util/log.cc
  ${LONGFELLOW_LIB}/util/crypto.cc
  ${LONGFELLOW_LIB}/circuits/sha/sha256_constants.cc
  ${LONGFELLOW_LIB}/circuits/sha/flatsha256_witness.cc
)
target_include_directories(longfellow_min PUBLIC ${LONGFELLOW_LIB})
target_compile_options(longfellow_min PUBLIC ${BL_ARCH_FLAGS})
target_link_libraries(longfellow_min PUBLIC OpenSSL::Crypto)

add_library(blind_xmss_longfellow STATIC
  src/sha.cc
  src/wots.cc
  src/xmss.cc
  src/commitment.cc
  src/native_witness.cc
  src/prover.cc
  src/verifier.cc
  src/protocol.cc
  src/circuit_cache.cc
)
target_include_directories(blind_xmss_longfellow
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${ZSTD_INCLUDE_DIRS})
target_link_libraries(blind_xmss_longfellow PUBLIC longfellow_min ${ZSTD_LIBRARIES})
target_link_directories(blind_xmss_longfellow PUBLIC ${ZSTD_LIBRARY_DIRS})

target_compile_definitions(blind_xmss_longfellow PRIVATE
  BL_CIRCUIT_CACHE="${CMAKE_CURRENT_SOURCE_DIR}/circuits/blind_circuit.cache")

function(bl_add_executable name src)
  cmake_parse_arguments(ARG "BIG_STACK" "" "" ${ARGN})
  add_executable(${name} ${src})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(${name} PRIVATE blind_xmss_longfellow)
  if(ARG_BIG_STACK)
    if(APPLE)
      target_link_options(${name} PRIVATE -Wl,-stack_size,0x1000000)
    elseif(UNIX)
      target_link_options(${name} PRIVATE -Wl,-z,stacksize=16777216)
    endif()
  endif()
endfunction()

bl_add_executable(blindsig bin/cli.cc BIG_STACK)

bl_add_executable(protocol_test tests/protocol_test.cc BIG_STACK)
bl_add_executable(bench         bench/bench.cc         BIG_STACK)

enable_testing()
add_test(NAME protocol_test COMMAND protocol_test)

set_tests_properties(protocol_test PROPERTIES TIMEOUT 1200)
