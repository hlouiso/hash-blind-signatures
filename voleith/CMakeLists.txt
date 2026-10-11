cmake_minimum_required(VERSION 3.20)
project(blind_xmss_voleith LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
  #include <expected>
  int main() {
    std::expected<int, int> value{std::unexpected(1)};
    return value.error();
  }
" VOLEITH_HAVE_STD_EXPECTED)
if(NOT VOLEITH_HAVE_STD_EXPECTED)
  message(FATAL_ERROR
    "voleith requires C++23 std::expected and std::unexpected. "
    "Select a recent compiler and standard library; on macOS, use Homebrew LLVM.")
endif()

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "voleith currently supports macOS and Linux")
endif()
include(CheckSymbolExists)
check_symbol_exists(getentropy "sys/random.h" VOLEITH_HAVE_GETENTROPY)
if(NOT VOLEITH_HAVE_GETENTROPY)
  message(FATAL_ERROR "getentropy is required for cryptographic randomness")
endif()

option(VOLEITH_SANITIZE "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
set(VOLEITH_TAU 8 CACHE STRING "Number of GGM trees (7..32; smaller proofs cost more PRG work)")
set(VOLEITH_DEGREE 64 CACHE STRING "QuickSilver degree (16, 32 or 64)")
set(VOLEITH_GRIND 16 CACHE STRING "Fiat-Shamir grinding bits (0..24)")
set_property(CACHE VOLEITH_DEGREE PROPERTY STRINGS 16 32 64)

if(NOT VOLEITH_TAU MATCHES "^[0-9]+$" OR VOLEITH_TAU LESS 7 OR VOLEITH_TAU GREATER 32)
  message(FATAL_ERROR "VOLEITH_TAU must be in [7,32]")
endif()
if(NOT VOLEITH_DEGREE MATCHES "^(16|32|64)$")
  message(FATAL_ERROR "VOLEITH_DEGREE must be 16, 32 or 64")
endif()
if(NOT VOLEITH_GRIND MATCHES "^[0-9]+$" OR VOLEITH_GRIND GREATER 24)
  message(FATAL_ERROR "VOLEITH_GRIND must be in [0,24]")
endif()
math(EXPR MAX_K "((128-${VOLEITH_GRIND})/${VOLEITH_TAU})+1")
if(MAX_K GREATER_EQUAL 16)
  message(FATAL_ERROR "This FAEST implementation requires floor((128-GRIND)/TAU)+1 < 16; increase TAU or GRIND")
endif()

if(VOLEITH_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" VOLEITH_ARCH)
if(VOLEITH_ARCH MATCHES "arm64|aarch64")
  add_compile_options(-march=armv8.2-a+crypto)
elseif(VOLEITH_ARCH MATCHES "x86_64|amd64")
  add_compile_options(-mavx2 -maes -mpclmul -mbmi)
else()
  message(FATAL_ERROR "FAEST requires AArch64 with crypto extensions or x86-64 with AVX2/AES/PCLMUL/BMI")
endif()

include(cmake/Dependencies.cmake)

set(X "${voleith_xkcp_SOURCE_DIR}")
add_library(xkcp STATIC
  ${X}/lib/high/Keccak/FIPS202/KeccakHash.c
  ${X}/lib/high/Keccak/KeccakSponge.c
  ${X}/lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
  ${X}/lib/low/KeccakP-1600-times4/fallback-on1/KeccakP-1600-times4-on1.c)
target_include_directories(xkcp SYSTEM PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/include" ${X} ${X}/lib/common ${X}/lib/low/common
  ${X}/lib/high/Keccak ${X}/lib/high/Keccak/FIPS202
  ${X}/lib/low/KeccakP-1600/common ${X}/lib/low/KeccakP-1600/plain-64bits
  ${X}/lib/low/KeccakP-1600/plain-64bits/SnP
  ${X}/lib/low/KeccakP-1600-times4/fallback-on1)

set(F "${voleith_faest_SOURCE_DIR}")
add_library(faest_components STATIC ${F}/aes.cpp ${F}/polynomials_constants.cpp
  ${F}/sha3/KeccakHash-times4.c ${F}/sha3/KeccakSponge-times4.c)
target_include_directories(faest_components SYSTEM PUBLIC ${F})
target_link_libraries(faest_components PUBLIC xkcp)

add_library(pomfrit_trace STATIC "${VOLEITH_POMFRIT_TRACE_DIR}/fips202.c")
target_compile_definitions(pomfrit_trace PRIVATE KECCAK_DEG_16)
if(VOLEITH_DEGREE EQUAL 16)
  target_compile_definitions(pomfrit_trace PRIVATE KECCAK_TRACE_ROUNDS=6)
elseif(VOLEITH_DEGREE EQUAL 32)
  target_compile_definitions(pomfrit_trace PRIVATE KECCAK_TRACE_ROUNDS=8)
else()
  target_compile_definitions(pomfrit_trace PRIVATE KECCAK_TRACE_ROUNDS=9)
endif()

add_library(voleith_native STATIC src/native/hash.c src/native/xmss.c
  src/native/commitment.c src/native/gf128.c src/native/randombytes.c)
target_include_directories(voleith_native PUBLIC src)
target_link_libraries(voleith_native PUBLIC xkcp)
target_compile_definitions(voleith_native PUBLIC
  VOLEITH_TAU=${VOLEITH_TAU}
  VOLEITH_DEGREE=${VOLEITH_DEGREE}
  VOLEITH_GRIND=${VOLEITH_GRIND})

add_library(voleith STATIC src/proof.cpp src/protocol.cpp)
target_link_libraries(voleith PUBLIC voleith_native faest_components pomfrit_trace)
add_executable(blindsig src/cli.cpp)
target_link_libraries(blindsig PRIVATE voleith)
add_executable(bench src/bench.cpp)
target_link_libraries(bench PRIVATE voleith)

function(voleith_apply_project_options target)
  target_compile_options(${target} PRIVATE
    $<$<COMPILE_LANG_AND_ID:C,GNU,Clang,AppleClang>:-Wall;-Wextra;-Werror>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall;-Wextra;-Werror>)
endfunction()
foreach(target voleith_native voleith blindsig bench)
  voleith_apply_project_options(${target})
endforeach()

include(CTest)
if(BUILD_TESTING)
  add_executable(circuit_test tests/circuit_test.cpp)
  target_link_libraries(circuit_test PRIVATE voleith_native faest_components pomfrit_trace)
  target_compile_options(circuit_test PRIVATE -UNDEBUG)
  voleith_apply_project_options(circuit_test)
  add_test(NAME circuit COMMAND circuit_test)

  add_executable(protocol_test tests/protocol_test.cpp)
  target_link_libraries(protocol_test PRIVATE voleith)
  voleith_apply_project_options(protocol_test)
  add_test(NAME protocol COMMAND protocol_test)

  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME cli COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py $<TARGET_FILE:blindsig>)
  set_tests_properties(circuit protocol cli PROPERTIES TIMEOUT 1200)
endif()
