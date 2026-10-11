include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

FetchContent_Declare(voleith_faest
  URL https://codeload.github.com/faest-sign/faest-arch-opt/tar.gz/1d8330979cb467c54edac43ffe695da249fa3417
  URL_HASH SHA256=a759200288b12535862acd38d0f431af1f2b4e33d4cdf03147b6c250608a41a6
  SOURCE_SUBDIR _download_only)
FetchContent_Declare(voleith_xkcp
  URL https://codeload.github.com/XKCP/XKCP/tar.gz/4affab454735d54e78156880b3b44e38dcbf765c
  URL_HASH SHA256=42055374a213ba8cedbfaa76ce80e184ed515f111eb0e7d82ac1df2ba0eda1d0
  SOURCE_SUBDIR _download_only)
FetchContent_Declare(voleith_pomfrit
  URL https://codeload.github.com/shibammukherjee/pq_blind_signatures/tar.gz/b984d1f141e318a351af9a660a3e6cee26307b65
  URL_HASH SHA256=516ea9cd566d936218047c5000a1f80ab1aa6743d264254191762c6cc21aee07
  SOURCE_SUBDIR _download_only)
FetchContent_MakeAvailable(voleith_faest voleith_xkcp voleith_pomfrit)

find_package(Git REQUIRED)
set(VOLEITH_POMFRIT_TRACE_DIR "${CMAKE_CURRENT_BINARY_DIR}/pomfrit")
foreach(file fips202.c fips202.h)
  configure_file("${voleith_pomfrit_SOURCE_DIR}/vole/common/${file}"
    "${VOLEITH_POMFRIT_TRACE_DIR}/${file}" COPYONLY)
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_LIST_DIR}/pomfrit-trace.patch")
execute_process(
  COMMAND "${GIT_EXECUTABLE}" apply --no-index
    "${CMAKE_CURRENT_LIST_DIR}/pomfrit-trace.patch"
  WORKING_DIRECTORY "${VOLEITH_POMFRIT_TRACE_DIR}"
  COMMAND_ERROR_IS_FATAL ANY)
