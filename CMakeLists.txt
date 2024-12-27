cmake_minimum_required(VERSION 3.16)
project(sVPN VERSION 0.1 LANGUAGES C)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_COLOR_MAKEFILE   ON)

set (3RDPARTY_ROOT	3rdparty/ )
set (STARLET_ROOT       ${3RDPARTY_ROOT}/utility_routines/ )
add_subdirectory(${STARLET_ROOT})						# Set of utility routines for general purpose


include_directories (
	./
	${STARLET_ROOT}
	${3RDPARTY_ROOT}
)


set (SRV_EXE svpn_server)								# Set target excutable
add_executable(${SRV_EXE} src/svpn_server.c src/svpn_defs.h src/svpn_common.c 3rdparty/sha1.c)
add_dependencies( ${SRV_EXE} starlet)
target_compile_definitions (${SRV_EXE} PRIVATE DEBUG=1)
target_link_libraries(${SRV_EXE} PRIVATE starlet pthread)


set (CLI_EXE svpn_client)								# Set target excutable
add_executable(${CLI_EXE} src/svpn_client.c src/svpn_defs.h src/svpn_common.c 3rdparty/sha1.c)
add_dependencies( ${CLI_EXE} starlet)
target_compile_definitions (${CLI_EXE} PRIVATE DEBUG=1)
target_link_libraries(${CLI_EXE} PRIVATE starlet pthread)

set (UTL_EXE svpn_util)								# Set target excutable
add_executable(${UTL_EXE} src/svpn_util.c src/svpn_defs.h src/svpn_common.c)
add_dependencies( ${UTL_EXE} starlet)
target_compile_definitions (${UTL_EXE} PRIVATE DEBUG=1)
target_link_libraries(${UTL_EXE} PRIVATE starlet pthread)
