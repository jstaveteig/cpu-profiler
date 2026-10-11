cmake_minimum_required(VERSION 3.20)

project(scope LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
find_program(BPFTOOL bpftool REQUIRED)
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

set(VMLINUX_H "${GENERATED_DIR}/vmlinux.h")

add_custom_command(
    OUTPUT "${VMLINUX_H}"
    COMMAND /bin/sh -c
        "\"${BPFTOOL}\" btf dump file /sys/kernel/btf/vmlinux format c > \"${VMLINUX_H}\""
    COMMENT "Generating vmlinux.h"
    VERBATIM
)

add_custom_target(generate_vmlinux DEPENDS "${VMLINUX_H}")


set(SCOPE_BPF "${GENERATED_DIR}/scope.bpf.o")

add_custom_command(
    OUTPUT "${SCOPE_BPF}"

    COMMAND clang
        -O2
        -g
        -target bpf
        -I "${GENERATED_DIR}"
        -c "${CMAKE_CURRENT_SOURCE_DIR}/bpf/scope.bpf.c"
        -o "${SCOPE_BPF}"

    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/bpf/scope.bpf.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/bpf/events.h"
        "${VMLINUX_H}"

    COMMENT "Compiling eBPF program"
    VERBATIM
)

set(SCOPE_SKEL "${GENERATED_DIR}/scope.skel.h")

add_custom_command(
    OUTPUT "${SCOPE_SKEL}"

    COMMAND /bin/sh -c
        "\"${BPFTOOL}\" gen skeleton \"${SCOPE_BPF}\" > \"${SCOPE_SKEL}\""

    DEPENDS "${SCOPE_BPF}"

    COMMENT "Generating BPF skeleton"
    VERBATIM
)

add_custom_target(generate_skeleton DEPENDS "${SCOPE_SKEL}")

add_executable(scope main.cpp)

add_dependencies(scope generate_skeleton)

target_include_directories(scope PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/bpf"
    "${GENERATED_DIR}"
)

target_link_libraries(scope PRIVATE PkgConfig::LIBBPF)

enable_testing()

add_executable(reconstruct_test
    tests/reconstruct_test.cpp
    reconstruct.cpp
)

target_include_directories(reconstruct_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/bpf"
)

add_test(NAME reconstruction COMMAND reconstruct_test)