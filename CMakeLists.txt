cmake_minimum_required(VERSION 3.20)
project(scope LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
find_program(BPFTOOL bpftool REQUIRED)
find_program(CLANG clang REQUIRED)

set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")
set(VMLINUX_H "${GENERATED_DIR}/vmlinux.h")
set(BPF_OBJECT "${GENERATED_DIR}/scope.bpf.o")
set(BPF_SKELETON "${GENERATED_DIR}/scope.skel.h")

add_custom_command(
    OUTPUT "${VMLINUX_H}"
    COMMAND /bin/sh -c
        "\"${BPFTOOL}\" btf dump file /sys/kernel/btf/vmlinux format c > \"${VMLINUX_H}\""
    COMMENT "Generating kernel BTF header"
    VERBATIM
)
add_custom_command(
    OUTPUT "${BPF_OBJECT}"
    COMMAND "${CLANG}" -O2 -g -target bpf -DSCOPE_BPF_TARGET=1
            -I "${GENERATED_DIR}"
            -c "${CMAKE_CURRENT_SOURCE_DIR}/bpf/scope.bpf.c"
            -o "${BPF_OBJECT}"
    DEPENDS "${VMLINUX_H}"
            "${CMAKE_CURRENT_SOURCE_DIR}/bpf/scope.bpf.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/bpf/events.h"
    COMMENT "Compiling eBPF probes"
    VERBATIM
)
add_custom_command(
    OUTPUT "${BPF_SKELETON}"
    COMMAND /bin/sh -c
        "\"${BPFTOOL}\" gen skeleton \"${BPF_OBJECT}\" > \"${BPF_SKELETON}\""
    DEPENDS "${BPF_OBJECT}"
    COMMENT "Generating libbpf skeleton"
    VERBATIM
)
add_custom_target(generate_skeleton DEPENDS "${BPF_SKELETON}")

add_library(scope_core STATIC reconstruct.cpp recording.cpp)
target_include_directories(scope_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/bpf")
target_link_libraries(scope_core PUBLIC SQLite::SQLite3)

add_executable(scope main.cpp)
add_dependencies(scope generate_skeleton)
target_include_directories(scope PRIVATE "${GENERATED_DIR}")
target_link_libraries(scope PRIVATE scope_core PkgConfig::LIBBPF)

add_executable(scope-view viewer.cpp)
target_link_libraries(scope-view PRIVATE scope_core Qt6::Widgets)

find_package(Threads REQUIRED)
add_executable(stress examples/stress.cpp)
target_link_libraries(stress PRIVATE Threads::Threads)
target_compile_options(stress PRIVATE -O1 -g -fno-omit-frame-pointer)

enable_testing()
add_executable(reconstruct_test tests/reconstruct_test.cpp)
target_link_libraries(reconstruct_test PRIVATE scope_core)
add_test(NAME reconstruction COMMAND reconstruct_test)

add_executable(recording_test tests/recording_test.cpp)
target_link_libraries(recording_test PRIVATE scope_core)
add_test(NAME recording COMMAND recording_test)

# Header-only application spans
add_executable(span_test tests/span_test.cpp)
target_link_libraries(span_test PRIVATE scope_core)
add_test(NAME named_spans COMMAND span_test)

add_executable(viewer_test tests/viewer_test.cpp)
target_link_libraries(viewer_test PRIVATE scope_core Qt6::Widgets)
add_test(NAME viewer_spans COMMAND viewer_test)
set_tests_properties(viewer_spans PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
