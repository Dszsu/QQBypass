cmake_minimum_required(VERSION 3.18.1)

project("xalsaceqqbypass")

# ByteHook (通过 prefab 提供的预编译库，无需编译任何汇编)
find_package(bytehook REQUIRED CONFIG)

# Main native library
add_library(
    native-bypass
    SHARED
    native-bypass.cpp
    hooks/hook_libc.cpp
    hooks/hook_libfekit.cpp
    hooks/hook_libturingxq.cpp
    hooks/hook_libmsf.cpp
    hooks/hook_libqsec.cpp
    hooks/hook_libmsfkernel.cpp
    hooks/hook_libturingmfa.cpp
    hooks/hook_libqimei.cpp
    utils/log.cpp
)

# Include directories
target_include_directories(native-bypass PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(
    native-bypass
    bytehook::bytehook
    log
    android
)

# Compiler flags
target_compile_options(native-bypass PRIVATE
    -std=c++17
    -Wall
    -Wextra
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
)

# Linker flags
target_link_options(native-bypass PRIVATE
    -Wl,--gc-sections
    -Wl,-rpath,\$ORIGIN
)
