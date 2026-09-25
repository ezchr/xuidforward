cmake_minimum_required(VERSION 3.15)
project(xuidforward CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Two independent targets:
#
#   xuidforward-verify  standalone, no Endstone needed. Loads a profile, checks it
#                       against a bedrock_server binary on disk and prints the
#                       relay machine code it would install. Use this to validate
#                       a profile (or a BDS update) without running the server.
#
#   xuidforward         the plugin itself. Needs the Endstone C++ SDK and, on
#                       Linux, Clang + libc++ (Endstone requires libc++ so that
#                       plugin code shares BDS's std::string / std::string_view ABI).
option(XUIDFORWARD_WITH_ENDSTONE "Build the Endstone plugin" ON)

add_executable(xuidforward-verify
    tools/verify.cpp
    src/profile.cpp
    src/hook.cpp
    src/stage.cpp
)
target_include_directories(xuidforward-verify PRIVATE src)
target_compile_options(xuidforward-verify PRIVATE -Wall -Wextra)

if(XUIDFORWARD_WITH_ENDSTONE)
    find_package(endstone REQUIRED)

    add_library(xuidforward SHARED
        src/xuid_forward_plugin.cpp
        src/profile.cpp
        src/hook.cpp
        src/inject.cpp
        src/stage.cpp
    )
    target_include_directories(xuidforward PRIVATE src)
    target_link_libraries(xuidforward PRIVATE endstone::endstone)
    target_compile_options(xuidforward PRIVATE -Wall -Wextra)

    # Endstone loads plugins/*.so by their bare name.
    set_target_properties(xuidforward PROPERTIES PREFIX "")
endif()
