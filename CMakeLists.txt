cmake_minimum_required(VERSION 3.22)

project(confium-plugin-botan
    LANGUAGES CXX
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(cfm-botan SHARED
    src/lib.cpp
)

find_package(Botan3 REQUIRED)

target_link_libraries(cfm-botan
    PRIVATE
        Botan3::Botan3
)

set_target_properties(cfm-botan PROPERTIES CXX_VISIBILITY_PRESET hidden)

enable_testing()

add_executable(cfm-botan-test
    tests/test_botan.cpp
)

target_link_libraries(cfm-botan-test
    PRIVATE
        cfm-botan
        Botan3::Botan3
)

# locate the plugin shared library next to the test binary at runtime
set_target_properties(cfm-botan-test PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN"
)

add_test(NAME botan-plugin COMMAND cfm-botan-test)

include(GNUInstallDirs)
install(TARGETS cfm-botan DESTINATION "${CMAKE_INSTALL_LIBDIR}")
