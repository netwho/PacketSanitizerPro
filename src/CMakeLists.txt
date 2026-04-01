# CMakeLists.txt for PacketSanitizer Wireshark epan plugin
#
# Drop this directory (with all source files and PacketSanitizer-Logo.png)
# into:
#   <wireshark-src>/plugins/epan/packetsanitizer/
#
# Then re-run cmake in your Wireshark build tree to pick it up.
# The build process mirrors the PacketCircle plugin exactly.

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(packetsanitizer 0 1 1 0)

# Enable Qt MOC and resource compilation
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Qt version selection (inherits from Wireshark build)
if(USE_qt6)
    set(qtver "6")
else()
    set(qtver "5")
endif()

find_package(Qt${qtver} REQUIRED COMPONENTS Core Widgets Gui)

set(PLUGIN_NAME packetsanitizer)

# Source files
set(DISSECTOR_SRC
    packetsanitizer_plugin.c
    sanitizer_engine.c
    ui_bridge.cpp
    ui_main_window.cpp
)

# These files are C++ despite some having .c extensions
set_source_files_properties(
    ui_bridge.cpp
    ui_main_window.cpp
    PROPERTIES LANGUAGE CXX
)

# glibc 2.38 compatibility shim (Linux only)
if(UNIX AND NOT APPLE)
    list(APPEND DISSECTOR_SRC glibc_compat.c)
    set_source_files_properties(glibc_compat.c PROPERTIES
        COMPILE_OPTIONS  "-U_GNU_SOURCE;-D_POSIX_C_SOURCE=200809L"
        LANGUAGE         C
        SKIP_AUTOGEN     ON
    )
endif()

# Qt resource file
set(PLUGIN_RESOURCES
    packetsanitizer.qrc
)

# All plugin files
set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
    ${PLUGIN_RESOURCES}
)

set(PLUGIN_HEADERS
    packetsanitizer_plugin.h
    sanitizer_engine.h
    ui_bridge.h
    ui_main_window.h
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC UTF-8 source encoding
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Disable Qt version tagging (allows loading with any Qt 6.x runtime)
add_definitions(-DQT_NO_VERSION_TAGGING)

set_source_files_properties(
    plugin.c
    PROPERTIES
    SKIP_AUTOGEN ON
    LANGUAGE C
)

set_source_files_properties(
    ${PLUGIN_FILES}
    PROPERTIES
    COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
    plugin
    ${DISSECTOR_SRC}
)

add_wireshark_plugin_library(${PLUGIN_NAME} epan)

target_link_libraries(${PLUGIN_NAME}
    epan
    wiretap
    Qt${qtver}::Core
    Qt${qtver}::Widgets
    Qt${qtver}::Gui
)

install_plugin(${PLUGIN_NAME} epan)
