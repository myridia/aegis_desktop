cmake_minimum_required(VERSION 3.16)

# ------------------------------------------------------------------------------
# NAppGUI is installed as a precompiled SDK for x86_64 / macOS 13.6.
# These must be set before project() so the compiler checks use them.
# ------------------------------------------------------------------------------
set(DEPLOYMENT_TARGET_OSX "13.6" CACHE STRING "Minimum macOS version")
set(CMAKE_OSX_DEPLOYMENT_TARGET "${DEPLOYMENT_TARGET_OSX}" CACHE STRING "Minimum macOS version")
set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "Target architecture")

if (NOT CMAKE_OSX_SYSROOT)
    execute_process(
        COMMAND xcrun --show-sdk-path
        OUTPUT_VARIABLE _osx_sdk
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT _osx_sdk)
        message(FATAL_ERROR "Could not find the macOS SDK. Install Xcode command line tools.")
    endif()
    set(CMAKE_OSX_SYSROOT "${_osx_sdk}" CACHE STRING "macOS SDK")
endif()

project(AegisDesktop VERSION 1.0.0 LANGUAGES C CXX OBJC)

# The installed NAppGUI SDK only ships Release libraries.
if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

foreach (_cfg DEBUG MINSIZEREL RELWITHDEBINFO)
    set(CMAKE_MAP_IMPORTED_CONFIG_${_cfg} "Release")
endforeach()

if (NOT nappgui_DIR AND EXISTS "/usr/local/nappgui/cmake/nappgui-config.cmake")
    set(nappgui_DIR "/usr/local/nappgui/cmake" CACHE PATH "NAppGUI CMake package")
endif()

# Homebrew OpenSSL 3 (CommonCrypto has no public AES-GCM decryption API).
if (EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "OpenSSL root")
elseif (EXISTS "/usr/local/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3" CACHE PATH "OpenSSL root")
endif()

find_package(nappgui REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(AegisDesktop MACOSX_BUNDLE
    src/main.c
    src/gui.c
    src/vault.c
    src/otp.c
    src/json.c
    src/util.c
    src/clipboard.m
)

target_include_directories(AegisDesktop PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${NAPPGUI_INCLUDE_PATH}"
)

target_compile_options(AegisDesktop PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

target_link_libraries(AegisDesktop PRIVATE
    nappgui::osapp
    nappgui::gui
    nappgui::osgui
    nappgui::draw2d
    nappgui::geom2d
    nappgui::core
    nappgui::osbs
    nappgui::sewer
    OpenSSL::Crypto
    "-framework Cocoa"
    "-framework UniformTypeIdentifiers"
    "-framework WebKit"
)

set_target_properties(AegisDesktop PROPERTIES
    LINKER_LANGUAGE CXX
    MACOSX_BUNDLE_BUNDLE_NAME "Aegis Desktop"
    MACOSX_BUNDLE_GUI_IDENTIFIER "local.aegisdesktop"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist"
)
