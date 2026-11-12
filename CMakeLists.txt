cmake_minimum_required(VERSION 3.16)
project(AegisDesktop)

find_package(nappgui REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

include("${NAPPGUI_ROOT_PATH}/prj/NAppProject.cmake")
include("${NAPPGUI_ROOT_PATH}/prj/NAppCompilers.cmake")

nap_config_compiler()
nap_project_desktop_app(aegis_desktop src)
