nap_desktop_app(aegis_desktop "" NRC_NONE)

target_include_directories(aegis_desktop PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(aegis_desktop OpenSSL::Crypto)
