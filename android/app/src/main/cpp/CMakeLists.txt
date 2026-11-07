cmake_minimum_required(VERSION 3.22.1)
project(spa C)
file(GLOB FKO_SOURCES CONFIGURE_DEPENDS "vendor/lib/*.c")
add_library(spa SHARED ${FKO_SOURCES} vendor/common/fko_util.c
    vendor/common/strlcpy.c vendor/common/strlcat.c packet.c jni_bridge.c)
target_compile_definitions(spa PRIVATE HAVE_CONFIG_H=1)
target_include_directories(spa PRIVATE . vendor/lib vendor/common)
target_compile_options(spa PRIVATE -Wall -Wextra)
