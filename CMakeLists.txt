cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
project("impe-kun")

add_library("miniz" STATIC
    "${CMAKE_SOURCE_DIR}/lib/miniz/miniz.c"
)
target_include_directories("miniz" PUBLIC "${CMAKE_SOURCE_DIR}/lib/miniz/")

add_subdirectory("ggr-crypt")
add_subdirectory("packer")
if(WIN32)
add_subdirectory("patcher")
endif()