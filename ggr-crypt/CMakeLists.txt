project("ggr-crypt")

add_executable("ggr-crypt"
    "src/main.cpp"
)

target_link_libraries("ggr-crypt" PRIVATE "miniz")

target_include_directories("ggr-crypt" PUBLIC "inc/")
target_include_directories("ggr-crypt" PRIVATE "${CMAKE_SOURCE_DIR}/lib/json/single_include/")
target_include_directories("ggr-crypt" PRIVATE "${CMAKE_SOURCE_DIR}/lib/stb/")