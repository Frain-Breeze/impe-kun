project("packer")

add_executable("packer"
    "src/main.cpp"
)

target_link_libraries("packer" PRIVATE "miniz")

target_include_directories("packer" PUBLIC "inc/")