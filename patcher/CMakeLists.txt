#ONLY FOR WINDOWS (with MSVC)
project("patcher")

add_library("patcher" SHARED
    "src/dllmain.cpp"
    "src/readregs.asm"
)

target_include_directories("patcher" PUBLIC "inc/")
target_include_directories("patcher" PUBLIC "MinHook_133_bin/include/")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries("patcher" "MinHook_133_bin/bin/MinHook.x64.lib")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_libraries("patcher" "MinHook_133_bin/bin/MinHook.x86.lib")
endif()