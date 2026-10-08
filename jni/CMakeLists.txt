cmake_minimum_required(VERSION 3.22)
project(inoadb LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Os -fno-exceptions -fno-rtti -fvisibility=hidden
        -ffunction-sections -fdata-sections -Werror=format)
add_link_options(-Wl,--gc-sections -Wl,--strip-all -Wl,--exclude-libs,ALL
        -Wl,-z,max-page-size=16384)

# Sama seperti jni.zip milikmu (prefab BoringSSL)
find_package(boringssl REQUIRED CONFIG)
# Kalau linker minta libc++: tambahkan find_package(cxx REQUIRED CONFIG) dan cxx::cxx

add_library(adb SHARED ino_adb.cpp)
target_link_libraries(adb log boringssl::crypto_static)
