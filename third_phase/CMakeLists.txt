cmake_minimum_required(VERSION 3.13)
project(third_phase)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(third_phase
        pkcs11.h
        pkcs11_ft.h
        pkcs11f.h
        Pkcs11Stub.cpp
        Pkcs11Stub.h
        pkcs11t.h
        tester.c)
