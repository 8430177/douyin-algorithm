cmake_minimum_required(VERSION 3.24)
project(bd-algorithm)

set(CMAKE_CXX_STANDARD 23)

include_directories(include digestpp crypto)

include(cmake/CPM.cmake)
CPMAddPackage(
        NAME protobuf
        GIT_TAG v21.12
        GIT_REPOSITORY https://gitee.com/jpacg/protobuf.git
        OPTIONS
        "protobuf_BUILD_TESTS OFF"
        "protobuf_BUILD_LIBPROTOC OFF"
        "protobuf_BUILD_PROTOBUF_BINARIES OFF"
        "protobuf_BUILD_PROTOC_BINARIES OFF"
        "protobuf_BUILD_SHARED_LIBS OFF"
        "protobuf_BUILD_EXAMPLES OFF"
        "ABSL_PROPAGATE_CXX_STD ON"
)

add_executable(bd-algorithm
        main.cpp
        common.cpp
        argus.pb.cc
        ladon.cpp
        crypto/base64.cpp
        crypto/simon.c
        argus.cpp
        ByteBuf.cpp
        crypto/pkcs7_padding.c
        crypto/aes.c)

target_link_libraries(bd-algorithm PRIVATE protobuf::libprotobuf)
