project(sipParse)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive")

add_executable(msg_parse main.cpp common.cpp msg_parse_c.cpp uri_parse_c.cpp)