cmake_minimum_required(VERSION 3.15)
project(WorkerHandoffCpp LANGUAGES CXX)

find_package(worker-handoff CONFIG REQUIRED)
add_executable(read-worker-cpp read_input.cpp)
target_link_libraries(read-worker-cpp PRIVATE worker-handoff::worker-handoff)
set_target_properties(read-worker-cpp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_options(read-worker-cpp PRIVATE -Wall -Wextra -Werror)
