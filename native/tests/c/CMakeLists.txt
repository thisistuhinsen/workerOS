cmake_minimum_required(VERSION 3.15)
project(WorkerHandoffC LANGUAGES C)

find_package(worker-handoff CONFIG REQUIRED)
add_executable(read-worker-c read_input.c)
target_link_libraries(read-worker-c PRIVATE worker-handoff::worker-handoff)
set_target_properties(read-worker-c PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_options(read-worker-c PRIVATE -Wall -Wextra -Werror)
