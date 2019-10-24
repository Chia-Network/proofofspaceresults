cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_CURRENT_LIST_DIR}/libs/block/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/libs/block/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/libs/block/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

cm_workspace(chia)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

cm_find_package(CM)

add_subdirectory(libs/block)
add_subdirectory(libs/hash)

file(GLOB FiniteStateEntropy_SOURCES ${CMAKE_CURRENT_LIST_DIR}/libs/FiniteStateEntropy/lib/*.c)
add_library(FiniteStateEntropy ${FiniteStateEntropy_SOURCES})
set_target_properties(FiniteStateEntropy PROPERTIES
                      COMPILE_FLAGS "-maes -mpclmul -mssse3 -msse2 -march=native -ofast"
                      LINK_FLAGS "-flto")

cm_find_package(Boost COMPONENTS program_options system thread)
cm_find_package(Threads)

cm_project(consensus_primitive LANGUAGES ASM C CXX)

# Workaround for interface ASM sources support for CMake <= 3.7
if(NOT CMAKE_ASM_COMPILE_OBJECT)
    enable_language(C CXX ASM)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     )

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     src/main.cpp)

cm_setup_version(VERSION 0.1.0 PREFIX ${CURRENT_PROJECT_NAME})

add_executable(${CURRENT_PROJECT_NAME}
               ${${CURRENT_PROJECT_NAME}_HEADERS}
               ${${CURRENT_PROJECT_NAME}_SOURCES})

set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CURRENT_PROJECT_NAME}
                      CXX_STANDARD 14
                      CXX_STANDARD_REQUIRED TRUE
                      COMPILE_FLAGS "-O3 -maes -mpclmul -msse2 -mssse3 -mavx -mavx2 -mavx512f -march=native")

target_include_directories(${CURRENT_PROJECT_NAME} PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"
                           ${Boost_INCLUDE_DIRS})

target_link_libraries(${CURRENT_PROJECT_NAME} PUBLIC crypto3::block crypto3::hash

                      FiniteStateEntropy

                      ${CMAKE_THREAD_LIBS_INIT}
                      ${Boost_LIBRARIES})