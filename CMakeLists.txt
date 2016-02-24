#######################################################
#
# This project was scaled back considerably from it's
# first iteration, from a fully featured testing tool
# to a generic command line utility.  There are still
# a lot of things that need to be cleaned up.  For now
# it appears to be functional, so it will be posted on
# github where progress can be tracked more easily.
#
#######################################################

#project information
cmake_minimum_required(VERSION 2.8)
project(fuzzcap)

#flags
set(CMAKE_CXX_FLAGS "-std=c++0x ${CMAKE_CXX_FLAGS} -g")

#find required boost packages
find_package(Boost 1.55 COMPONENTS program_options system date_time thread filesystem REQUIRED)

#add include directories
include_directories(${Boost_INCLUDE_DIR})
include_directories(src)

#beautiful block of cmake madness will build things in the future, thanks SO
file(GLOB_RECURSE fuzzy_source
    "src/main.cpp")

#exe and linker info
add_executable (fuzzcap ${fuzzy_source})
target_link_libraries(fuzzcap ${Boost_LIBRARIES})

#install path and whatnot
install(TARGETS fuzzcap DESTINATION bin)

