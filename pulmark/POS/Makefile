###############################################################################
# Copyright 2018 Chia Network Inc
# Makefile for building ProofOfSpace app.
#
# Usage:
# make build - create temp dirs for build objs
# make clean - removes app, objs, build dirs, profile files
# make release - makes release binary, full optimized, no debug info
# make debug - makes binary for debugging
# make profile-gen - makes binary for profiling
# make profile-use - makes binary that uses generated profiling information
# make valgrind - makes binary for running valgrind tests
###############################################################################

SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .cpp .o

CXX := -g++
CXXFLAGS_COMMON := -pipe -Wall -fpermissive -maes -std=c++17 -march=native -mtune=native -D_FILE_OFFSET_BITS=64
CXXFLAGS_RELEASE := -Ofast -DNDEBUG -DUSE_ITERATOR_ACCESS 
#-DUSE_MADVISE -DUSE_DROP_TABLE \ 
#-D_GLIBCXX_PARALLEL -fopenmp
CXXFLAGS := -O3 -g $(CXXFLAGS_COMMON) -DUSE_ITERATOR_ACCESS \
-Winline -Wdisabled-optimization 
#-DUSE_MADVISE -DUSE_DROP_TABLE # -DUSE_HELLMAN_ATTACK

LDFLAGS  := -lstdc++fs 

BUILD := ./build
OBJ_DIR := $(BUILD)/objs
PROFILE_DIR := $(BUILD)/profiles
APP_DIR := .
TARGET := ProofOfSpace

INCLUDE := -I./include/mio \
	-I./lib/FiniteStateEntropy/lib/ \
	-I./lib/FastPrefixCoder/ \
	-I./src/include/
#	-I./lib/rans_static/ \
#	-I./include/dynamic_bitset/include \
#	-I./include/vector_class \
#	-I./include/hedley \
	
SRC := $(wildcard lib/FiniteStateEntropy/lib/*.c) \
	$(wildcard lib/FastPrefixCoder/fpc.c) \
	$(wildcard src/*.cpp)
#	$(wildcard lib/rans_static/rNx16.c) \
#	$(wildcard lib/rans_static/r8x16_sse.c) \
#	$(wildcard lib/rans_static/rANS_static.c) \
#	$(wildcard lib/rans_static/rANS_static4x16.c) \
#	$(wildcard lib/rans_static/rANS_static4x8.c) \

#OBJECTS := $(SRC:%.cpp,%.c=$(OBJ_DIR)/%.o)
OBJECTS := $(SRC:%.cpp=$(OBJ_DIR)/%.o)

.PHONY: all build clean debug release hellman valgrind profile-gen profile-use profile-use-clean depend

all: build $(APP_DIR)/$(TARGET)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ -c $<

$(APP_DIR)/$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $(APP_DIR)/$(TARGET) $(OBJECTS) $(LDFLAGS)

build:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(PROFILE_DIR)
	@mkdir -p $(APP_DIR)

clang: CXX = -clang++
clang: CXXFLAGS = $(CXXFLAGS_RELEASE) $(CXXFLAGS_COMMON) #-DUSE_BIT_FIDDLING
clang: all

debug: CXXFLAGS = -ggdb -g3 $(CXXFLAGS_COMMON)
debug: all

release: CXXFLAGS = $(CXXFLAGS_RELEASE) $(CXXFLAGS_COMMON) #-DUSE_BIT_FIDDLING
release: all

hellman: CXXFLAGS = $(CXXFLAGS_RELEASE) $(CXXFLAGS_COMMON) -DUSE_HELLMAN_ATTACK
hellman: all

valgrind: CXXFLAGS = -O0 -g $(CXXFLAGS_COMMON)
valgrind: all

profile-gen: CXXFLAGS = $(CXXFLAGS_RELEASE) $(CXXFLAGS_COMMON) -fprofile-generate -fprofile-dir=$(PROFILE_DIR)
profile-gen: all

profile-use: CXXFLAGS = $(CXXFLAGS_RELEASE) $(CXXFLAGS_COMMON) -fprofile-use -fprofile-dir=$(PROFILE_DIR)
profile-use: LDFLAGS += -lgcov
profile-use: profile-use-clean all

depend: 
	-@makedepend -- $(CXXFLAGS) -- -Y $(SRC)

profile-use-clean:
	-@rm -rvf $(APP_DIR)/$(TARGET)
	-@rm -rvf $(OBJ_DIR)/*.*
	-@rm -rvf $(OBJ_DIR)/src/*.*
	-@rm -vf $(APP_DIR)/*.gcda
	-@rm -vf $(APP_DIR)/*.dat
	-@rm -vf $(APP_DIR)/*.dat.tmp
	-@rm -vf $(APP_DIR)/*.dat.hellman
	-@rm -vf $(APP_DIR)/*.lz4
	-@rm -vf $(APP_DIR)/*.xz

clean:
	-@rm -rvf $(OBJ_DIR)/*.*
	-@rm -rvf $(OBJ_DIR)/src/*.*
	-@rm -rvf $(PROFILE_DIR)/*.*
	-@rm -rvf $(APP_DIR)/$(TARGET)
	-@rm -vf $(APP_DIR)/*.gcda
	-@rm -vf $(APP_DIR)/*.dat
	-@rm -vf $(APP_DIR)/*.dat.tmp
	-@rm -vf $(APP_DIR)/*.dat.hellman
	-@rm -vf $(APP_DIR)/*.lz4
	-@rm -vf $(APP_DIR)/*.xz

# DO NOT DELETE
