# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

ARCH := $(shell uname -m)

ROOT := ./$(shell git rev-parse --show-cdup)

CPPFLAGS = -MMD -MP
CPPFLAGS += -I $(ROOT)include

CXXFLAGS = -std=c++26
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -O3 -flto=auto
CXXFLAGS += -Wno-unused-function

ifeq ($(ARCH), aarch64)
    CXXFLAGS += -march=armv8-a+aes
else ifeq ($(ARCH), x86_64)
    #CXXFLAGS += -march=native
    CXXFLAGS += -march=x86-64-v3 -maes -mvaes
    #CXXFLAGS += -march=raptorlake
endif

#LDFLAGS =

LDLIBS = -lfmt

