# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include ../config.mk

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))
MANS = $(addsuffix .1,$(BINS))

all: $(BINS)

test: all
	bash test-correctness.bash

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

man: $(MANS)

castella.1: MAN_NAME = compute the Castella hash
cch.1: MAN_NAME = compute the Compress-Castella hash

%.1: %
	help2man --no-info --locale=C.UTF-8 --name='$(MAN_NAME)' --output=$@ ./$<

install: $(BINS) $(MANS)
	@install -D --verbose --mode=755 --target-directory=$(DESTDIR)$(BINDIR) -- $(BINS)
	@install -D --verbose --mode=644 --target-directory=$(DESTDIR)$(MAN1DIR) -- $(MANS)

uninstall:
	@$(RM) --verbose -- $(addprefix $(DESTDIR)$(BINDIR)/,$(BINS))
	@$(RM) --verbose -- $(addprefix $(DESTDIR)$(MAN1DIR)/,$(MANS))

clean:
	@$(RM) --verbose -- $(DEPS) $(BINS) $(MANS)

lint:
	-clang-tidy --quiet $(SRCS) -- $(LINT_CPPFLAGS) $(LINT_CXXFLAGS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all man test install uninstall clean lint

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
