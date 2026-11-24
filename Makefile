CC      ?= cc
AR      ?= ar
STRIP   ?= strip
PYTHON3 ?= python3
# CFLAGS is the caller's to override. Flags the build cannot work without live in RS_CFLAGS,
# which is always appended, so `make CFLAGS=-O0` (or a parent make) cannot drop them.
CFLAGS  ?= -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude
RS_BASE  = -std=c11 $(INCLUDES)

# This repo's own build is a development build: tests and demos use cfg.allow_unsealed.
# A release build must pass ALLOW_UNSEALED=0 (or compile without -DRESHIELD_ALLOW_UNSEALED);
# the library then reports INTERNAL_ERROR if a caller sets the field.
ALLOW_UNSEALED ?= 1
ifeq ($(ALLOW_UNSEALED),1)
RS_CFLAGS = $(RS_BASE) -DRESHIELD_ALLOW_UNSEALED
BUILD_DIR ?= build
else
RS_CFLAGS = $(RS_BASE)
# Own directory, so a development library is never reused as a release one (or the reverse).
BUILD_DIR ?= build/release
endif

# Target platform comes from the compiler (so cross builds work), not from the host uname.
TARGET_TRIPLE := $(shell $(CC) -dumpmachine)
ifneq ($(findstring mingw,$(TARGET_TRIPLE)),)
EXE ?= .exe
LDFLAGS += -lwintrust -lpsapi
else ifneq ($(findstring darwin,$(TARGET_TRIPLE)),)
LDFLAGS += -framework Security -framework CoreFoundation
endif
EXE ?=
# Overridden by `make sanitize`: that script drives the hardcoded build/ binaries, not build/san/.
SEAL_WORKFLOW_TEST ?= $(PYTHON3) tests/test_seal_workflow.py
# Prefix for running built programs, e.g. `make test RUN=wine`.
RUN ?=

LIB_SRCS  = src/sha256.c \
            src/integrity_common.c \
            src/integrity_macos.c \
            src/integrity_linux.c \
            src/integrity_windows.c \
            src/file_posix.c \
            src/file_windows.c \
            src/manifest.c \
            src/attestation_macos.c \
            src/attestation_linux.c \
            src/attestation_windows.c \
            src/reshield.c
LIB_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
LIB_TARGET = $(BUILD_DIR)/libreshield.a

HEADERS = include/reshield/integrity.h \
          include/reshield/manifest.h \
          include/reshield/attestation.h \
          include/reshield/reshield.h

DEMO_INTEGRITY          = $(BUILD_DIR)/integrity_demo$(EXE)
DEMO_INTEGRITY_DISABLED = $(BUILD_DIR)/integrity_demo_disabled$(EXE)
SAMPLE_GAME             = $(BUILD_DIR)/sample_game$(EXE)
SAMPLE_GAME_SEALED      = $(BUILD_DIR)/sample_game_sealed$(EXE)
SAMPLE_GAME_DISABLED    = $(BUILD_DIR)/sample_game_disabled$(EXE)
SAMPLE_MANIFEST         = $(BUILD_DIR)/sample_assets.manifest

TEST_INTEGRITY          = $(BUILD_DIR)/test_integrity$(EXE)
TEST_INTEGRITY_DISABLED = $(BUILD_DIR)/test_integrity_disabled$(EXE)
TEST_MANIFEST           = $(BUILD_DIR)/test_manifest$(EXE)
TEST_MANIFEST_DISABLED  = $(BUILD_DIR)/test_manifest_disabled$(EXE)
TEST_RUNTIME            = $(BUILD_DIR)/test_runtime$(EXE)
TEST_RUNTIME_DISABLED   = $(BUILD_DIR)/test_runtime_disabled$(EXE)
TEST_WX                 = $(BUILD_DIR)/test_wx$(EXE)
TEST_NO_ALLOW           = $(BUILD_DIR)/test_no_allow_unsealed$(EXE)

.PHONY: all lib clean test release-demo sanitize fuzz-build fuzz fuzz-pe

all: $(LIB_TARGET) $(DEMO_INTEGRITY) $(SAMPLE_GAME) $(SAMPLE_GAME_SEALED) \
     $(TEST_INTEGRITY) $(TEST_MANIFEST) $(TEST_RUNTIME) $(TEST_WX)

lib: $(LIB_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(DEMO_INTEGRITY): examples/integrity_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(DEMO_INTEGRITY_DISABLED): examples/integrity_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(SAMPLE_GAME): examples/sample_game.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(SAMPLE_GAME_DISABLED): examples/sample_game.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(SAMPLE_MANIFEST): examples/assets/stage1.cfg | $(BUILD_DIR)
	$(PYTHON3) tools/gen_manifest.py examples/assets -o $@

$(SAMPLE_GAME_SEALED): $(SAMPLE_GAME) $(SAMPLE_MANIFEST)
	cp $(SAMPLE_GAME) $@
	$(STRIP) $@
	$(PYTHON3) tools/seal_binary.py $@ --manifest $(SAMPLE_MANIFEST) --build-id 1

$(TEST_INTEGRITY): tests/test_integrity.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_INTEGRITY_DISABLED): tests/test_integrity.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(TEST_MANIFEST): tests/test_manifest.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_MANIFEST_DISABLED): tests/test_manifest.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(TEST_WX): tests/test_wx.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_RUNTIME): tests/test_runtime.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_RUNTIME_DISABLED): tests/test_runtime.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(TEST_NO_ALLOW): tests/test_no_allow_unsealed.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(filter-out -DRESHIELD_ALLOW_UNSEALED,$(CFLAGS)) $(RS_BASE) $^ $(LDFLAGS) -o $@

release-demo: $(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST)
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --manifest $(SAMPLE_MANIFEST) --assets examples/assets
	$(RUN) ./$(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST) examples/assets STAGE-1-CLEAR-2026

test: $(TEST_INTEGRITY) $(TEST_INTEGRITY_DISABLED) \
      $(TEST_MANIFEST) $(TEST_MANIFEST_DISABLED) \
      $(TEST_RUNTIME) $(TEST_RUNTIME_DISABLED) $(TEST_WX) $(TEST_NO_ALLOW) \
      $(DEMO_INTEGRITY) $(DEMO_INTEGRITY_DISABLED) \
      $(SAMPLE_GAME) $(SAMPLE_GAME_SEALED) $(SAMPLE_GAME_DISABLED) $(SAMPLE_MANIFEST)
	$(RUN) ./$(TEST_INTEGRITY)
	$(RUN) ./$(TEST_INTEGRITY_DISABLED)
	$(RUN) ./$(TEST_MANIFEST)
	$(RUN) ./$(TEST_MANIFEST_DISABLED)
	$(RUN) ./$(TEST_RUNTIME)
	$(RUN) ./$(TEST_RUNTIME_DISABLED)
	$(RUN) ./$(TEST_NO_ALLOW)
	$(RUN) ./$(TEST_WX)
	$(SEAL_WORKFLOW_TEST)
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --manifest $(SAMPLE_MANIFEST) --assets examples/assets

clean:
	rm -rf $(BUILD_DIR)

# ASan+UBSan run of the C test flow in build/san/ (tests still write scratch files under build/).
# Skipped on purpose: tests/test_seal_workflow.py (drives build/ binaries and unsanitized Python).
SAN_CFLAGS = -Wall -Wextra -Wpedantic -Werror -O1 -g -fno-omit-frame-pointer \
             -fsanitize=address,undefined -fno-sanitize-recover=undefined
sanitize:
	mkdir -p build
	$(MAKE) test BUILD_DIR=build/san CFLAGS="$(SAN_CFLAGS)" SEAL_WORKFLOW_TEST=true

# libFuzzer harnesses (tests/fuzz/). Needs a clang with libFuzzer (not Apple clang): run inside
# a container, see docs/fuzzing.md. Corpora live outside the repo (FUZZ_CORPUS).
FUZZ_CC     ?= clang
FUZZ_DIR     = build/fuzz
FUZZ_TIME   ?= 60
FUZZ_CORPUS ?= $(FUZZ_DIR)/corpus
FUZZ_TARGETS = fuzz_manifest fuzz_path fuzz_sha256
FUZZ_CFLAGS  = -std=c11 -Wall -Wextra -O1 -g -fno-omit-frame-pointer \
               -fsanitize=address,undefined -fno-sanitize-recover=undefined

fuzz-build:
	$(MAKE) CC=$(FUZZ_CC) BUILD_DIR=$(FUZZ_DIR) \
	    CFLAGS="$(FUZZ_CFLAGS) -fsanitize=fuzzer-no-link" $(FUZZ_DIR)/libreshield.a
	for t in $(FUZZ_TARGETS); do \
	    $(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer $(INCLUDES) tests/fuzz/$$t.c \
	        $(FUZZ_DIR)/libreshield.a $(LDFLAGS) -o $(FUZZ_DIR)/$$t || exit 1; \
	done

fuzz-pe:
	$(PYTHON3) tests/fuzz/test_parser_regressions.py
	$(PYTHON3) tests/fuzz/fuzz_pe.py

fuzz: fuzz-build fuzz-pe
	for t in $(FUZZ_TARGETS); do \
	    k=$${t#fuzz_}; mkdir -p $(FUZZ_CORPUS)/$$k; \
	    seeds=; [ -d tests/fuzz/seeds/$$k ] && seeds=tests/fuzz/seeds/$$k; \
	    dict=; [ -f tests/fuzz/$$k.dict ] && dict=-dict=tests/fuzz/$$k.dict; \
	    ./$(FUZZ_DIR)/$$t -max_total_time=$(FUZZ_TIME) -max_len=20000 $$dict \
	        -artifact_prefix=$(FUZZ_DIR)/crash-$$k- $(FUZZ_CORPUS)/$$k $$seeds || exit 1; \
	done
	$(PYTHON3) tests/fuzz/diff_path_rules.py --binary $(FUZZ_DIR)/fuzz_path --corpus $(FUZZ_CORPUS)/path
