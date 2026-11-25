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
# `make lib` and `make shared` therefore give a DEVELOPMENT library, which carries the marker
# RESHIELD-DEV-BUILD-v1 so tools/reshield_release.py and verify_release.py refuse to ship it.
# A release build must pass ALLOW_UNSEALED=0 (or compile without -DRESHIELD_ALLOW_UNSEALED), or use
# `make release-shared`; the library then reports INTERNAL_ERROR if a caller sets the field.
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
# Shared library (module mode): `make shared`. Not offered for mingw, where DLLs are built with cl
# and reshield.def (see the windows-msvc CI job).
ifneq ($(findstring mingw,$(TARGET_TRIPLE)),)
EXE ?= .exe
LDFLAGS += -lwintrust -lpsapi
else ifneq ($(findstring darwin,$(TARGET_TRIPLE)),)
LDFLAGS += -framework Security -framework CoreFoundation
SHARED_EXT = dylib
SHARED_LDFLAGS = -dynamiclib
else
SHARED_EXT = so
# -Bsymbolic: calls inside the library bind to its own copy, never to a same-named symbol that
# the host executable exports, so the library always finds its own integrity record.
SHARED_LDFLAGS = -shared -Wl,-Bsymbolic
DL_LIBS = -ldl
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
            src/reshield.c \
            src/verify_app.c
LIB_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
LIB_TARGET = $(BUILD_DIR)/libreshield.a
PIC_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/pic/%.o,$(LIB_SRCS))
SHARED_TARGET = $(BUILD_DIR)/libreshield.$(SHARED_EXT)

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
CRACKME                 = $(BUILD_DIR)/crackme$(EXE)
CRACKME_SEALED          = $(BUILD_DIR)/crackme_sealed$(EXE)

TEST_INTEGRITY          = $(BUILD_DIR)/test_integrity$(EXE)
TEST_INTEGRITY_DISABLED = $(BUILD_DIR)/test_integrity_disabled$(EXE)
TEST_MANIFEST           = $(BUILD_DIR)/test_manifest$(EXE)
TEST_MANIFEST_DISABLED  = $(BUILD_DIR)/test_manifest_disabled$(EXE)
TEST_RUNTIME            = $(BUILD_DIR)/test_runtime$(EXE)
TEST_RUNTIME_DISABLED   = $(BUILD_DIR)/test_runtime_disabled$(EXE)
TEST_WX                 = $(BUILD_DIR)/test_wx$(EXE)
TEST_VERIFY_APP         = $(BUILD_DIR)/test_verify_app$(EXE)
TEST_NO_ALLOW           = $(BUILD_DIR)/test_no_allow_unsealed$(EXE)
TEST_MODULE_HOST        = $(BUILD_DIR)/test_module_host$(EXE)

.PHONY: all lib shared release-shared module-test guard-test release-sample clean test crackme release-demo sanitize fuzz-build fuzz fuzz-pe

all: $(LIB_TARGET) $(DEMO_INTEGRITY) $(SAMPLE_GAME) $(SAMPLE_GAME_SEALED) \
     $(TEST_INTEGRITY) $(TEST_MANIFEST) $(TEST_RUNTIME) $(TEST_WX) $(TEST_VERIFY_APP)

lib: $(LIB_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

shared: $(SHARED_TARGET)

$(BUILD_DIR)/pic:
	mkdir -p $@

$(BUILD_DIR)/pic/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)/pic
	$(CC) $(CFLAGS) $(RS_CFLAGS) -fPIC -c $< -o $@

$(SHARED_TARGET): $(PIC_OBJS)
	$(CC) $(SHARED_LDFLAGS) $(PIC_OBJS) $(LDFLAGS) -o $@

# The release (ALLOW_UNSEALED=0) library has its own directory; build it from a sub-make.
release-shared:
	$(MAKE) ALLOW_UNSEALED=0 BUILD_DIR=build/release shared

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

$(CRACKME): examples/crackme/crackme.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

# Not stripped: the lab finds the patch targets by symbol name.
$(CRACKME_SEALED): $(CRACKME)
	cp $(CRACKME) $@
	$(PYTHON3) tools/seal_binary.py $@ --build-id 1

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

$(TEST_VERIFY_APP): tests/test_verify_app.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_RUNTIME): tests/test_runtime.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_RUNTIME_DISABLED): tests/test_runtime.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) -DRESHIELD_DISABLE $^ $(LDFLAGS) -o $@

$(TEST_NO_ALLOW): tests/test_no_allow_unsealed.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(filter-out -DRESHIELD_ALLOW_UNSEALED,$(CFLAGS)) $(RS_BASE) $^ $(LDFLAGS) -o $@

# Module mode: re-shield linked into a shared library that an unsealed host dlopen()s. The host
# links no re-shield code. `make sanitize` skips it (an ASan library needs an ASan host runtime).
MODULE_TEST ?= $(PYTHON3) tests/test_module_mode.py --host $(TEST_MODULE_HOST) \
               --lib $(SHARED_TARGET) --release-lib build/release/libreshield.$(SHARED_EXT) \
               $(MODULE_DUAL_ARG)

$(TEST_MODULE_HOST): tests/test_module_host.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< $(DL_LIBS) -o $@

# ELF only (macOS has a two-level namespace, no interposition): a host that links re-shield too and
# exports its symbols, to check that -Wl,-Bsymbolic keeps the library on its own record.
ifeq ($(SHARED_EXT),so)
TEST_MODULE_DUAL = $(BUILD_DIR)/test_module_host_dual$(EXE)
MODULE_DUAL_ARG  = --dual-host $(TEST_MODULE_DUAL)
$(TEST_MODULE_DUAL): tests/test_module_host.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(RS_CFLAGS) $< -Wl,--whole-archive $(LIB_TARGET) -Wl,--no-whole-archive -rdynamic $(DL_LIBS) -o $@
endif

module-test: $(TEST_MODULE_HOST) $(TEST_MODULE_DUAL) $(SHARED_TARGET) release-shared
	$(MODULE_TEST)

# Dev-build guard (docs/steam-pipeline.md): the development marker is in dev artifacts only, and
# reshield_release.py / verify_release.py refuse it. release-sample links a sample with the release library.
RELEASE_SAMPLE = build/release/sample_game$(EXE)

release-sample:
	$(MAKE) ALLOW_UNSEALED=0 BUILD_DIR=build/release $(RELEASE_SAMPLE)

guard-test: $(LIB_TARGET) $(SAMPLE_GAME) $(SHARED_TARGET) release-shared release-sample
	$(PYTHON3) tests/test_dev_build_guard.py \
	    --dev-artifact $(LIB_TARGET) --dev-artifact $(SHARED_TARGET) --dev-bin $(SAMPLE_GAME) \
	    --release-artifact build/release/libreshield.a --release-artifact build/release/libreshield.$(SHARED_EXT) \
	    --release-bin $(RELEASE_SAMPLE)

# The demo seals a development build on purpose, hence --allow-dev-build.
release-demo: $(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST)
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --allow-dev-build --manifest $(SAMPLE_MANIFEST) --assets examples/assets
	$(RUN) ./$(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST) examples/assets STAGE-1-CLEAR-2026

# Crackme lab (docs/crackme-lab.md): needs nm and POSIX binaries, so not part of `make test` for mingw.
crackme: $(CRACKME_SEALED)
	$(PYTHON3) tests/test_crackme_lab.py $(CRACKME_SEALED)

ifeq ($(findstring mingw,$(TARGET_TRIPLE)),)
CRACKME_TEST = crackme
MODULE_TEST_TARGET ?= module-test
GUARD_TEST_TARGET ?= guard-test
endif

test: $(CRACKME_TEST) $(MODULE_TEST_TARGET) $(GUARD_TEST_TARGET) \
      $(TEST_INTEGRITY) $(TEST_INTEGRITY_DISABLED) \
      $(TEST_MANIFEST) $(TEST_MANIFEST_DISABLED) \
      $(TEST_RUNTIME) $(TEST_RUNTIME_DISABLED) $(TEST_WX) $(TEST_NO_ALLOW) $(TEST_VERIFY_APP) \
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
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --allow-dev-build --manifest $(SAMPLE_MANIFEST) --assets examples/assets

clean:
	rm -rf $(BUILD_DIR)

# ASan+UBSan run of the C test flow in build/san/ (tests still write scratch files under build/).
# Skipped on purpose: tests/test_seal_workflow.py (drives build/ binaries and unsanitized Python)
# and module-test (an ASan shared library needs an ASan host runtime), and guard-test (it checks
# the plain build/ and build/release/ artifacts).
SAN_CFLAGS = -Wall -Wextra -Wpedantic -Werror -O1 -g -fno-omit-frame-pointer \
             -fsanitize=address,undefined -fno-sanitize-recover=undefined
sanitize:
	mkdir -p build
	$(MAKE) test BUILD_DIR=build/san CFLAGS="$(SAN_CFLAGS)" SEAL_WORKFLOW_TEST=true MODULE_TEST_TARGET= GUARD_TEST_TARGET=

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
