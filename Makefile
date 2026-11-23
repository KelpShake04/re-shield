CC      ?= cc
AR      ?= ar
STRIP   ?= strip
PYTHON3 ?= python3
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LDFLAGS += -framework Security -framework CoreFoundation
endif

BUILD_DIR = build
LIB_SRCS  = src/sha256.c \
            src/integrity_common.c \
            src/integrity_macos.c \
            src/integrity_linux.c \
            src/manifest.c \
            src/attestation_macos.c \
            src/attestation_linux.c \
            src/reshield.c
LIB_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
LIB_TARGET = $(BUILD_DIR)/libreshield.a

HEADERS = include/reshield/integrity.h \
          include/reshield/manifest.h \
          include/reshield/attestation.h \
          include/reshield/reshield.h

DEMO_INTEGRITY          = $(BUILD_DIR)/integrity_demo
DEMO_INTEGRITY_DISABLED = $(BUILD_DIR)/integrity_demo_disabled
SAMPLE_GAME             = $(BUILD_DIR)/sample_game
SAMPLE_GAME_SEALED      = $(BUILD_DIR)/sample_game_sealed
SAMPLE_GAME_DISABLED    = $(BUILD_DIR)/sample_game_disabled
SAMPLE_MANIFEST         = $(BUILD_DIR)/sample_assets.manifest

TEST_INTEGRITY          = $(BUILD_DIR)/test_integrity
TEST_INTEGRITY_DISABLED = $(BUILD_DIR)/test_integrity_disabled
TEST_MANIFEST           = $(BUILD_DIR)/test_manifest
TEST_MANIFEST_DISABLED  = $(BUILD_DIR)/test_manifest_disabled
TEST_RUNTIME            = $(BUILD_DIR)/test_runtime
TEST_RUNTIME_DISABLED   = $(BUILD_DIR)/test_runtime_disabled

.PHONY: all clean test release-demo

all: $(LIB_TARGET) $(DEMO_INTEGRITY) $(SAMPLE_GAME) $(SAMPLE_GAME_SEALED) \
     $(TEST_INTEGRITY) $(TEST_MANIFEST) $(TEST_RUNTIME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(DEMO_INTEGRITY): examples/integrity_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(DEMO_INTEGRITY_DISABLED): examples/integrity_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ $(LDFLAGS) -o $@

$(SAMPLE_GAME): examples/sample_game.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(SAMPLE_GAME_DISABLED): examples/sample_game.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ $(LDFLAGS) -o $@

$(SAMPLE_MANIFEST): examples/assets/stage1.cfg | $(BUILD_DIR)
	$(PYTHON3) tools/gen_manifest.py examples/assets -o $@

$(SAMPLE_GAME_SEALED): $(SAMPLE_GAME) $(SAMPLE_MANIFEST)
	cp $(SAMPLE_GAME) $@
	$(STRIP) $@
	$(PYTHON3) tools/seal_binary.py $@ --manifest $(SAMPLE_MANIFEST) --build-id 1

$(TEST_INTEGRITY): tests/test_integrity.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_INTEGRITY_DISABLED): tests/test_integrity.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ $(LDFLAGS) -o $@

$(TEST_MANIFEST): tests/test_manifest.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_MANIFEST_DISABLED): tests/test_manifest.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ $(LDFLAGS) -o $@

$(TEST_RUNTIME): tests/test_runtime.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) $(LDFLAGS) -o $@

$(TEST_RUNTIME_DISABLED): tests/test_runtime.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ $(LDFLAGS) -o $@

release-demo: $(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST)
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --manifest $(SAMPLE_MANIFEST) --assets examples/assets
	./$(SAMPLE_GAME_SEALED) $(SAMPLE_MANIFEST) examples/assets STAGE-1-CLEAR-2026

test: $(TEST_INTEGRITY) $(TEST_INTEGRITY_DISABLED) \
      $(TEST_MANIFEST) $(TEST_MANIFEST_DISABLED) \
      $(TEST_RUNTIME) $(TEST_RUNTIME_DISABLED) \
      $(DEMO_INTEGRITY) $(DEMO_INTEGRITY_DISABLED) \
      $(SAMPLE_GAME) $(SAMPLE_GAME_SEALED) $(SAMPLE_GAME_DISABLED) $(SAMPLE_MANIFEST)
	./$(TEST_INTEGRITY)
	./$(TEST_INTEGRITY_DISABLED)
	./$(TEST_MANIFEST)
	./$(TEST_MANIFEST_DISABLED)
	./$(TEST_RUNTIME)
	./$(TEST_RUNTIME_DISABLED)
	$(PYTHON3) tests/test_seal_workflow.py
	$(PYTHON3) tools/verify_release.py $(SAMPLE_GAME_SEALED) --manifest $(SAMPLE_MANIFEST) --assets examples/assets

clean:
	rm -rf $(BUILD_DIR)
