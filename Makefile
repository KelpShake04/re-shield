CC      ?= cc
AR      ?= ar
STRIP   ?= strip
PYTHON3 ?= python3
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude

BUILD_DIR = build
LIB_SRCS  = src/debug_policy_common.c \
            src/debug_policy_macos.c \
            src/debug_policy_linux.c \
            src/sha256.c \
            src/integrity_common.c \
            src/integrity_macos.c \
            src/integrity_linux.c \
            src/reshield.c
LIB_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
LIB_TARGET = $(BUILD_DIR)/libreshield.a

DEMO_DEBUG_POLICY          = $(BUILD_DIR)/debug_policy_demo
DEMO_DEBUG_POLICY_DISABLED = $(BUILD_DIR)/debug_policy_demo_disabled
DEMO_INTEGRITY             = $(BUILD_DIR)/integrity_demo
DEMO_INTEGRITY_DISABLED    = $(BUILD_DIR)/integrity_demo_disabled

SAMPLE_UNPROTECTED         = $(BUILD_DIR)/sample_game_unprotected
SAMPLE_PROTECTED           = $(BUILD_DIR)/sample_game_protected

TEST_DEBUG_POLICY          = $(BUILD_DIR)/test_debug_policy
TEST_DEBUG_POLICY_DISABLED = $(BUILD_DIR)/test_debug_policy_disabled
TEST_INTEGRITY             = $(BUILD_DIR)/test_integrity
TEST_INTEGRITY_DISABLED    = $(BUILD_DIR)/test_integrity_disabled
TEST_RUNTIME               = $(BUILD_DIR)/test_runtime
TEST_RUNTIME_DISABLED      = $(BUILD_DIR)/test_runtime_disabled

.PHONY: all clean test sample-compare

all: $(LIB_TARGET) $(DEMO_DEBUG_POLICY) $(DEMO_INTEGRITY) $(SAMPLE_UNPROTECTED) $(SAMPLE_PROTECTED) \
     $(TEST_DEBUG_POLICY) $(TEST_INTEGRITY) $(TEST_RUNTIME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c include/reshield/debug_policy.h include/reshield/integrity.h include/reshield/reshield.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(DEMO_DEBUG_POLICY): examples/debug_policy_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(DEMO_DEBUG_POLICY_DISABLED): examples/debug_policy_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(DEMO_INTEGRITY): examples/integrity_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(DEMO_INTEGRITY_DISABLED): examples/integrity_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(SAMPLE_UNPROTECTED): examples/sample_game.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_UNPROTECTED $(INCLUDES) $< -o $@

$(SAMPLE_PROTECTED): examples/sample_game.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@
	$(STRIP) $@
	$(PYTHON3) tools/seal_binary.py $@

$(TEST_DEBUG_POLICY): tests/test_debug_policy.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_DEBUG_POLICY_DISABLED): tests/test_debug_policy.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(TEST_INTEGRITY): tests/test_integrity.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_INTEGRITY_DISABLED): tests/test_integrity.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(TEST_RUNTIME): tests/test_runtime.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_RUNTIME_DISABLED): tests/test_runtime.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

sample-compare: $(SAMPLE_UNPROTECTED) $(SAMPLE_PROTECTED)
	$(PYTHON3) tools/compare_sample.py

test: $(TEST_DEBUG_POLICY) $(TEST_DEBUG_POLICY_DISABLED) \
      $(TEST_INTEGRITY) $(TEST_INTEGRITY_DISABLED) \
      $(TEST_RUNTIME) $(TEST_RUNTIME_DISABLED) \
      $(DEMO_DEBUG_POLICY_DISABLED) $(DEMO_INTEGRITY) $(DEMO_INTEGRITY_DISABLED) \
      $(SAMPLE_UNPROTECTED) $(SAMPLE_PROTECTED)
	./$(TEST_DEBUG_POLICY)
	./$(TEST_DEBUG_POLICY_DISABLED)
	./$(TEST_INTEGRITY)
	./$(TEST_INTEGRITY_DISABLED)
	./$(TEST_RUNTIME)
	./$(TEST_RUNTIME_DISABLED)
	./$(DEMO_DEBUG_POLICY_DISABLED) --mode=check
	$(PYTHON3) tests/test_integrity_e2e.py
	$(PYTHON3) tools/compare_sample.py

clean:
	rm -rf $(BUILD_DIR)
