CC      ?= cc
AR      ?= ar
PYTHON3 ?= python3
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude

BUILD_DIR = build
LIB_SRCS  = src/anti_debug_common.c \
            src/anti_debug_macos.c \
            src/anti_debug_linux.c \
            src/sha256.c \
            src/integrity_common.c \
            src/integrity_macos.c \
            src/integrity_linux.c
LIB_OBJS  = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
LIB_TARGET = $(BUILD_DIR)/libreshield.a

DEMO_ANTI_DEBUG          = $(BUILD_DIR)/anti_debug_demo
DEMO_ANTI_DEBUG_DISABLED = $(BUILD_DIR)/anti_debug_demo_disabled
DEMO_INTEGRITY           = $(BUILD_DIR)/integrity_demo
DEMO_INTEGRITY_DISABLED  = $(BUILD_DIR)/integrity_demo_disabled

TEST_ANTI_DEBUG          = $(BUILD_DIR)/test_anti_debug
TEST_ANTI_DEBUG_DISABLED = $(BUILD_DIR)/test_anti_debug_disabled
TEST_INTEGRITY           = $(BUILD_DIR)/test_integrity
TEST_INTEGRITY_DISABLED  = $(BUILD_DIR)/test_integrity_disabled

.PHONY: all clean test

all: $(LIB_TARGET) $(DEMO_ANTI_DEBUG) $(DEMO_INTEGRITY) $(TEST_ANTI_DEBUG) $(TEST_INTEGRITY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c include/reshield/anti_debug.h include/reshield/integrity.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(DEMO_ANTI_DEBUG): examples/anti_debug_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(DEMO_ANTI_DEBUG_DISABLED): examples/anti_debug_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(DEMO_INTEGRITY): examples/integrity_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(DEMO_INTEGRITY_DISABLED): examples/integrity_demo.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(TEST_ANTI_DEBUG): tests/test_anti_debug.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_ANTI_DEBUG_DISABLED): tests/test_anti_debug.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(TEST_INTEGRITY): tests/test_integrity.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_INTEGRITY_DISABLED): tests/test_integrity.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

test: $(TEST_ANTI_DEBUG) $(TEST_ANTI_DEBUG_DISABLED) $(TEST_INTEGRITY) $(TEST_INTEGRITY_DISABLED) $(DEMO_INTEGRITY) $(DEMO_INTEGRITY_DISABLED)
	./$(TEST_ANTI_DEBUG)
	./$(TEST_ANTI_DEBUG_DISABLED)
	./$(TEST_INTEGRITY)
	./$(TEST_INTEGRITY_DISABLED)
	$(PYTHON3) tests/test_tamper_e2e.py

clean:
	rm -rf $(BUILD_DIR)
