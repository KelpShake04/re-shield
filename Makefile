CC      ?= cc
AR      ?= ar
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude

BUILD_DIR = build
LIB_OBJS  = $(BUILD_DIR)/anti_debug_common.o \
            $(BUILD_DIR)/anti_debug_macos.o \
            $(BUILD_DIR)/anti_debug_linux.o
LIB_TARGET = $(BUILD_DIR)/libreshield.a

DEMO_BIN         = $(BUILD_DIR)/anti_debug_demo
DEMO_DISABLED    = $(BUILD_DIR)/anti_debug_demo_disabled
TEST_BIN         = $(BUILD_DIR)/test_anti_debug
TEST_DISABLED    = $(BUILD_DIR)/test_anti_debug_disabled

.PHONY: all clean test test-disabled

all: $(LIB_TARGET) $(DEMO_BIN) $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c include/reshield/anti_debug.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(DEMO_BIN): examples/anti_debug_demo.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(TEST_BIN): tests/test_anti_debug.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB_TARGET) -o $@

$(DEMO_DISABLED): examples/anti_debug_demo.c src/anti_debug_common.c src/anti_debug_macos.c src/anti_debug_linux.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

$(TEST_DISABLED): tests/test_anti_debug.c src/anti_debug_common.c src/anti_debug_macos.c src/anti_debug_linux.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DRESHIELD_DISABLE $(INCLUDES) $^ -o $@

test: $(TEST_BIN) $(TEST_DISABLED)
	./$(TEST_BIN)
	./$(TEST_DISABLED)

clean:
	rm -rf $(BUILD_DIR)
