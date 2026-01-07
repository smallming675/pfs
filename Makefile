CC := gcc
CFLAGS := -O2 -Wall -Wextra -Werror -pedantic -g
LDFLAGS :=
INCLUDES := -Iinclude

SRC := src/fs.c src/logger.c src/main.c src/dir.c
OBJ := $(SRC:src/%.c=build/%.o)

BIN_DIR := bin
BUILD_DIR := build
BIN := $(BIN_DIR)/fs_tool
TEST_BIN := $(BIN_DIR)/tests_runner

.PHONY: all clean run test dirs

all: dirs $(BIN)

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

$(BUILD_DIR)/%.o: src/%.c include/fs.h include/logger.h include/dir.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: dirs $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(BUILD_DIR)/tests.o $(BUILD_DIR)/fs.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/dir.o
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
