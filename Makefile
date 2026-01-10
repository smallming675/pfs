CC := gcc
CFLAGS := -O2 -Wall -Wextra -Werror -pedantic -g -D_FILE_OFFSET_BITS=64
LDFLAGS :=
INCLUDES := -Iinclude
FUSE_LIBS := `pkg-config fuse --cflags --libs`

SRC := src/fs.c src/logger.c src/main.c src/dir.c
OBJ := $(SRC:src/%.c=build/%.o)
SRC_PFS := src/fs.c src/logger.c src/dir.c src/pfs.c
OBJ_PFS := $(SRC_PFS:src/%.c=build/%.o)

BIN_DIR := bin
BUILD_DIR := build
BIN := $(BIN_DIR)/fs_tool
BIN_PFS := $(BIN_DIR)/pfs
TEST_BIN := $(BIN_DIR)/tests_runner
PFS_TEST_BIN := $(BIN_DIR)/pfs_tests_runner

.PHONY: all clean run test dirs

all: dirs $(BIN) $(BIN_PFS)

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

$(BIN_PFS): $(OBJ_PFS)
	$(CC) $(CFLAGS) $(OBJ_PFS) -o $@ $(FUSE_LIBS)

$(BUILD_DIR)/%.o: src/%.c include/fs.h include/logger.h include/dir.h include/pfs.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: dirs $(TEST_BIN) $(PFS_TEST_BIN)
	./$(TEST_BIN)
	./$(PFS_TEST_BIN)

$(TEST_BIN): $(BUILD_DIR)/tests.o $(BUILD_DIR)/fs.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/dir.o
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

$(PFS_TEST_BIN): src/pfs_tests.c $(BUILD_DIR)/fs.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/dir.o $(BUILD_DIR)/pfs.test.o
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(FUSE_LIBS)

$(BUILD_DIR)/pfs.test.o: src/pfs.c include/fs.h include/logger.h include/dir.h include/pfs.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -DTEST_BUILD -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
