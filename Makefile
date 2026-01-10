CC := gcc
CFLAGS := -O2 -Wall -Wextra -Werror -pedantic -g -D_FILE_OFFSET_BITS=64
LDFLAGS :=
INCLUDES := -Iinclude
FUSE_LIBS := `pkg-config fuse --cflags --libs`

BIN_DIR := bin
BUILD_DIR := build

SRC := src/fs.c src/logger.c src/dir.c
OBJ := $(SRC:src/%.c=build/%.o)

SRC_PFS := src/pfs.c
OBJ_PFS := $(BUILD_DIR)/fs.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/dir.o $(BUILD_DIR)/pfs_main.o 

BIN_PFS := $(BIN_DIR)/pfs
TESTS_RUNNER := $(BIN_DIR)/tests_runner

.PHONY: all clean test run

all: $(BUILD_DIR) $(BIN_DIR) $(BIN_PFS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BUILD_DIR)/pfs_main.o: src/pfs.c include/fs.h include/logger.h include/dir.h include/pfs.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(BUILD_DIR)/pfs_main.o

$(BUILD_DIR)/pfs_test.o: src/pfs.c include/fs.h include/logger.h include/dir.h include/pfs.h
	$(CC) $(CFLAGS) $(INCLUDES) -DTEST_BUILD -c $< -o $(BUILD_DIR)/pfs_test.o

$(BUILD_DIR)/%.o: src/%.c include/fs.h include/logger.h include/dir.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN_PFS): $(OBJ_PFS)
	$(CC) $(CFLAGS) $(OBJ_PFS) -o $@ $(FUSE_LIBS)

$(TESTS_RUNNER): src/tests.c $(BUILD_DIR)/fs.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/dir.o $(BUILD_DIR)/pfs_test.o
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(FUSE_LIBS)

test: $(TESTS_RUNNER)
	./$(TESTS_RUNNER)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
