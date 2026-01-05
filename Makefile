CC := gcc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -pedantic
LDFLAGS := 
INCLUDES := -Iinclude

SRC := src/fs.c src/logger.c src/main.c
OBJ := $(SRC:src/%.c=build/%.o)

BIN := fs_tool

.PHONY: all clean run test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(BIN)

build/%.o: src/%.c include/fs.h include/logger.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

src/%.o: src/%.c include/fs.h include/logger.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)
	rm -rf tests/tmp

run: $(BIN)
	./$(BIN) -d tests/tmp.img -b 64 init
	./$(BIN) -d tests/tmp.img write tests/sample.txt hello
	./$(BIN) -d tests/tmp.img read hello
	./$(BIN) -d tests/tmp.img delete hello
	./$(BIN) -d tests/tmp.img exam

test: clean all
	bash tests/run.sh
