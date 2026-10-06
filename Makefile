CC = gcc

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude

TARGET = build/stracelite

SRC = src/main.c \
      src/tracer.c \
      src/syscall.c \
      src/memory.c \
      src/stats.c \
      src/filter.c

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -rf build/*

.PHONY: all clean
