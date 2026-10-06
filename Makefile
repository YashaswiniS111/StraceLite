CC = gcc

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude

TARGET = build/stracelite

SRC = src/main.c \
      src/tracer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -rf build/*

debug: CFLAGS += -O0
debug: $(TARGET)

.PHONY: all clean debug
