#
# Makefile for assignment 6 part 2
#
SRC := aesdsocket.c queue.c
TARGET ?= aesdsocket 
OBJS := $(SRC:.c=.o)
CC ?= $(CROSS_COMPILE)gcc 
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lrt -pthread

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
