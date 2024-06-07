#
# Makefile for assignment 2
#
SRC := writer.c
TARGET = writer 
OBJS := $(SRC:.c=.o)
CC := gcc

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
