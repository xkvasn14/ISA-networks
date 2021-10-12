CC = g++
CFLAGS = -Wall -Werror
TARGET = secret
OBJ = c.o
LOGIN = xkvasn14


all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@
	rm -f *.o

