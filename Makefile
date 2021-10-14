CC = g++
CFLAGS = -Wall -Werror -Wextra -pedantic
LDFLAGS = -lssl -lcrypto -lpcap
TARGET = secret
OBJ = c.o
LOGIN = xkvasn14


all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)
	rm -f *.o

