TARGET = libfpc.a

CC = g++
CFLAGS= -pipe -fPIC -O3 -g -Wall -c -march=native -mtune=native

INC = -I.
OBJ_DIR=./obj
OUT_DIR=.
SRC_DIR=.

#Lib for fpc.c	
FILES = $(SRC_DIR)/fpc.c

$(TARGET): $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(FILES))
	ar -rcs -o $(OUT_DIR)/$@ $^

#Compiling every *.c to *.o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c dirmake
	$(CC) -c $(INC) $(CFLAGS) -o $@  $<
	
dirmake:
	@mkdir -p $(OBJ_DIR)
	
clean:
	rm -f $(OBJ_DIR)/*.o $(OUT_DIR)/$(TARGET)

rebuild: clean build
