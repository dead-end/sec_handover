############################################################################
# Definition of the project directories.
############################################################################

INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj

############################################################################
# Definition of the compiler and its flags.
############################################################################

CC     = gcc
CFLAGS = -I$(INC_DIR) -Wall -Werror -Wpedantic -g
LIBS   = -lgcrypt

############################################################################
# Definition of the project files.
############################################################################

SH_EXEC     = sec_handover
SH_SRC      = $(SRC_DIR)/$(SH_EXEC).c
SH_INC      = $(INC_DIR)/$(SH_EXEC).h
SH_OBJS     = $(OBJ_DIR)/$(SH_EXEC).o

GEN_EXEC    = sh_generate_keys
GEN_OBJS    = $(OBJ_DIR)/$(GEN_EXEC).o
GEN_KEY_SRC = $(SRC_DIR)/sh_generated_keys.c

TEST_EXEC    = sh_test
TEST_OBJS    = test/$(TEST_EXEC).o
TEST_SRC     = test/$(TEST_EXEC).c

INCS = \
  $(INC_DIR)/sh_generated_keys.h \
  $(INC_DIR)/sh_utils.h \
  $(INC_DIR)/sh_gcrypt.h \
  $(INC_DIR)/sh_commons.h

OBJS  = \
  $(OBJ_DIR)/sh_generated_keys.o \
  $(OBJ_DIR)/sh_utils.o \
  $(OBJ_DIR)/sh_gcrypt.o

OBJS_ALL = $(OBJS) $(SH_OBJS) $(GEN_OBJS) $(TEST_OBJS)
EXEC_ALL =         $(SH_EXEC) $(GEN_EXEC) $(TEST_EXEC)

############################################################################
# Definitions of the build commands.
############################################################################

all: $(EXEC_ALL) $(OBJS_ALL) $(GEN_KEY_SRC)
	
$(GEN_KEY_SRC): $(GEN_EXEC)
	./$(GEN_EXEC) $(GEN_KEY_SRC)

$(GEN_EXEC): $(GEN_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(TEST_EXEC): $(OBJS) $(TEST_OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	
$(SH_EXEC):   $(OBJS) $(SH_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INCS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

############################################################################
# Definition of the cleanup and run task.
############################################################################

.PHONY: run clean

run:
	./$(SH_EXEC)

test:
	./$(SH_TEST)
	
clean:
	rm -f */*.o 
	rm -f */*.c~
	rm -f */*.h~
	rm -f $(EXEC_ALL) $(GEN_KEY_SRC)
