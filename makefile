############################################################################
# Definition of the project directories.
############################################################################

INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

############################################################################
# Definition of the compiler and its flags.
############################################################################

CC     = gcc
#DEBUG  = -DDEBUG -g

#
# readlink, getpwnam_r, strdup, ...
#
FEATURES = -D _POSIX_C_SOURCE=200809L -std=c11

CFLAGS =  $(FEATURES) -O2 -I$(INC_DIR) -Wextra -Wall -Werror -Wpedantic $(DEBUG)

LIBS   = -lgcrypt

############################################################################
# Definition of the project files.
############################################################################

SH_EXEC     = $(BIN_DIR)/sec_handover
SH_SRC      = $(SRC_DIR)/sec_handover.c
SH_INC      = $(INC_DIR)/sec_handover.h
SH_OBJS     = $(OBJ_DIR)/sec_handover.o

GEN_EXEC    = $(BIN_DIR)/sh_generate_keys
GEN_OBJS    = $(OBJ_DIR)/sh_generate_keys.o
GEN_KEY_SRC = $(SRC_DIR)/sh_generated_keys.c

TEST_EXEC    = $(BIN_DIR)/sh_test
TEST_OBJS    = $(OBJ_DIR)/sh_test.o
TEST_SRC     = $(SRC_DIR)/sh_test.c

TRACER_EXEC    = $(BIN_DIR)/sh_tracer
TRACER_OBJS    = $(OBJ_DIR)/sh_tracer.o
TRACER_SRC     = $(SRC_DIR)/sh_tracer.c

INCS = \
  $(INC_DIR)/sh_generated_keys.h \
  $(INC_DIR)/sh_utils.h \
  $(INC_DIR)/sh_hex.h \
  $(INC_DIR)/sh_gcrypt.h \
  $(INC_DIR)/sh_commons.h \
  $(INC_DIR)/sh_start_data.h

OBJS  = \
  $(OBJ_DIR)/sh_generated_keys.o \
  $(OBJ_DIR)/sh_utils.o \
  $(OBJ_DIR)/sh_hex.o \
  $(OBJ_DIR)/sh_gcrypt.o \
  $(OBJ_DIR)/sh_start_data.o

OBJS_ALL = $(OBJS) $(SH_OBJS) $(GEN_OBJS) $(TEST_OBJS) $(TRACER_OBJS)
EXEC_ALL =         $(SH_EXEC) $(GEN_EXEC) $(TEST_EXEC) $(TRACER_EXEC)

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

$(TRACER_EXEC): $(OBJS) $(TRACER_OBJS) 
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
	
secure:
	rm -f */*.o
	rm -f $(GEN_KEY_SRC)
