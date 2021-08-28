############################################################################
# Definition of the project directories.
############################################################################

INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

############################################################################
# Definition of the compiler.
############################################################################

CC = gcc

################################################################################
# A variable that collects the optional flags.
################################################################################

OPTION_FLAGS=

################################################################################
# A debug flag for the application. 
################################################################################

DEBUG = false

ifeq ($(DEBUG),true)
  OPTION_FLAGS += -DDEBUG -g
  
  #
  # The following definitions switch on asan in debug mode.
  #
  OPTION_FLAGS += -fsanitize=address,undefined -fsanitize-undefined-trap-on-error -static-libasan -fno-omit-frame-pointer
endif

############################################################################
# We want all hints for bugs and errors.
############################################################################

OPTION_FLAGS = -Wextra -Wall -Werror -Wpedantic

############################################################################
# Global definition of the POSIX standard. It does not make sence to define
# the standard per file.
#
# readlink, getpwnam_r, strdup, ...
############################################################################

OPTION_FLAGS += -D _POSIX_C_SOURCE=200809L 

############################################################################
# Definition of the c standard (ISO C11).
############################################################################

OPTION_FLAGS += -std=c11

############################################################################
# Set flags and libs
############################################################################

CFLAGS =  $(OPTION_FLAGS) -O2 -I$(INC_DIR) $(shell libgcrypt-config --cflags)

LIBS   = $(shell libgcrypt-config --libs)

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

.PHONY: run test clean secure

run:
	./$(SH_EXEC)

test:
	./$(TEST_EXEC)
	
clean:
	rm -f */*.o 
	rm -f */*.c~
	rm -f */*.h~
	rm -f $(EXEC_ALL) $(GEN_KEY_SRC)
	
secure: clean
	rm -f $(GEN_KEY_SRC)
