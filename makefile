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

EXEC     = sec_handover

INCS = \
  $(INC_DIR)/sh_generated_keys.h \
  $(INC_DIR)/sh_utils.h \
  $(INC_DIR)/sh_gcrypt.h \
  $(INC_DIR)/sec_handover.h \
  $(INC_DIR)/sh_commons.h

OBJS  = \
  $(OBJ_DIR)/sh_generated_keys.o \
  $(OBJ_DIR)/sh_utils.o \
  $(OBJ_DIR)/sh_gcrypt.o \
  $(OBJ_DIR)/sec_handover.o

############################################################################
# Definitions for the key generation program. The result is a source file 
# with two keys.
############################################################################

GEN_EXEC    = sh_generate_keys

GEN_OBJS    = $(OBJ_DIR)/sh_generate_keys.o

GEN_KEY_SRC = $(SRC_DIR)/sh_generated_keys.c

############################################################################
# Definitions of the build commands.
############################################################################

all: $(EXEC) $(OBJS) $(GEN_EXEC) $(GEN_OBJS) $(GEN_SRC)
	
$(GEN_KEY_SRC): $(GEN_EXEC)
	./$(GEN_EXEC) $(GEN_KEY_SRC)

$(GEN_EXEC): $(GEN_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	
$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INCS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

############################################################################
# Definition of the cleanup and run task.
############################################################################

.PHONY: run clean

run:
	./$(EXEC)

clean:
	rm -f $(OBJ_DIR)/*.o
	rm -f $(SRC_DIR)/*.c~
	rm -f $(INC_DIR)/*.h~
	rm -f $(EXEC) $(GEN_EXEC) $(GEN_KEY_SRC)
