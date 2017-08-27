############################################################################
# Definition of the project directories.
############################################################################

INCLUDE_DIR=include
SRC_DIR=src
OBJECT_DIR=obj

############################################################################
# Definition of the compiler and its flags.
############################################################################

CC=gcc
CFLAGS=-I$(INCLUDE_DIR) -Wall -Werror -Wpedantic -g
LIBS=-lgcrypt

############################################################################
# Definition of the project files.
############################################################################

EXEC     = sec_handover

INCLUDES = \
  $(INCLUDE_DIR)/sh_keys.h \
  $(INCLUDE_DIR)/sh_utils.h \
  $(INCLUDE_DIR)/sh_gcrypt.h \
  $(INCLUDE_DIR)/sec_handover.h \
  $(INCLUDE_DIR)/sh_commons.h

OBJECTS  = \
  $(OBJECT_DIR)/sh_keys.o \
  $(OBJECT_DIR)/sh_utils.o \
  $(OBJECT_DIR)/sh_gcrypt.o \
  $(OBJECT_DIR)/sec_handover.o

############################################################################
# Definitions of the build commands.
############################################################################

$(OBJECT_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDES)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

$(EXEC): $(OBJECTS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

all: $(EXEC) $(OBJECTS)

############################################################################
# Definition of the cleanup and run task.
############################################################################

.PHONY: run clean

run:
	./$(EXEC)

clean:
	rm -f $(OBJECT_DIR)/*.o
	rm -f $(SRC_DIR)/*.c~
	rm -f $(INCLUDE_DIR)/*.h~
	rm -f $(EXEC)
