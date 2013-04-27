
CXX = $(PREFIX)g++
CC = $(PREFIX)gcc
STRIP = $(PREFIX)strip

LINK_FLAGS = 
COMPILE_C_FLAGS = -O0 -ggdb
COMPILE_CPP_FLAGS = $(COMPILE_C_FLAGS)
LIBS =  


OBJS = pe_parser.o peinfo.o disasm.o

all:	$(OBJS)
	$(CC) -o peinfo $(OBJS)
	
%.o:	%.c
	$(CC) $(COMPILE_C_FLAGS) -c $<
	
clean:
	rm -f *.o peinfo
