CXX = gcc
CXXFLAGS = -g -Wall -Werror -Wextra -pedantic -Wno-pointer-sign 
LDFLAGS =
LBLIBS = -lrt -pthread

SRC = midterm.c
OBJ = $(SRC:.cc=.o)
EXEC = program

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LBLIBS)

clean:
	rm program
