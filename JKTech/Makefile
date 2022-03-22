# Makefile by Hailun Tan.

current_dir = $(shell pwd)

SRC_DIR = $(current_dir)/src
OBJ_DIR = $(current_dir)/obj
LIB_DIR = $(current_dir)/lib
BIN_DIR = $(current_dir)/bin

# static library name
LIBNAME = LicenseTimeStamp

# source files  (i.e., *.cpp files)
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# *.o files
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

# static library file name
OUT = ${LIB_DIR}/lib${LIBNAME}.a
 
# include directories
INCLUDES = -I. -I $(current_dir)/include/ -I/usr/local/include
 
# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -g -std=c++11
 
# C++ compiler
CCC = g++
 
# library paths
LIBS = -L$(LIB_DIR) -L/usr/local/lib -lm
 
# compile flags
LDFLAGS = -g 

all: ${LIBNAME}Test
	$(CCC)  -o $(BIN_DIR)/$< ${LIBS} -l${LIBNAME}

.SUFFIXES: .cpp
 
${LIBNAME}Test: $(OUT)

$(OBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp
	$(CCC) $(INCLUDES) $(CCFLAGS) -c $< -o $@
 
$(OUT): $(OBJS)
	ar rcs $(OUT) $(OBJS)
 
depend: dep

# here is the Makefile space for the unit test build recipes 
# TODO: It is a code test for job application, it is skipped for now given the limited amount of time.  But it is not a problem for me to complete this section. 
test:
	@echo "to be implemented"
 
dep:
	makedepend -- $(CFLAGS) -- $(INCLUDES) $(SRCS)
 
clean:
	rm -rf $(LIB_DIR)/* $(BIN_DIR)/* $(OBJ_DIR)/* $(current_dir)/${LIBNAME}Test $(OUT) Makefile.bak