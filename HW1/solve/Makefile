CXX := g++
TARGET := sandbox.so
SRC := sandbox.cpp
CXXFLAGS := -std=c++20 -g -Wall -fPIC -shared -ldl

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@

.PHONY: clean
clean:
	rm -f $(TARGET)