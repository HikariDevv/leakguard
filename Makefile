CXX ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic
SRCS := src/main.cpp src/entropy.cpp src/rules.cpp src/scanner.cpp src/reporter.cpp
TARGET := leakguard

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET).exe
