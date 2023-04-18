all: write_bench

write_bench: main.cpp
	$(CXX) -O3 -std=c++17 -o $@ $< -luring
