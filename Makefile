# Faculty: BUT FIT 
# Course: KRY
# Project Name: SHA-256, Length extension attack
# Name: Jakub Kuznik
# Login: xkuzni04
# Year: 2024

CC = g++

CFLAGS = -g -Wpedantic -Wall -Wextra 
all: kry

kry: kry.cpp 
	g++ $(CFLAGS) -o kry kry.cpp 


clean:
	rm *.o kry 

zip: Makefile kry.cpp kry.hpp README.md
	zip 231552.zip $^