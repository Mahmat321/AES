CFLAGS = -std=c11 -Wall -Wextra -g -O2
CPPFLAGS = 
LDFLAGS = 

all: aes

aes: aes.o main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< 


	
clean:
	@rm -f *.o aes

help:
	@echo " Usage"
	@echo " make build the whole project"
	@echo " make clean to remove the files that was generated from the make all"
	@echo " make help to get his"
