TARGETS=hw4
hw4: hw4.c
	gcc -g --std=gnu99 -o hw4 hw4.c 

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

