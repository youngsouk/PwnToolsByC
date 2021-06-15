CC = "gcc"
CFLAGS = "-W"
TARGET = exp

$(TARGET) : pwnc.o exp.o
	$(CC) $(CFLAGS) -o $(TARGET) pwnc.o exp.o

pwnc.o : pwnc.c
	$(CC) $(CFLAGS) -c -o pwnc.o pwnc.c

exp.o : exp.c
	$(CC) $(CFLAGS) -c -o exp.o exp.c

clean : 
	rm pwnc.o exp.o exp