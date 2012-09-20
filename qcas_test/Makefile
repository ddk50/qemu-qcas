CC 	     = gcc
CFLAGS   = -Wall -g
LD		 = gcc
LIBS     = -g -lpthread -lghthash
INCLUDES = -I../block -I..
OBJS	 = qemu-io-emulation.o qemu-emulation-test.o qemu-bswap-emulation.o ../sha1.o

qcastest: $(OBJS)
	$(LD) -o $@ $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -c $<

qemu-io-emulation.o: qemu-io-emulation.h qemu-queue.h qemu-debug.h ../block/qcas-debug.h
qemu-bswap-emulation.o: qemu-bswap-emulation.h qemu-debug.h
qemu-emulation-test.o: qemu-io-emulation.h qemu-bswap-emulation.h qemu-debug.h
../block/qcas.o: qemu-io-emulation.h qemu-bswap-emulation.h
../sha1.o: ../sha1.h

clean:
	rm -rf *.o
	rm -rf qcastest
	rm -rf *.dbf
	rm -rf *.f2o
	rm -rf test.file
	rm -rf *.qcas
