CC 	      = gcc
OPTCFLAGS = $(shell pkg-config --cflags glib-2.0)
CFLAGS   = -Wall -g
LD		 = gcc
OPTLIBS  = $(shell pkg-config --libs glib-2.0)
LIBS     = -g -lpthread -lghthash
INCLUDES = -I../block -I..
OBJS	 = qemu-io-emulation.o qemu-emulation-test.o qemu-bswap-emulation.o qemu-test.o ../sha1.o

qcastest: $(OBJS)
	$(LD) -o $@ $(OBJS) $(OPTLIBS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(OPTCFLAGS) $(INCLUDES) -c $<

qemu-io-emulation.o: qemu-io-emulation.h qemu-queue.h qemu-bswap-emulation.h qemu-debug.h ../block/qcas-debug.h
qemu-bswap-emulation.o: qemu-bswap-emulation.h qemu-debug.h
qemu-emulation-test.o: qemu-io-emulation.h qemu-bswap-emulation.h qemu-debug.h
qemu-test.o: qemu-io-emulation.h qemu-queue.h qemu-debug.h ../block/qcas-debug.h ../block/qcas.c
../block/qcas.o: qemu-io-emulation.h qemu-bswap-emulation.h
../sha1.o: ../sha1.h

clean:
	rm -rf *.o
	rm -rf qcastest
	rm -rf *.dbf
	rm -rf *.f2o
	rm -rf test.file
	rm -rf *.qcas
