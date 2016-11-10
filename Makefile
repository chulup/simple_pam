all: mypam.so pam_test

mypam.o: src/mypam.cpp
	g++ -fPIC -fno-stack-protector -o mypam.o -c src/mypam.cpp

mypam.so: mypam.o
	ld --discard-all -shared -o mypam.so mypam.o

pam_test: src/test.c
	g++ -o pam_test src/test.c -lpam -lpam_misc
