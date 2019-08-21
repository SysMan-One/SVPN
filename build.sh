#
#
#

#linux-mipsel-g++
#linux-arm-gnueabi-g++ 
#linux-g++-32
#linux-g++-64


#SPEC=linux-aarch64-g++
#SPEC=linux-arm-gnueabihf-g++
#SPEC=linux-arm-gnueabi-g++
#SPEC=linux-mipsel-g++

#SPEC=linux-g++-32
SPEC=linux-g++-64
DEST="./"
PRO="simpletun.pro"


CDIR=$PWD


build	()
{
    echo	"------------------------------ Build $1, destination directory $2 ..."

    qmake $PRO -r -spec $1
    make -f Makefile clean
    make -f Makefile
    cp -v 	./simpletun		./simpletun-$2

}

    build	"linux-arm-gnueabihf-g++"	"ARMhf"
    build	"linux-arm-gnueabi-g++"		"ARMel"
    build	linux-g++-64	"x86_64"
