TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG	+= -static

HEADERS += \
	../svpn_defs.h

SOURCES += \
	../utility_routines.c \
	../svpn_common.c \
	svpn_util.c \



INCLUDEPATH	+= ..\

LIBS	+= -static
# -pthread -lrt




if (linux-aarch64-g++):{
	message(Building ARM64/AArch64 )
	DEFINES		+= __ARCH__NAME__=\\\"ARM64\\\"
}
if (linux-arm-gnueabihf-g++):{
	message(Building ARM(hf) )
	DEFINES		+= __ARCH__NAME__=\\\"ARMhf\\\"
}
if (linux-arm-gnueabi-g++):{
	message(Building ARM(el) )
	DEFINES		+= __ARCH__NAME__=\\\"ARMel\\\"
}
if (linux-mipsel-g++):{
	message(Building MIPS(el)/32 )
	DEFINES		+= __ARCH__NAME__=\\\"MIPSel\\\"
}
if (linux-g++-32):{
	message(Building x86/32 bit )
	QMAKE_CFLAGS	= -m32
	QMAKE_CXXFLAGS	= -m32
	QMAKE_LFLAGS	= -m32
	CONFIG	+= warn_off

	DEFINES		+= __ARCH__NAME__=\\\"i386\\\"
}
if (linux-g++-64 | linux-g++):{
	message(Building x86/64 bit )
	QMAKE_CFLAGS	= -m64
	QMAKE_CXXFLAGS	= -m64
	QMAKE_LFLAGS	= -m64

	DEFINES		+= __ARCH__NAME__=\\\"x86_64\\\"
}


CONFIG (debug, debug|release) {
	DEFINES	+= _DEBUG=1 __TRACE__=1
	CONFIG	+= -static
	LIBS	+= -static -static-libgcc

}
else {
	CONFIG	+= warn_off
	DEFINES	+= _DEBUG=1 __TRACE__=1
	CONFIG	+= -static
	LIBS	+= -static -static-libgcc
}

