#
#set -x
#set -d
#set -v


COPTS="-fPIC -I ../ -D_DEBUG=1 -D__TRACE__=1 -static"
# -static-libgcc

#COPTS="-I ../ -pthread -static"
SRCS="svpn_util.c ../utility_routines.c"
EXE="svpn_util"

build	()
{
	echo	"Compile with $1 gcc for $2 ..."

	$1gcc -o $EXE-$2 -w -D__ARCH__NAME__=\"$2\" $SRCS $COPTS 
}

	build	"arm-linux-gnueabihf-"		"ARMhf"
	#build	"arm-linux-gnueabi-"		"ARMel"
	#build	"mips-linux-gnu-"		"MIPS32"
	#build	"mipsel-linux-gnu-"		"MIPSel"
	build	""				"x86_64"
