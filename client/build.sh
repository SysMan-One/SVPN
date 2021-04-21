#
#set -x
#set -d
#set -v


COPTS="-fPIC -I ../ -D_DEBUG=1 -D__TRACE__=1 -pthread -static -latomic"
# -static-libgcc

#COPTS="-I ../ -pthread -static -latomic"
SRCS="svpn_client.c ../svpn_common.c ../sha1.c ../utility_routines.c"
EXE="svpn_client"

build	()
{
	echo	"Compile with $1 gcc for $2 ..."

	$1gcc -o $EXE-$2 -w -D__ARCH__NAME__=\"$2\" $SRCS $COPTS 
}

	build	"arm-linux-gnueabihf-"		"ARMhf"
	#build	"arm-linux-gnueabi-"		"ARMel"
	#build	"mips-linux-gnu-"		"MIPS32"
	build	""				"x86_64"
	build	"mipsel-linux-gnu-"		"MIPSel"
	build	"mips-linux-gnu-"		"MIPS"
