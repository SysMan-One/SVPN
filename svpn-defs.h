#ifndef	__SVPN$DEF__
#define	__SVPN$DEF__	1

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wdate-time"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
#endif


#ifdef _WIN32
	#pragma once
	#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#endif

/*
**++
**
**  FACILITY:  StarLet VPN service
**
**  DESCRIPTION: StarLet VPN commond data structures and constant definition is supposed to be used
**	in the sVPN server and client code.
**
**  AUTHORS: Ruslan R. (The BadAss SysMan) Laishev
**
**  CREATION DATE:  21-AUG-2019
**
**  MODIFICATION HISTORY:
**
**
**--
*/

#include		"utility_routines.h"



#ifdef __cplusplus
extern "C" {
#endif

#define	SVPN$SZ_IOBUF	2048	/* Default buffer size of the I/O */
#define	SVPN$K_IOBUF	32	/* A number of buffers */
#define	SVPN$SZ_USER	32
#define	SVPN$SZ_PASS	32
#define	SVPN$K_DEFPORT	1394	/* A default port sVPN			*/

enum	{
	SVPN$K_PROTO_V1 = 1	/* A current version of the handshake protocol	*/
};

enum	{
	SVPN$K_ENC_NONE = 0,	/* Encryption of data:	ZERO - no encryption */
	SVPN$K_ENC_XOR,		/* XOR with static key	*/
	SVPN$K_ENC_IDEA,	/* IDEA with PSK	*/
	SVPN$K_ENC_TWOFISH,	/* TWOFISH with PSK	*/
};

enum	{
	SVPN$K_TAG_NAME = 0,	/* ASCII	*/
	SVPN$K_TAG_NET,		/* in_addr	*/
	SVPN$K_TAG_MASK,	/* in_addr	*/
	SVPN$K_TAG_IP,		/* in_addr	*/
	SVPN$K_TAG_IDLE,	/* WORD		*/
	SVPN$K_TAG_KEEPALIVE,	/* WORD		*/
	SVPN$K_TAG_TOTAL,	/* WORD		*/
	SVPN$K_TAG_ENC,		/* OCTET	*/
	SVPN$K_TAG_TRACE,	/* OCTET	*/
	SVPN$K_TAG_MSG		/* ASCII	*/
};

#pragma	pack	(push, 1)


#define	SVPN$SZ_MAZIC	8
#define	SVPN$T_MAZIC	"StarLet"

typedef struct	__svpn_pdu
	{
	unsigned char	magic[SVPN$SZ_MAZIC],
			proto,		/* Protocol version	*/
			req;		/* Request type		*/

	unsigned short	len;		/* Length of the payload part	*/

	unsigned char	data[0];	/* Placeholder for payload of the PDU */
} SVPN_PDU;


#pragma	pack	(pop)

#ifdef __cplusplus
	}
#endif

#endif	/* #ifndef	__SVPN$DEF__	*/
