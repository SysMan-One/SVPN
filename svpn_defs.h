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
#define	SVPN$SZ_SALT	32

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
	SVPN$K_TAG_NAME = 1,	/* BBLOCK/ASCII	*/
	SVPN$K_TAG_NET,		/* in_addr	*/
	SVPN$K_TAG_NETMASK,	/* in_addr	*/
	SVPN$K_TAG_CLIADDR,	/* in_addr	*/
	SVPN$K_TAG_IDLE,	/* WORD		*/
	SVPN$K_TAG_KEEPALIVE,	/* WORD		*/
	SVPN$K_TAG_TOTAL,	/* WORD		*/
	SVPN$K_TAG_ENC,		/* OCTET	*/
	SVPN$K_TAG_TRACE,	/* OCTET	*/
	SVPN$K_TAG_MSG,		/* BBLOCK/ASCII	*/
	SVPN$K_TAG_USER,	/* BBLOCK/ASCII	*/

};


enum	{
	SVPN$K_STATECTL,	/* VPN State - waiting for remote/peer initial request */
	SVPN$K_STATETUN,	/* In data tunneling mode	*/
};



enum	{			/* Signaling channel requests */
	SVPN$K_REQ_NOPE = 0,

	SVPN$K_REQ_LOGIN,
	SVPN$K_REQ_LOGOUT,
	SVPN$K_REQ_ACCEPT,
	SVPN$K_REQ_REJECT,
	SVPN$K_REQ_PING,
	SVPN$K_REQ_PONG
};


#pragma	pack	(push, 1)


#define	SVPN$SZ_MAZIC	8
#define	SVPN$T_MAZIC	"StarLet"
#define	SVPN$SZ_DIGEST	20	/* SHA1 size	*/

typedef struct	__svpn_pdu
	{
	unsigned char	magic[SVPN$SZ_MAZIC],
			proto,		/* Protocol version	*/
			req,		/* Request type		*/
			digest[SVPN$SZ_DIGEST];	/* SHA1		*/

	unsigned char	data[0];	/* Placeholder for payload of the PDU */
} SVPN_PDU;

#define	SVPN$SZ_PDUHDR	(offsetof(struct __svpn_pdu, data))
#define	SVPN$SZ_HASHED	(offsetof(struct __svpn_pdu, digest))


typedef struct	__svpn_tlv
	{
	unsigned char	tag,
			len;
	union	{
		unsigned char	b_val[0];
		unsigned short	w_val[0];
		unsigned	l_val[0];
		unsigned long long q_val[0];
	};
} SVPN_TLV;


enum	{
	SVPN$K_BBLOCK = 0,		/* Octets block			*/
	SVPN$K_WORD,			/* 16-bits unsigned word	*/
	SVPN$K_LONG,			/* 32-bit unsigned longword	*/
	SVPN$K_QUAD,			/* 64-bit unsigned long longword*/
	SVPN$K_IP			/* IP4 or IP6 address		*/
};

int	tlv_get (void *buf, int bufsz, unsigned v_tag, unsigned *v_type, void *val, unsigned *valsz);
int	tlv_put (void *buf, unsigned bufsz, unsigned v_tag, unsigned v_type, void *val, unsigned valsz, unsigned *adjlen);
void	tlv_dump (void *buf, unsigned bufsz);

static	inline	void	rand_octets(
		void	*buf,
		int	 bufsz
			)
{
int	i, r, *ip;

	srand((unsigned) time(NULL)) ;

	for(i =  135 + (time(NULL)%135); i--; )
		rand();

	for (i = bufsz/(sizeof (int)), ip = (int *)buf; i--; ip++ )
		*ip = rand();

	if ( i = (bufsz % (sizeof(int))) )
		{
		r = rand();
		memcpy(ip, &r, i);
		}
}


#pragma	pack	(pop)


#ifdef __cplusplus
	}
#endif

#endif	/* #ifndef	__SVPN$DEF__	*/
