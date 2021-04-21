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
**	14-MAY-2020	RRL	Removed delta field from VSTAT.
**
**	12-SEP-2020	RRL	Now structure of SVPN_STAT record  live here.
**
**	 3-OCT-2020	RRL	Added new TAG OPTIONS to carry capabilities.
**
**--
*/

#include		"utility_routines.h"



#ifdef __cplusplus
extern "C" {
#endif

#define	SVPN$SZ_IOBUF	2048			/* Default buffer size of the I/O */
#define	SVPN$K_IOBUF	32			/* A number of buffers */
#define	SVPN$SZ_USER	32
#define	SVPN$SZ_PASS	32
#define	SVPN$K_DEFPORT	1394			/* A default port sVPN			*/
#define	SVPN$SZ_SALT	32
#define	SVPN$SZ_MAXIPBLOG	32		/* A maximum entries in the IP Backlog file	*/

enum	{
	SVPN$K_PROTO_V1 = 1			/* A current version of the handshake protocol	*/
};


enum	{
	SVPN$K_ENC_NONE = 0,			/* Encryption of data:	ZERO - no encryption */
	SVPN$K_ENC_XOR,				/* XOR with static key	*/
	SVPN$K_ENC_IDEA,			/* IDEA with PSK	*/
	SVPN$K_ENC_TWOFISH,			/* TWOFISH with PSK	*/
};

#define	SVPN$K_OPT_AGGR	0x1			/* Aggregation		*/

enum	{
	SVPN$K_TAG_NAME = 1,			/* BBLOCK/ASCII	*/
	SVPN$K_TAG_NET,				/* in_addr	*/
	SVPN$K_TAG_NETMASK,			/* in_addr	*/
	SVPN$K_TAG_CLIADDR,			/* in_addr	*/
	SVPN$K_TAG_IDLE,			/* WORD		*/
	SVPN$K_TAG_PING,			/* WORD		*/
	SVPN$K_TAG_RETRY,			/* WORD		*/
	SVPN$K_TAG_TOTAL,			/* WORD		*/
	SVPN$K_TAG_ENC,				/* OCTET	*/
	SVPN$K_TAG_TRACE,			/* OCTET	*/
	SVPN$K_TAG_MSG,				/* BBLOCK/ASCII	*/
	SVPN$K_TAG_USER,			/* BBLOCK/ASCII	*/
	SVPN$K_TAG_TIME,			/* timespec	*/
	SVPN$K_TAG_SEQ,				/* LONGWORD	*/
	SVPN$K_TAG_REV,				/* BBLOCK/ASCII	*/
	SVPN$K_TAG_TUNTYPE,			/* WORD		*/
	SVPN$K_TAG_OPTS				/* LONGWORD	*/
};


enum	{
	SVPN$K_STATECTL,			/* VPN State - waiting for remote/peer initial request */
	SVPN$K_STATEON,				/* New session has been etsablished	*/
	SVPN$K_STATETUN,			/* In data tunneling mode	*/
	SVPN$K_STATEOFF				/* Data channel is need to be closed */
};


enum	{					/* Signaling channel requests */
	SVPN$K_REQ_NOPE = 0,

	SVPN$K_REQ_LOGIN,
	SVPN$K_REQ_LOGOUT,
	SVPN$K_REQ_ACCEPT,
	SVPN$K_REQ_REJECT,
	SVPN$K_REQ_PING,
	SVPN$K_REQ_PONG
};


#pragma	pack	(push, 1)


#define	SVPN$SZ_MAGIC	8
#define	SVPN$T_MAGIC	"StarLet"
#define	SVPN$SZ_DIGEST	20			/* SHA1 size	*/


typedef struct	__svpn_vstat__
	{
	struct timespec rtt;

	unsigned long long
		bnetrd,
		bnetwr,
		pnetrd,
		pnetwr;

} SVPN_VSTAT;


/* Structue of record in the STAT file */
typedef struct	__svpn_stat_rec__
	{
	struct tm	tmrec;

	unsigned long long
		btunrd,				/* Octets counters	*/
		btunwr,
		bnetrd,
		bnetwr,

		ptunrd,				/* Packets counters	*/
		ptunwr,
		pnetrd,
		pnetwr;

	struct  timespec ts;
} SVPN_STAT_REC;


/*
 *	Definitions of the element uses in the network interchange
 *
 *	|<-------- PDU   ----------------->|
 *	+---------+---------+    +---------+
 *	| HDR     | TLV 1   | ...| TLV N   |
 *	+---------+---------+    +---------+
*/
typedef struct	__svpn_pdu
	{
	union {
	unsigned char	magic[SVPN$SZ_MAGIC];
	unsigned long long magic64;
	};

	unsigned char	proto,			/* Protocol version	*/
			req,			/* Request type		*/
			digest[SVPN$SZ_DIGEST];	/* SHA1		*/

	unsigned char	data[0];		/* Placeholder for payload of the PDU */
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
	SVPN$K_BBLOCK = 0,			/* Octets block			*/
	SVPN$K_WORD,				/* 16-bits unsigned word	*/
	SVPN$K_LONG,				/* 32-bit unsigned longword	*/
	SVPN$K_QUAD,				/* 64-bit unsigned long longword*/
	SVPN$K_IP				/* IP4 or IP6 address		*/
};


/*	Value type is 3 bits
 *	Tag Id is 5 bits
 */
#define	TAG$M_TYPE	0xE0
#define	TAG$M_ID	(~(TAG$M_TYPE))


int	tlv_get (void *buf, int bufsz, unsigned v_tag, unsigned *v_type, void *val, unsigned *valsz);
int	tlv_put (void *buf, unsigned bufsz, unsigned v_tag, unsigned v_type, void *val, unsigned valsz, unsigned *adjlen);


/**
 * @brief avproto_encode_tag - encapsulate given 'v_type' and  'v_tag' into the 16-bits field.
 *	return NBO representation of the w_tag;
 *
 * @param v_type	- Tag type, see TAG$K_* constatnts
 * @param v_tag		- Tasg Id, application specific Tag Id
 *
 * @return	- 16 bits TLV.w_tag field, NBO
 */
inline	static unsigned char tlv_encode_tag
		(
	unsigned char	v_type,
	unsigned char	v_tag
		)
{
	return	( (v_type << 5) | v_tag );
}

/**
 * @brief avproto_decode_tag - extract 'tag id' and 'tag type' field from the TLV.w_tag.
 *	Return w_gat in the Host Order Byte
 *
 * @param w_tag		- TLV.w_tag field, NBO
 * @param v_type	- an address of variable to accept unpacked 'tag type' field
 * @param v_tag		- an address of variable to accept unpacked 'tag id field
 *
 * @return	- 16 bits, TLV_w_tag in Host Order Byte
 */
inline static unsigned char	tlv_decode_tag
		(
	unsigned char	tag,
	unsigned char	*v_type,
	unsigned char	*v_tag
		)
{

	*v_type = tag >> 5;
	*v_tag = tag & TAG$M_ID;

	return	tag;
}

#pragma	pack	(pop)

/*
 *   DESCRIPTION: Encrypting given buffer by XOR-ing with the specified key, it's simples kind of obfuscation.
 *
 *   INPUT:
 *	src:	A buffer with the data to be processed on the place
 *	srclen:	A length of the data in the buffer
 *	key:	A key octets string
 *	keysz:	Key length
 *
 *   OUTPUT:
 *	src:	Has been XOR-ed data
 *
 *   RETURNS:
 *	NONE
 */
static inline	int	qbox_xor	(
				void	*buf,
				int	 buflen,
				void	*key,
				int	 keysz
					)
{
int	i, j, *isrc = (int *) buf, *ikey;
char	*csrc , *ckey;

	keysz	= keysz/sizeof(int);

	assert(keysz);



	/* Step by 4 octets ... */
	for ( i = buflen / sizeof(int), j = 0, ikey = (int *) key; i--; )
		{
		/* XOR-ing 32-bits data with 32-bits of key */
		(*isrc) = (*isrc) ^ (*ikey);

		isrc++;
		ikey = (int *) key + j % keysz;
		}



	/* Rest of buffer */
	csrc = (char *) isrc;

	for ( i = buflen % sizeof(int), ckey = key; i; i--)
		{
		/* XOR-ing 8-bits data with 8-bits of key */
		(*csrc) = (*csrc) ^ (*ckey);

		csrc++;
		ckey++;
		}

	return	STS$K_SUCCESS;
}



static inline 	int	decode	(
		int	algo,
		void	*buf,
		int	buflen,
		void	*key,
		int	keysz
		)
{
	switch (algo)
		{
		case	SVPN$K_ENC_NONE:	/* No encryption */
			return	STS$K_SUCCESS;

		case	SVPN$K_ENC_XOR:		/* Simple XOR-ing	*/
			return	qbox_xor (buf, buflen, key, keysz);

		case	SVPN$K_ENC_IDEA:
		case	SVPN$K_ENC_TWOFISH:

		default:
			return	STS$K_WARN;
		}

	return	STS$K_ERROR;
}




static inline 	int	encode	(
		int	algo,
		void	*buf,
		int	buflen,
		void	*key,
		int	keysz
		)
{
	switch (algo)
		{
		case	SVPN$K_ENC_NONE:	/* No encryption */
			return	STS$K_SUCCESS;

		case	SVPN$K_ENC_XOR:		/* Simple XOR-ing	*/
			return	qbox_xor (buf, buflen, key, keysz);

		case	SVPN$K_ENC_IDEA:
		case	SVPN$K_ENC_TWOFISH:

		default:
			return	STS$K_WARN;
		}

	return	STS$K_ERROR;
}


#ifdef __cplusplus
	}
#endif

#endif	/* #ifndef	__SVPN$DEF__	*/
