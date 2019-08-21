#ifndef	__AVPROTO$DEF__
#define	__AVPROTO$DEF__	1

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
**  FACILITY:  AVProto - Attribute/Value Pair (AKA TLV) based protocol
**
**  ABSTRACT: Carring data incapsulated in to the AVP microcontainers
**
**  DESCRIPTION: This module contains data structures and constant definition is supposed to be used
**	in the core AVProto routines as well as in general API routines.
**
**  DESIGN ISSUE:
**
**	A main idea is imaginated follows :
**
	PDU (protocol/packet data unit ) - is a block is supposed to be send to remote peer over network

		 |<- Payload (see Header.len field)-->|
	+--------+-------+-------+--    ...  ----+-------+
	| Header | TLV 0 | TLV 1 |          .... | TLV N |
	+--------+-------+-------+----  ...    --+-------+

	PDU's Header :
	+-----------+-----------+-----------+-----------+
	| magic     |  len      |  csr      |   seq     |
	| 8 octets  |  4 octets |  4 octets |   4 octets
	+-----------+-----------+-----------+-----------+

	T[ag] L[ength] V[alue] :
	0                    16                  32
	+---------+-----------+-------------------+
	| Type    |   Id      |      Length       |
	| 4 bits  |   12 bits |      16 bits      |
	+---------+-----------+-------------------+
	|    optional data (value)                |
	|      0 - 'Length' octets                |
	+---------+-----------+-------------------+
**
**  AUTHORS: Ruslan R. Laishev (RRL)
**
**  CREATION DATE:  20-JUL-2018
**
**  MODIFICATION HISTORY:
**
**	15-FEB-2019	RRL	Removed bitfields.
**
**	22-FEB-2019	RRL	Added closing for "#ifdef __cplusplus"
**				some code reorganizing;
**
**	29-JUL-2019	RRL	Added declaration for avproto_dump();
**				improved error handling in the avproto_hget();
**
**
**--
*/

#include	<endian.h>


#ifdef __cplusplus
extern "C" {
#endif



/*
 * AVP/TLV - type of block types to help transparent conversion of the well-know datas
 * is carried in NBO or to help LE/Be conversion
 */
enum	{
	TAG$K_BBLOCK = 0,	/* A default type - octets block	*/
	TAG$K_WORD = 3,		/* 16-bits word, NBO			*/
	TAG$K_LONGWORD,		/* 32-bits word, NBO			*/
	TAG$K_QWORD,		/* 64-bits word, NBO			*/
	TAG$K_UUID = 8,		/* UUID					*/


	TAG$K_MAX		/* EOL marker, mast be last!		*/
};


#pragma	pack (push, 1)

#define	TAG$M_TYPE	0xf000
#define	TAG$M_ID	(~(TAG$M_TYPE))

typedef struct __avproto_tlv__ {

	unsigned short	w_tag;	/* Tag's type and id			*/
	unsigned short	w_len;	/* Actual data length in the b_val[]	*/

	union	{		/* Placeholder for data block		*/
		unsigned char	b_val[0];
		unsigned short	w_val[0];
		unsigned	u_val[0];
	unsigned long long	q_val[0];
	};
} AVPROTO_TLV;

typedef struct __avproto_hdr__ {
	unsigned char	magic[8];
	unsigned	u_len;		/* A length of payload follows header	*/
	unsigned	u_csr;		/* Command/Status Register		*/

	unsigned	u_seq;		/* A PDU sequence number is supposed to help
					  parallel and asyncronus processing	*/

} AVPROTO_HDR;

typedef struct __avproto_pdu__ {
	AVPROTO_HDR	r_hdr;		/* Fixed length header			*/
	AVPROTO_TLV	r_tlv[0];	/* Placeholder for variable part of PDU	*/
} AVPROTO_PDU;

#pragma	pack (pop)

/**
 * @brief avproto_encode_tag - encapsulate given 'v_type' and  'v_tag' into the 16-bits field.
 *	return NBO representation of the w_tag;
 *
 * @param v_type	- Tag type, see TAG$K_* constatnts
 * @param v_tag		- Tasg Id, application specific Tag Id
 *
 * @return	- 16 bits TLV.w_tag field, NBO
 */
inline	static unsigned short avproto_encode_tag
		(
	unsigned short	v_type,
	unsigned short	v_tag
		)
{
	return	htobe16 ( ( (v_type << 12) | v_tag ));
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
inline static unsigned short	avproto_decode_tag
		(
	unsigned short	w_tag,
	unsigned short	*v_type,
	unsigned short	*v_tag
		)
{
unsigned short tag = 0;

	tag = be16toh(w_tag);

	*v_type = tag >> 12;
	*v_tag = tag & TAG$M_ID;

	return	tag;
}


int	avproto_put  (void *pdu, unsigned short pdusz, unsigned v_tag, unsigned v_type, void *val, unsigned valsz);
int	avproto_get  (void *pdu, int *context, unsigned v_tag, unsigned *v_type, void *val, unsigned *valsz);
void	avproto_dump (void *pdu);


/*
 *  DESCRIPTION: Inialize given PDU's header with given values, reset length of the PDU
 *	to initial.
 *
 *  INPUT:
 *	sig:	A signature string, ASCIZ
 *	pdu:	A Prototocol Data Unit
 *	u_csr:	A command/status register field
 *	u_seq:	PDU's sequence field
 *
 *  OUTPUT:
 *	NONE
 *
 *   RETURN:
 *	condition code
 */
inline static int	avproto_hset	(
	void		*pdup,
	unsigned char	*sig,
	unsigned	u_csr,
	unsigned	u_seq
			)
{
AVPROTO_PDU	*pdu = (AVPROTO_PDU *) pdup;

	memset(&pdu->r_hdr, 0, sizeof(AVPROTO_HDR));
	strncpy(pdu->r_hdr.magic, sig, sizeof(pdu->r_hdr.magic));

	pdu->r_hdr.u_csr = htobe32(u_csr);
	pdu->r_hdr.u_seq = htobe32(u_seq);

	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: Get information from the PDU's header.
 *
 *  INPUT:
 *	pdu:	A Prototocol Data Unit
 *	sig:	A signature string, ASCIZ
 *
 *  OUTPUT:
 *	u_len:	A length of the PDU's payload
 *	u_csr:	A command/status register field
 *	u_seq:	PDU's sequence field
 *
 *   RETURN:
 *	condition code
 */
inline static int	avproto_hget	(
	void		*pdup,
	unsigned char	*sig,
	unsigned	*u_len,
	unsigned	*u_csr,
	unsigned	*u_seq
			)
{
int	len;
AVPROTO_PDU	*pdu = (AVPROTO_PDU *) pdup;

	*u_csr = STS$K_ERROR;

	if ( (len = strlen(sig)) > (sizeof (pdu->r_hdr.magic)) )
		return	STS$K_ERROR;

	if ( strncmp(pdu->r_hdr.magic, sig, sizeof (pdu->r_hdr.magic)) )
		return	STS$K_ERROR;

	*u_len = be32toh(pdu->r_hdr.u_len);
	*u_csr = be32toh(pdu->r_hdr.u_csr);
	*u_seq = be32toh(pdu->r_hdr.u_seq);

	return	STS$K_SUCCESS;
}


#ifdef __cplusplus
	}
#endif

#endif	/* #ifndef	__AVPROTO$DEF__	*/
