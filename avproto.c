#define	__MODULE__	"AVPROTO"
#define	__IDENT__	"X.94-07"

#ifdef	__GNUC__	/* We don't interesting in the some warnings */

	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
#endif


/*
**++
**
**  FACILITY:  AVProto - Attribute/Value Pair (Tag Length Value) based protocol
**
**  ABSTRACT: Carring data incapsulated in to the AVP microcontainers as payload of the protocol data unit (PDU)
**
**  DESCRIPTION: This module contains data structures and constant definition is supposed to be used
**	in the core AVProto routines as well as in general API routines.
**
**  DESIGN ISSUE:
**	This API - is a set of routines to performs encapsulation data into the TVL containers
**	and extract data.
**
**	See example of using this API at end of this module!
**
**
**  SET OF ROUTINES:
**
**	int	avproto_hset (void *pdu, char *sig, unsigned u_csr, unsigned u_seq);
**		- Initialize PDU with given values, reset PDU's length field to initial state.
**
**
**	int	avproto_hget (void *pdu, char *sig, unsigned *u_len, unsigned *u_csr, unsigned *u_seq);
**		- Retreive values from the PDU
**
**	int	avproto_put  (void *pdu, unsigned short pdusz, unsigned v_tag, unsigned v_type, void *val, unsigned valsz);
**		- Add new TLV into the PDU (at end);
**
**	int	avproto_get  (void *pdu, [int *context], unsigned v_tag, unsigned *v_type, void *val, [unsigned *valsz]);
**		- Retreive TLV from the given PDU
**
**	int	avproto_lookup  (void *pdu, [int *context], unsigned v_tag, unsigned *v_type, void **val, [unsigned *valsz]);
**		- Lookup TLV with specified Tag Id (v_tag), return an address of the value (unconversed !)  in the PDU's area and size.
**
**
**	unsigned short avproto_encode_tag( unsigned short v_type, unsigned short v_tag);
**		- Encaplsulate Tag Id and Value Type into the 16-bits variable;
**
**	unsigned short avproto_decode_tag (unsigned short w_tag, unsigned short	*v_type, unsigned short	*v_tag);
**		- Decode Tag Id and Value Type from the 16-bits opaque;
**
**
**   USAGE:
**		#include	"avproto.h"
**		add avproto.c module into project
**
**  AUTHORS: Ruslan R. (The BadAss Sysman) Laishev
**
**  CREATION DATE:  20-JUL-2018
**
**  MODIFICATION HISTORY:
**
**	 6-FEB-2019	SYS	Some redesigning according changes in the AVP's structure.
**
**	15-FEB-2019	RRL	Redesigned to exclude using bitfields ...
**
**	18-FEB-2019	RRL	Added API routine to lookup functionality.
**
**	22-FEB-2019	RRL	X.94-02 : Added destination buffer checking in the avproto_get();
**				moved avproto_hget()/avproto_hset() to .H;
**				unhardcoded "Z0magic" signature - now it's parameter;
**
**	25-FEB-2019	SYS	X.94-03 : Fixed bug with ptlv pointer computation in the avproto_get(), avproto_lookup()
**
**	26-FEB-2019	SYS	X.94-04 : Recoded to make 'context' parameter is optional in the avproto_get()/avproto_lookup()
**
**	 6-JUN-2019	RRL	X.94-05 : Added zeroing area before copying  attribute value in the avproto_put()
**
**	 2-JUL-2019	RRL	X.94-06 : Parameter 'valsz' of the avproto_put() is optional now for fixed size arguments (WORD, LONGWORD, QUADWORD, UUID)
**
**	29-JUL-2019	RRL	X.94-07 : Redeclared avproto_dump();
**
**
**
**--
*/

#include	<stddef.h>
#include	<ctype.h>
#include	<limits.h>
#include	<stdarg.h>
#include	<string.h>
#include	<endian.h>

#include	"utility_routines.h"
#include	"avproto.h"	/* Constants and data structure definitions */

/*
 *  DESCRIPTION: Encapsulate given data to TLV-container at end of the given PDU,
 *	adjust length of the PDU in the header.
 *
 *  INPUT:
 *	pdu:	A Prototocol Data Unit
 *	pdusz:	A size of the PDU's area in octets
 *	v_tag:	Tag Id of the value (application specific)
 *	v_type:	See TAG$K_* constants
 *	val:	An address of the value to be encapsulated into the TLV
 *	valsz:	Actual size of the value, optional for fixed size 'val'
 *
 *  OUTPUT:
 *	NONE
 *
 *   RETURN:
 *	condition code, STS$K_* constants
 */
int	avproto_put (
	void *		pdup,
	unsigned short	pdusz,
	unsigned	v_tag,
	unsigned	v_type,
	void	*	val,
	unsigned	valsz
		)
{
unsigned len = 0;
AVPROTO_TLV *ptlv;
char	*pchar;
AVPROTO_PDU	*pdu = (AVPROTO_PDU *) pdup;

	pdusz -= sizeof(AVPROTO_HDR);

	/* Get current PDU's payload  size from the header */
	len = be32toh(pdu->r_hdr.u_len);

	/* Compute pointer to "first free byte" of the PDU's area */
	pchar = (char *) pdu->r_tlv;
	pchar += len;

	len = pdusz - len;

	/* Check for free space in the PDU's area */
	if ( (sizeof (AVPROTO_TLV) + valsz) > len )
		return	$LOG(STS$K_ERROR, "No free space for tag=%d, type=%d, len=%d", v_tag, v_type, valsz);

	/* Set TLV pointer to end of the current PDU  */
	ptlv = (AVPROTO_TLV *) (pchar);

	/* Pack Tag type and Tag id into the field */
	ptlv->w_tag = avproto_encode_tag (v_type, v_tag);

	/* Put value into the TLV container */
	switch ( v_type )
		{
		case	TAG$K_WORD:	/* 16 bits */
			{
			unsigned short *vptr = (unsigned short *) ptlv->b_val;

			*vptr = 0;
			memcpy(vptr, val, valsz ? valsz : sizeof( unsigned short));
			*(vptr) = htobe16(*vptr);

			ptlv->w_len = htobe16( len = sizeof(unsigned short) );

			break;
			}

		case	TAG$K_LONGWORD:	/* 32 bits */
			{
			unsigned *vptr = (unsigned *) ptlv->b_val;

			*vptr = 0UL;
			memcpy(vptr, val, valsz ? valsz : sizeof( unsigned));
			*(vptr) = htobe32(*vptr);

			ptlv->w_len = htobe16( len = sizeof(unsigned) );

			break;
			}

		case	TAG$K_QWORD:	/* 64 bits */
			{
			unsigned long long *vptr = (unsigned long long *) ptlv->b_val;

			*vptr = 0ULL;
			memcpy(vptr, val, valsz ? valsz : sizeof( unsigned long long));
			*(vptr) = htobe64(*vptr);

			ptlv->w_len = htobe16( len = sizeof(unsigned long long) );

			break;
			}

		case	TAG$K_UUID:	/* 16 octets  */
			memset(ptlv->b_val, 0, 16);

			memcpy(ptlv->b_val, val, len = $MIN(valsz, 16));
			ptlv->w_len = htobe16( 16 );

			break;

		default:
			memcpy(ptlv->b_val, val, len = valsz);
			ptlv->w_len = htobe16( valsz );

			break;
		}

	/* Adjust PDU's length  */
	pdu->r_hdr.u_len = htobe32(sizeof (AVPROTO_TLV) + len + be32toh(pdu->r_hdr.u_len) );

	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: Find TLV in with specified TAG the PDU from begin of the TLV areas (if contexts is set to -1).
 *
 *  INPUT:
 *	pdu:	A Prototocol Data Unit
 *	ctx:	A private context to be used in consequtive calls, must be -1 at first call
 *	v_tag:	Tag Id of the value (application specific)
 *	val:	An address of the buffer to accept value
 *	valsz:	A size of the buffer
 *
 *  OUTPUT:
 *	v_type:	See TAG$K_* constants
 *	valsz:	Actual size of the value, optional
 *
 *   RETURN:
 *	condition code
 */
int	avproto_get (
		void	*pdup,
	int	*	context,
	unsigned	v_tag,
	unsigned	*v_type,
	void	*	val,
	unsigned *	valsz
		)
{
int status, pdusz = 0, len = 0, pos = 0;
AVPROTO_TLV *ptlv;
unsigned short w_len, l_tag = 0, l_type = 0;
AVPROTO_PDU	*pdu = (AVPROTO_PDU *) pdup;

	/* Get size of the PDU's payload part*/
	pdusz = be32toh(pdu->r_hdr.u_len);

	/* Compute a pointer to first unprocessed TLV */
	if ( context && (*context != -1) )
		ptlv = (AVPROTO_TLV *) (((char *) pdu->r_tlv) + (pos = *context));
	else	{
		ptlv = pdu->r_tlv;
		pos = 0;
		}

	/* Find TLVs with a given Tag Id */
	for ( status = STS$K_WARN; pos < pdusz; )
		{
		avproto_decode_tag (ptlv->w_tag, &l_type, &l_tag);
		w_len = be16toh(ptlv->w_len);

		/* Adjust context */
		pos += sizeof(AVPROTO_TLV) + w_len;

		if ( status = (v_tag == l_tag) )
			break;

		/* Jump to next TLV */
		ptlv = (AVPROTO_TLV *) (((char *) ptlv) + sizeof(AVPROTO_TLV) + w_len);
		}

	if ( context )
		*context = pos;


	/* Not found ? */
	if ( !(1 & status) )
		return	status;

	/* Check that size of destination buffer is enough */
	if ( valsz && (*valsz) < w_len )
		return	STS$K_ERROR;

	/* Convert and extract value according the type */
	*v_type = l_type;


	switch ( *v_type )
		{
		case	TAG$K_WORD:	/* 16 bits */
			*((unsigned short *) val) = be16toh(ptlv->w_val[0]);
			len  = sizeof(unsigned short);

			break;

		case	TAG$K_LONGWORD:	/* 32 bits */
			*((unsigned  *) val) = be32toh(ptlv->u_val[0]);
			len  = sizeof(unsigned);

			break;

		case	TAG$K_QWORD:	/* 64 bits */
			*((unsigned long long *) val) = be64toh(ptlv->q_val[0]);
			len  = sizeof(unsigned long long);

			break;

		case	TAG$K_UUID:	/* 16 octets  */
			len = 16;
			w_len = $MIN(w_len, 16);
			__util$movc5 (&w_len, ptlv->b_val,  0, &len, val);

			break;
		default:
			memcpy(val, ptlv->b_val, w_len);

			len = w_len;

			break;
		}

	if ( valsz )
		*valsz = len;

	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: Lookup TLV in with specified TAG the PDU from begin of the TLV areas (if contexts is set to -1),
 *	return type and address of the TLV's data area.
 *
 *  INPUT:
 *	pdu:	A Prototocol Data Unit
 *	ctx:	A private context to be used in consequtive calls, must be -1 at first call
 *	v_tag:	Tag Id of the value (application specific)
 *
 *  OUTPUT:
 *	v_type:	See TAG$K_* constants
 *	val:	An address of TLV's data block (unconverted !!!)
 *	valsz:	A size of the TLV's data block
 *
 *   RETURN:
 *	condition code
 */
int	avproto_lookup (
	AVPROTO_PDU	*pdu,
	int	*	context,
	unsigned	v_tag,
	unsigned	*v_type,
	void	**	val,
	unsigned *	valsz
		)
{
int status, pdusz = 0, len = 0, pos = 0;
AVPROTO_TLV *ptlv;
unsigned short w_len, l_tag = 0, l_type = 0;

	/* Get size of the PDU's payload part*/
	pdusz = be32toh(pdu->r_hdr.u_len);

	/* Compute a pointer to first unprocessed TLV */
	if ( context && (*context != -1) )
		ptlv = (AVPROTO_TLV *) (((char *) pdu->r_tlv) + (pos = *context));
	else	{
		ptlv = pdu->r_tlv;
		pos = 0;
		}

	/* Find TLVs with a given Tag Id */
	for ( status = STS$K_WARN; pos < pdusz; )
		{
		avproto_decode_tag (ptlv->w_tag, &l_type, &l_tag);
		w_len = be16toh(ptlv->w_len);

		/* Adjust context */
		pos += sizeof(AVPROTO_TLV) + w_len;

		if ( status = (v_tag == l_tag) )
			break;

		/* Jump to next TLV */
		ptlv = (AVPROTO_TLV *) (((char *) pdu) + sizeof(AVPROTO_TLV) + w_len);
		}

	if ( context )
		*context = pos;

	/* Not found ? */
	if ( !(1 & status) )
		return	status;

	*v_type = l_type;
	*val = ptlv->b_val;
	*valsz = len;


	return	STS$K_SUCCESS;
}




/*
 *  DESCRIPTION: Dump PDU
 *
 *  INPUT:
 *	pdu:	A Prototocol Data Unit
 *
 *   RETURN:
 *	condition code
 */
void	avproto_dump	(
		void	*_pdu
			)
{
AVPROTO_TLV *ptlv;
AVPROTO_PDU	*pdu = (AVPROTO_PDU *) _pdu;
char	hexbuf1[512], hexbuf2[512];
void	*pchar = (char *) pdu->r_tlv, *pend;
unsigned pdusz, count;
unsigned short w_len, w_tag, v_type, v_tag;


	/* Get size of the PDU's area */
	pdusz = be32toh(pdu->r_hdr.u_len);
	pend  = pchar + pdusz;

	$LOG(STS$K_INFO, "PDU [len=%d, cmd=%#x, seq=%d]", be32toh(pdu->r_hdr.u_len), be32toh(pdu->r_hdr.u_csr), be32toh(pdu->r_hdr.u_seq));

	for ( pchar = ptlv = pdu->r_tlv, count = 0; pchar < pend ; count++ )
		{
		w_len = be16toh(ptlv->w_len);
		w_tag = avproto_decode_tag (ptlv->w_tag, &v_type, &v_tag);

		__util$bin2hex (ptlv, hexbuf1, sizeof(AVPROTO_TLV));
		__util$bin2hex (ptlv->b_val, hexbuf2, w_len);
		$LOG(STS$K_INFO, "[%04.4d] TLV [tag=%04x(id=%04x, type=%04x), len=%02d] 0x%s:0x%s",
		     count, w_tag, v_tag, v_type, w_len, hexbuf1, hexbuf2);

		pchar	+= sizeof(AVPROTO_TLV) + w_len;
		ptlv	 = (AVPROTO_TLV *) pchar;
		}
}


//#define	__AVPROTO_MAIN__	1
#if	__AVPROTO_MAIN__	/* At development/debug time	*/



const char VCLOUD$K_PROTOSIG [] = "Z0magic";


/* A set of definitions for toy client-server interoperations	*/
enum	{
	VCLOUD$K_CMD_LOGIN,
	VCLOUD$K_CMD_LOGOUT,
	VCLOUD$K_CMD_GET
};

enum	{
	VCLOUD$K_STS_ERROR,
	VCLOUD$K_STS_SUCCESS
};


/* An example set of tag's id for demonstration purpose */
enum	{
	VCLOUD$K_TAG_RESULT = 1,
	VCLOUD$K_TAG_COMP_ID,	/* Computer Id	*/
	VCLOUD$K_TAG_DISK_ID,	/* Disk Id	*/
	VCLOUD$K_TAG_KEY = 4,	/* Key Block */
	VCLOUD$K_TAG_UNAME,
	VCLOUD$K_TAG_PASS,
	VCLOUD$K_TAG_MSG
};

char	pdubuf[8192];	/* This buffer will keep the PDU is ahsred between
			  toy client and server */

AVPROTO_PDU *pdu = (AVPROTO_PDU *) pdubuf;


int	__client	(void)
{
unsigned char	username[] = "Ruslan (BadAss SysMan) Laishev",
		password[] = "My cool password string";

unsigned short	w_val = 0x1234;
unsigned 	u_val = 0x1234abcd;
long long	q_val = 0x1234abcddeadbeef;

	/* Initialize header of the PDU */
	avproto_hset (pdu, VCLOUD$K_PROTOSIG, /* Command */ VCLOUD$K_CMD_LOGIN, /* Sequence */ 17);

	/* Encapsulate some data into the PDU */
	avproto_put (pdu, sizeof(pdubuf),	/* PDU'address and maximum size of the PDU's area */
		     VCLOUD$K_TAG_UNAME,	/* 'Tag Id' constant				*/
		     0,				/* Default 'Tag Type' is binary data block	*/
		     username,			/* Address of the 'Value', length ...		*/
		     sizeof(username) - 1);

	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_PASS, 0, password, sizeof(password) - 1);
	avproto_put (pdu, sizeof(pdubuf), TAG$K_WORD, TAG$K_WORD, &w_val, sizeof(w_val) );
	avproto_put (pdu, sizeof(pdubuf), TAG$K_LONGWORD, TAG$K_LONGWORD, &u_val, sizeof(u_val) );
	avproto_put (pdu, sizeof(pdubuf), TAG$K_QWORD, TAG$K_QWORD, &q_val, sizeof(q_val) );

	return	STS$K_SUCCESS;
}

int	__server	(void)
{
unsigned context = -1, u_len, u_csr, u_seq, v_type, mlen;
char	uname[128], pass [128];
unsigned short ulen, plen, w_val = 0;
unsigned u_val = 0;
unsigned long long q_val = 0;
char	welcome [] = "This is an asnwer to request: cmd/seq=%u/%u",
	msg [ 512 ];


	/* Get header's values of the PDU */
	if ( !(1 & avproto_hget (pdu, VCLOUD$K_PROTOSIG,  &u_len, &u_csr, &u_seq)) )
		return	$LOG(STS$K_ERROR, "Illformed or corrupted PDU");

	/* Retreive attributes from the request */
	ulen = sizeof(uname);
	avproto_get (pdu, &context, VCLOUD$K_TAG_UNAME, &v_type, uname, &ulen);
	$TRACE("uname=[0:%d]='%.*s'", ulen , ulen, uname);

	plen = sizeof(pass);
	avproto_get (pdu, &context, VCLOUD$K_TAG_PASS, &v_type, pass, &plen);
	$TRACE("pass=[0:%d]='%.*s'", plen , plen, pass);

	avproto_get (pdu, &context, /* Is used as Tag Id */ TAG$K_WORD, &v_type, &w_val, 0 );
	$TRACE("w_val=%d/%#x", w_val, w_val);

	avproto_get (pdu, &context, /* Is used as Tag Id */ TAG$K_LONGWORD, &v_type, &u_val, 0 );
	$TRACE("u_val=%d/%#x", u_val, u_val);

	avproto_get (pdu, &context, /* Is used as Tag Id */ TAG$K_QWORD, &v_type, &q_val, 0 );
	$TRACE("q_val=%llu/%#llx", q_val, q_val);

	/* Prepare answer to the request */
	avproto_hset (pdu, VCLOUD$K_PROTOSIG, /* Status */ VCLOUD$K_STS_SUCCESS, /* Sequence */ u_seq);

	/* Encapsulate text message into the PDU */
	mlen = sprintf(msg, welcome, u_csr, u_seq);
	avproto_put (pdu, sizeof(pdubuf),	/* PDU'address and maximum size of the PDU's area */
		     VCLOUD$K_TAG_MSG,		/* 'Tag Id' constant				*/
		     0,				/* Default 'Tag Type' is binary data block	*/
		     msg,			/* Address of the 'Value', length ...		*/
		     mlen);

	return	STS$K_SUCCESS;

}

#if	0
void	main	(void)
{

	/* Form a request ... */
	__client();

	$DUMPHEX(pdu, be32toh(pdu->r_hdr.u_len));
	avproto_dump(pdu);


	/* Process request from client - form the answer */
	__server();

	$DUMPHEX(pdu, be32toh(pdu->r_hdr.u_len));
	avproto_dump(pdu);

}
#endif




#if	1
#include	<stdio.h>
#include	<stdlib.h>
#include	<stdbool.h>
#include	<string.h>
#include	<unistd.h>
#include	<netinet/ip.h>
#include	<arpa/inet.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<poll.h>
#include	<openssl/ssl.h>
#include	<openssl/err.h>
#include	<uuid/uuid.h>

#include	"vcloud_common.h"

const char	clntcert_fname [] = "vCloud-client.crt",
		clntkey_fname [] = "vCloud-client.key",
		cacert_fname [] =  "rootCA.crt";

#define	VCLOUD$K_IOTMO	13

/**
 *   DESCRIPTION: Read n bytes from the network socket, wait if not all data has been get
 *		but no more then 13 seconds.
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	ssl:	SSL' session context
 *	buf:	A buffer to accept data
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	buf:	Received data
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
inline	static int __recv_n
		(
		int	sd,
		SSL	*ssl,
	unsigned char	*buf,
		int	bufsz
		)
{
int	status, restbytes = bufsz, tmo = VCLOUD$K_IOTMO;
struct pollfd pfd = {sd, POLLIN, 0};

	for ( restbytes = bufsz; (tmo--) && restbytes; )
		{
		if ( !SSL_pending(ssl) ) /* Is the internal SSL' buffer empty ?*/
			{
			if( 0 >  (status = poll(&pfd, 1, 1000)) && (errno != EINTR) )
				return	$LOG(STS$K_ERROR, "[#%d] poll/select() -> %d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
			else if ( (status < 0) && (errno == EINTR) )
				{
				$LOG(STS$K_WARN, "[#%d] poll/select() -> %d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
				continue;
				}

			if ( pfd.revents & (~POLLIN) )	/* Unexpected events ?!			*/
				return	$LOG(STS$K_FATAL, "[#%d] poll() -> %d, .revents=%08x(%08x), errno=%d",
						sd, status, pfd.revents, pfd.events, errno);

			if ( !(pfd.revents & POLLIN) )	/* Non-interesting event ?		*/
				continue;
			}

		/* Do we reach an end of I/O time ?	*/
		if ( tmo <= 0 )
			{
			$LOG(STS$K_ERROR, "[#%d] Timeout (%d seconds) has been reached", sd, VCLOUD$K_IOTMO);
			break;
			}

		/* Retrieve data from socket buffer	*/
		if ( restbytes == (status = SSL_read(ssl, buf, restbytes)) )
			{
			$DUMPHEX(buf, bufsz);
			return	STS$K_SUCCESS; /* Bingo! We has been received a requested amount of data */
			}

		if ( 0 >= status )
			{
			$LOG(STS$K_ERROR, "[#%d] recv(%d octets) -> %d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, errno);
			break;
			}

		/* Advance buffer pointer and decrease expected byte counter */
		restbytes -= status;
		buf	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not get requested %d octets in %d seconds, rest %d octets", sd, bufsz, tmo, restbytes);
}


/**
 *   DESCRIPTION: Write n bytes to the network socket, wait if not all data has been get
 *		but no more then 13 seconds;
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	ssl:	SSL' session context
 *	buf:	A buffer with data to be sent
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	NONE
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
inline	static int __xmit_n
		(
		int	sd,
		SSL	*ssl,
	unsigned char	*buf,
		int	bufsz
		)
{
int	status, restbytes = bufsz, tmo = VCLOUD$K_IOTMO;
struct pollfd pfd = {sd, POLLOUT, 0};

	$DUMPHEX(buf, bufsz);

	for ( restbytes = bufsz; (tmo--) && restbytes; )
		{
		if( 0 >  (status = poll(&pfd, 1, 1000)) && (errno != EINTR) )
			return	$LOG(STS$K_ERROR, "[#%d] poll/select() -> %d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
		else if ( (status < 0) && (errno == EINTR) )
			{
			$LOG(STS$K_WARN, "[#%d] poll/select() -> %d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
			continue;
			}

		if ( pfd.revents & (~POLLOUT) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_FATAL, "[#%d] poll() -> %d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, errno);

		if ( !(pfd.revents & POLLOUT) )	/* No interesting event			*/
			continue;

		/* Send data to socket buffer	*/
		if ( restbytes == (status = SSL_write(ssl, buf, restbytes)) )
			return	STS$K_SUCCESS; /* Bingo! We has been sent a requested amount of data */

		if ( 0 >= status )
			{
			$LOG(STS$K_ERROR, "[#%d] send(%d octets) -> %d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, errno);
			break;
			}

		/* Advance buffer pointer and decrease to be sent byte counter */
		restbytes -= status;
		buf	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not put requested %d octets in %d seconds, rest %d octets", sd, bufsz, VCLOUD$K_IOTMO, restbytes);
}



int	pdu_recv	(
		int	sd,
		SSL	*ssl,
		void	*pdubuf,
	unsigned	 pdusz
			)

{
unsigned status, u_len, u_csr, u_seq;

	if ( pdusz < sizeof(AVPROTO_HDR) )
		return	$LOG(STS$K_ERROR, "No free space to read PDU's header");

	/* Get PDU header */
	if ( !(1 & (status = __recv_n (sd, ssl, pdubuf, sizeof(AVPROTO_HDR)))) )
	     return	$LOG(STS$K_ERROR, "Error receiving PDU's header");

	/* Check magic, extract PDU's Length, CSR, Sequence ... */
	if ( !(avproto_hget (pdubuf, VCLOUD$K_PROTOSIG, &u_len, &u_csr, &u_seq)) )
		return	$LOG(STS$K_ERROR, "Maillformed or invalid PDU's header");

	if ( pdusz < (sizeof(AVPROTO_HDR) + u_len) )
		return	$LOG(STS$K_ERROR, "No free space to read PDU's body (len=%d, csr=%d, seq=%d)", u_len, u_csr, u_seq);

	/* Read rest of the PDU */
	if ( !(1 & (status = __recv_n (sd, ssl, pdubuf + sizeof(AVPROTO_HDR), u_len))) )
		return	$LOG(STS$K_ERROR, "Error reading PDU's body (len=%d, csr=%d, seq=%d)", u_len, u_csr, u_seq);

	return	STS$K_SUCCESS;
}


int	pdu_xmit	(
		int	sd,
		SSL	*ssl,
		void	*pdubuf
			)

{
unsigned status, u_len, u_csr, u_seq;

	/* Check magic, extract PDU's Length, CSR, Sequence ... */
	if ( !(avproto_hget (pdubuf, VCLOUD$K_PROTOSIG,  &u_len, &u_csr, &u_seq)) )
		return	$LOG(STS$K_ERROR, "Maillformed or invalid PDU's header");

	/* Send the PDU */
	if ( !(1 & (status = __xmit_n (sd, ssl, pdubuf, sizeof(AVPROTO_HDR) + u_len))) )
		return	$LOG(STS$K_ERROR, "Error transmitting PDU's (len=%d, csr=%d, seq=%d)", u_len, u_csr, u_seq);

	return	STS$K_SUCCESS;
}


/**
 * @brief init_ssl - Initialize SSL internal data and contexts, load certificate.
 *
 * @param __ctx	: a local specific part of the SSL context
 *
 * @return	- condition code, see STS$K_* constats
 */
int	init_ssl (SSL_CTX ** __ctx )
{
const SSL_METHOD *method = NULL;

	$TRACE("Initialize client SSL context ...");

	/* General initialization ...	*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	method = SSLv23_client_method();

	if ( (*__ctx = SSL_CTX_new(method)) )
		{
		$TRACE("Loading certificate (-s) from %s file ...", clntcert_fname);

		if ( 0 < SSL_CTX_use_certificate_file(*__ctx, clntcert_fname, SSL_FILETYPE_PEM)  )
			if ( 0 < SSL_CTX_use_PrivateKey_file(*__ctx, clntkey_fname, SSL_FILETYPE_PEM) )
				{
				if ( SSL_CTX_check_private_key(*__ctx) )
					{
					/* Load trusted CA. */
					if ( SSL_CTX_load_verify_locations(*__ctx, cacert_fname, NULL) )
						{
						SSL_CTX_set_verify(*__ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
						SSL_CTX_set_verify_depth(*__ctx, 4);
						return	STS$K_SUCCESS;
						}
					}
				else	$LOG(STS$K_FATAL, "Private key  does not match the public certificate");
				}
		}

	ERR_print_errors_fp(stderr);

	return	$LOG(STS$K_FATAL, "Error initialization of SSL stuff");
}


#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int	kdepo_get_key	(
	struct sockaddr_in *	rsock,
		uuid_t		cuu,
		Z0_DRIVE_KEY *	dk
			)
{
int	sd = 0, status = 0, i, v_type = 0, valsz;
SSL *ssl = NULL;
SSL_CTX *ssl_ctx;
Z0_DRIVE_KEY *pdk;

	if ( !(1 & init_ssl(&ssl_ctx)) )
		return	$LOG(STS$K_FATAL, "Error initialization client SSL context");

	$LOG(STS$K_INFO, "Connecting to %s:%d", inet_ntoa(rsock->sin_addr), ntohs(rsock->sin_port));

	if ( 0 > (sd = socket(AF_INET, SOCK_STREAM, 0)) )
		return	$LOG(STS$K_ERROR, "socket() -> %d, errno = %d", sd, errno);

	if ( 0 > (status = connect(sd, (struct sockaddr *) rsock, sizeof(struct sockaddr))) )
		return	$LOG(STS$K_ERROR, "connect (%s:%d) -> %d, errno = %d",
			     inet_ntoa(rsock->sin_addr), ntohs(rsock->sin_port), status, errno);


	if ( 0 > (status = setsockopt( sd, IPPROTO_TCP, TCP_NODELAY, (void *)&sd, sizeof(sd))) )
		$LOG(STS$K_ERROR, "setsockopt()->%d, errno=%d", status, errno);

	/* We have etsablished the TCP-connection, so try to establishing SSL session */
	ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, sd);

	if ( 0 > SSL_connect(ssl) )
		{
		ERR_print_errors_fp(stderr);
		goto end;
		}

	/* Initialize header of the PDU */
	avproto_hset (pdu, VCLOUD$K_PROTOSIG, /* Command */ VCLOUD$K_CMD_GET, /* Sequence */ 17);

	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_COMP_ID, TAG$K_UUID, cuu, sizeof(uuid_t) );

	for (i = 0, pdk = dk; (i < DRIVES_MAX); i++, pdk++ )
		{
		if ( __util$iszero (pdk->disk_id, sizeof(pdk->disk_id)) )
			continue;

		avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DISK_ID, TAG$K_UUID, pdk->disk_id, sizeof(pdk->disk_id) );
		}

	avproto_dump (pdu);

	if ( !(1 & pdu_xmit (sd, ssl, pdu)) )
		$LOG(STS$K_ERROR, "Error sending request to Keys Depo");
	else if ( !(1 & pdu_recv (sd, ssl, pdu, sizeof(pdubuf))) )
		$LOG(STS$K_ERROR, "Error receiving answer from Keys Depo");
	else	{
		avproto_dump (pdu);

		/* Processing answer ... */
		i = 0;

		if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_RESULT, &v_type, &i, NULL))) )
			status = $LOG(STS$K_ERROR, "Answer did not contains result code");

		if ( i != 1 )
			status = $LOG(STS$K_ERROR, "Error processing request, relt code=%#x", i);
		else	{
			valsz = sizeof(Z0_DRIVE_KEY);
			if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_KEY, &v_type, dk, &valsz))) )
				status = $LOG(STS$K_ERROR, "Answer did not contains DK");
			}
		}

end:
	if (ssl)
		{
		SSL_shutdown(ssl);
		SSL_free(ssl);
		}

	if (sd)
		close(sd);

	return	status;
}



int	main	(int argc, char ** argv)
{
int	status, i;
uuid_t	cuu;
Z0_DRIVE_KEY dk[DRIVES_MAX] = {0};
struct sockaddr_in rsock = {0};
char	buf[512];

	/* Convert test data to the binary form */
#if 1
	status =  uuid_parse( "1d75bd4a-0dbf-4d4d-9d5e-e24b29fdf1f7" , cuu);
	status =  uuid_parse( "c245486d-de9c-4abc-bdb1-e07f917e5ad8" , dk[0].disk_id);
	status =  uuid_parse( "368b1e4c-eff9-48d5-a085-0da2013f40ad" , dk[1].disk_id);

	inet_pton(AF_INET, "172.28.5.30", &rsock.sin_addr);
#endif
#if 0
	{
	char	cid [] = {"e62bbc999f7b364395a3b5e55c55adb0"},
		did [] = {"ad030abe877bc946b199f904e57a58d1"};


	__util$hex2bin(cid, &cuu, strlen(cid));
	__util$hex2bin(did, dk[0].disk_id, strlen(dk[0].disk_id));

	}
	inet_pton(AF_INET, "172.28.4.135", &rsock.sin_addr);
#endif

	/* Keys Depo host socket */
	rsock.sin_family = AF_INET;
	rsock.sin_port = htobe16(4343);


	/* Request keys ...*/
	if ( 1 & (status = kdepo_get_key(&rsock, cuu, dk)) )
		{
		/* Dump secret keys to the SYS$OUTPUT - suprize mutafaqa! */
		for (i = 0; i < DRIVES_MAX; i++ )
			{
			__util$bin2hex (dk[i].disk_id, buf, sizeof(dk[i].disk_id));
			$LOG(STS$K_INFO, "Disk Id [%02.2d]=0x%s", i, buf);

			__util$bin2hex (dk[i].key, buf, sizeof(dk[i].key));
			$LOG(STS$K_INFO, "Disk Key[%02.2d]=0x%s", i, buf);
			}
		}

}

#endif



#endif	/* #if	__AVPROTO_MAIN__ */
