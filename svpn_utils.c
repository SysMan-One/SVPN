#define	__MODULE__	"SVPNUTILS"

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
	#pragma	GCC diagnostic ignored	"-Wmissing-braces"
#endif

/*++
**
**  FACILITY:  StarLet VPN - cross-platform VPN, light weight, high performance
**
**  DESCRIPTION: This is a main contains common C code is supposed to be used in the server and client parts of the StarLet VPN service.
**
**  AUTHORS: Ruslan R. (The BadAss SysMan) Laishev
**
**  CREATION DATE:  23-AUG-2019
**
**  MODIFICATION HISTORY:
**
**--
*/

#include	"svpn_defs.h"

extern	int	g_trace;


/*
 *  DESCRIPTION: Encapsulate data into the TLV container in the given buffer
 *
 *  INPUT:
 *	buf:	buffer to accept TLV
 *	bufsz:	size of the buffer
 *	v_tag:	Tag Id of the value (application specific)
 *	v_type:	See TAG$K_* constants
 *	val:	An address of the value to be encapsulated into the TLV
 *	valsz:	Actual size of the value, optional for fixed size 'val'
 *
 *  OUTPUT:
 *	adjlen:	A length of the whole TLV container
 *
 *   RETURN:
 *	condition code, STS$K_* constants
 */
int	tlv_put (
	void *		buf,
	unsigned	bufsz,
	unsigned	v_tag,
	unsigned	v_type,
	void	*	val,
	unsigned	valsz,
	unsigned *	adjlen
		)
{
unsigned len = 0;
SVPN_TLV *ptlv = (SVPN_TLV *) buf;

	/* Check free space in the buffer */
	if ( bufsz < (*adjlen = (sizeof(SVPN_TLV) + valsz)) )
		return	$LOG(STS$K_ERROR, "No free space for tag=%d, type=%d, len=%d", v_tag, v_type, valsz);

	ptlv->tag = (unsigned char ) v_tag;
	ptlv->len = (unsigned char ) valsz;

	switch ( v_type )
		{
		case	SVPN$K_WORD:	/* 16 bits */
			{
			unsigned short *vptr = (unsigned short *) ptlv->b_val;

			*vptr = 0;
			memcpy(vptr, val, ptlv->len);
			*(vptr) = htobe16(*vptr);
			break;
			}

		case	SVPN$K_LONG:	/* 32 bits */
			{
			unsigned *vptr = (unsigned *) ptlv->b_val;

			*vptr = 0UL;
			memcpy(vptr, val, ptlv->len);
			*(vptr) = htobe32(*vptr);

			break;
			}

		case	SVPN$K_QUAD:	/* 64 bits */
			{
			unsigned long long *vptr = (unsigned long long *) ptlv->b_val;

			*vptr = 0ULL;
			memcpy(vptr, val, ptlv->len);
			*(vptr) = htobe64(*vptr);

			break;
			}

		default:
			memcpy(ptlv->b_val, val, ptlv->len);

			break;
		}


	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: Find TLV in with specified TAG the PDU from begin of the TLV areas.
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
int	tlv_get (
	void		*buf,
	int		bufsz,
	unsigned	v_tag,
	unsigned	*v_type,
	void	*	val,
	unsigned *	valsz
		)
{
int status, len = 0, pos = 0;
SVPN_TLV *ptlv = (SVPN_TLV *) buf;
unsigned l_len = 0, l_tag = 0, l_type = 0;


	ptlv = (SVPN_TLV *) buf;
	pos = 0;

	/* Find TLVs with a given Tag Id */
	for ( status = STS$K_WARN; pos < bufsz; )
		{
		l_len = ptlv->len;
		l_tag = ptlv->tag;

		/* Adjust context */
		pos += sizeof(SVPN_TLV) + l_len;

		if ( status = (v_tag == l_tag) )
			break;

		/* Jump to next TLV */
		ptlv = (SVPN_TLV *) (((char *) ptlv) + sizeof(SVPN_TLV) + l_len);
		}

	/* Not found ? */
	if ( !(1 & status) )
		return	status;

	/* Check that size of destination buffer is enough */
	if ( valsz && (*valsz) < l_len )
		return	STS$K_ERROR;

	/* Convert and extract value according the type */
	*v_type = l_type;


	switch ( *v_type )
		{
		case	SVPN$K_WORD:	/* 16 bits */
			*((unsigned short *) val) = be16toh(ptlv->w_val[0]);
			len  = sizeof(unsigned short);

			break;

		case	SVPN$K_LONG:	/* 32 bits */
			*((unsigned  *) val) = be32toh(ptlv->l_val[0]);
			len  = sizeof(unsigned);

			break;

		case	SVPN$K_QUAD:	/* 64 bits */
			*((unsigned long long *) val) = be64toh(ptlv->q_val[0]);
			len  = sizeof(unsigned long long);

			break;

		default:
			memcpy(val, ptlv->b_val, l_len);

			len = l_len;

			break;
		}

	if ( valsz )
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
void	tlv_dump	(
		void	*buf,
		int	 bufsz
			)
{
SVPN_TLV *ptlv;
char	hexbuf1[512], hexbuf2[512];
void	*pchar = buf, *pend;
unsigned count;


	/* Get size of the PDU's area */
	pend  = pchar + bufsz;

	for ( pchar = ptlv = buf, count = 0; pchar < pend ; count++ )
		{
		__util$bin2hex (ptlv, hexbuf1, sizeof(SVPN_TLV));
		__util$bin2hex (ptlv->b_val, hexbuf2, ptlv->len);

		$LOG(STS$K_INFO, "[%04.4d] TLV [tag=%02x, len=%02d] 0x%s:0x%s", count, ptlv->tag, ptlv->len, hexbuf1, hexbuf2);

		pchar	+= sizeof(SVPN_TLV) + ptlv->len;
		ptlv	 = (SVPN_TLV *) pchar;
		}
}




static inline int	tlv_get_items	(
		void		*buf,
		int		bufsz,
		ILE3		*item
			)
{
int	i, l_type = 0, len = 0;

	for ( i = 0; item->code; item++)
		{
		len = item->len;

		if  ( item->retlen )
			*item->retlen = -1;

		if ( !(1 & tlv_get (buf, bufsz, item->code,  &l_type, item->ptr, &item->len)) )
			{
			$IFTRACE(g_trace, "No attribute with Tag Id %#x has been found", item->code);
			continue;
			}

		if  ( item->retlen )
			*item->retlen = len;

		i++;
		}

	return	(i ? STS$K_SUCCESS : STS$K_WARN);
}






