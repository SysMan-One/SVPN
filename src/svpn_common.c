#define	__MODULE__	"SVPNUTILS"


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

#include	<endian.h>
#include	"svpn_defs.h"

extern	int	g_trace;


/*
 *  DESCRIPTION: Encapsulate data into the TLV container in the given buffer
 *
 *  INPUT:
 *	a_buf:		buffer to accept TLV
 *	a_bufsz:	size of the buffer
 *	a_v_tag:	Tag Id of the value (application specific)
 *	a_v_type:	See TAG$K_* constants
 *	a_val:		An address of the value to be encapsulated into the TLV
 *	a_valsz:	Actual size of the value, optional for fixed size 'a_val'
 *
 *  OUTPUT:
 *	a_adjlen:	A length of the whole TLV container
 *
 *   RETURN:
 *	condition code, STS$K_* constants
 */
int	tlv_put (
		void	*a_buf,
	unsigned	a_bufsz,
	unsigned	a_v_tag,
	unsigned	a_v_type,
	const void	*a_val,
	unsigned	a_valsz,
		int	*a_adjlen
		)
{
SVPN_TLV *l_ptlv = (SVPN_TLV *) a_buf;

	/* Check free space in the buffer */
	if ( a_bufsz < (*a_adjlen = (sizeof(SVPN_TLV) + a_valsz)) )
		return	$LOG(STS$K_ERROR, "No free space for tag=%d, type=%d, len=%d", a_v_tag, a_v_type, a_valsz);

	l_ptlv->tag = (unsigned char ) tlv_encode_tag (a_v_type, a_v_tag);
	l_ptlv->len = (unsigned char ) a_valsz;

	switch ( a_v_type )
		{
		case	SVPN$K_WORD:	/* 16 bits */
			{
			unsigned short *vptr = (unsigned short *) l_ptlv->b_val;

			*vptr = 0;
			memcpy(vptr, a_val, l_ptlv->len);
			*(vptr) = htobe16(*vptr);
			break;
			}

		case	SVPN$K_LONG:	/* 32 bits */
			{
			unsigned *vptr = (unsigned *) l_ptlv->b_val;

			*vptr = 0UL;
			memcpy(vptr, a_val, l_ptlv->len);
			*(vptr) = htobe32(*vptr);

			break;
			}

		case	SVPN$K_QUAD:	/* 64 bits */
			{
			unsigned long long *vptr = (unsigned long long *) l_ptlv->b_val;

			*vptr = 0ULL;
			memcpy(vptr, a_val, l_ptlv->len);
			*(vptr) = htobe64(*vptr);

			break;
			}

		default:
			memcpy(l_ptlv->b_val, a_val, l_ptlv->len);

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
 *	a_v_tag:	Tag Id of the value (application specific)
 *	a_val:	An address of the buffer to accept value
 *	a_valsz:	A size of the buffer
 *
 *  OUTPUT:
 *	a_v_type:	See TAG$K_* constants
 *	a_valsz:	Actual size of the value, optional
 *
 *   RETURN:
 *	condition code
 */
int	tlv_get (
		const void	*a_buf,
			int	a_bufsz,
		 unsigned	a_v_tag,
		 unsigned	*a_v_type,
			void	*a_val,
			int	*a_valsz
		 )
{
int	l_status, l_len = 0, l_pos = 0;
SVPN_TLV *l_ptlv = (SVPN_TLV *) a_buf;
unsigned char l_v_len = 0, l_v_tag = 0, l_v_type = 0;


	l_ptlv = (SVPN_TLV *) a_buf;
	l_pos = 0;

	/* Find TLVs with a given Tag Id */
	for ( l_status = STS$K_WARN; l_pos < a_bufsz; )
		{
		l_v_len = l_ptlv->len;

		tlv_decode_tag (l_ptlv->tag, &l_v_type, &l_v_tag);

		/* Adjust context */
		l_pos += sizeof(SVPN_TLV) + l_v_len;

		if ( l_status = (a_v_tag == l_v_tag) )
			break;

		/* Jump to next TLV */
		l_ptlv = (SVPN_TLV *) (((char *) l_ptlv) + sizeof(SVPN_TLV) + l_v_len);
		}

	/* Not found ? */
	if ( !(1 & l_status) )
		return	l_status;

	/* Check that size of destination buffer is enough */
	if ( a_valsz && (*a_valsz) < l_v_len )
		return	STS$K_ERROR;

	/* Convert and extract value according the type */
	*a_v_type = l_v_type;


	switch ( *a_v_type )
		{
		case	SVPN$K_WORD:	/* 16 bits */
			*((unsigned short *) a_val) = be16toh(l_ptlv->w_val[0]);
			l_len  = sizeof(unsigned short);

			break;

		case	SVPN$K_LONG:	/* 32 bits */
			*((unsigned  *) a_val) = be32toh(l_ptlv->l_val[0]);
			l_len  = sizeof(unsigned);

			break;

		case	SVPN$K_QUAD:	/* 64 bits */
			*((unsigned long long *) a_val) = be64toh(l_ptlv->q_val[0]);
			l_len  = sizeof(unsigned long long);

			break;

		default:
			memcpy(a_val, l_ptlv->b_val, l_v_len);

			l_len = l_v_len;

			break;
		}

	if ( a_valsz )
		*a_valsz = l_len;

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
		const void	*a_buf,
		unsigned	 a_bufsz
			)
{
SVPN_TLV *l_ptlv;
char	l_hexbuf1[512], l_hexbuf2[512];
void	*l_pchar = (void *) a_buf , *l_pend;
unsigned l_count;


	/* Get size of the PDU's area */
	l_pend  = l_pchar + a_bufsz;

	for ( l_pchar = l_ptlv = (void *) a_buf, l_count = 0; l_pchar < l_pend ; l_count++ )
		{
		__util$bin2hex (l_ptlv, l_hexbuf1, sizeof(SVPN_TLV));
		__util$bin2hex (l_ptlv->b_val, l_hexbuf2, l_ptlv->len);

		$LOG(STS$K_INFO, "[%04.4d] TLV [tag=%02x, len=%02d] 0x%s:0x%s", l_count, l_ptlv->tag, l_ptlv->len, l_hexbuf1, l_hexbuf2);

		l_pchar	+= sizeof(SVPN_TLV) + l_ptlv->len;
		l_ptlv	 = (SVPN_TLV *) l_pchar;
		}
}




int	tlv_get_items	(
		const void	*buf,
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
			$LOG(STS$K_WARN, "No attribute with Tag Id %#x has been found", item->code);
			continue;
			}

		if  ( item->retlen )
			*item->retlen = len;

		i++;
		}

	return	(i ? STS$K_SUCCESS : STS$K_WARN);
}
