#define	__MODULE__	"SVPNCLNT"
#define	__IDENT__	"X.00-00"
#define	__REV__		"0.0.00"

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
	#pragma	GCC diagnostic ignored	"-Wmissing-braces"
#endif


/*++
**
**  FACILITY:  StarLet VPN - cross-platform VPN, light weight, high performance
**
**  DESCRIPTION: This is a main module, implement client functionality.
**	Runs as standalone process, connect to server, performs authentication and establishing
**	logical link for data transfers from/to client.
**
**  ABSTRACT: General logic of interoperation of the StarLet VPN server and client imagine follows:
**
**
**
**           Client                 |   Server               |
**      ----------------------------+------------------------+
**                             Phase I                       |
**                       (CRAM Authentication)               |
**                                  |                        |
**       1.                  HELLO --->                      |
**                                      (generate and store  |
**                                         initial Salt)     |
**       2.                       <--- WELCOME+Salt          |
**                                  |                        |
**       3. LOGIN+User/H(Pass, Salt) --->                    |
**                                  |  (authentication check |
**                                  | form answer, client's  |
**                                  |    attribute list)     |
**                                  |                        |
**                                  |   ( open TUN0:, start  |
**                                  |  (data worker crew )   |
**        4.                      <--- ACCEPT (avlist)       |
**      ----------------------------+------------------------+
**                             Phase II                      |
**                        (data interchange)                 |
**                                                           |
**                           --- data --->                   |
**                           <--- data ---                   |
**                                  |                        |
**                                  | (keep alive checking,  |
**                                  | refresh NAT slots)     |
**                      heartbit  --->                       |
**                                <--- heartbit              |
**      ----------------------------+------------------------+
**
**  USAGE:
**		$ ./BAGENT	[options]
**			/CONFIG=<configuration_file>
**			/TRACE
**			/LOGFILE=<fspec>
**			/TIMERS={<keepalive>, <total>, <iotmo>}
**
**
**
**  AUTHORS: Ruslan R. (The BadAss SysMan) Laishev
**
**  CREATION DATE:  28-AUG-2019
**
**  MODIFICATION HISTORY:
**
**--
*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<time.h>
#include	<inttypes.h>
#include	<signal.h>
#include	"sha1.h"


#ifdef _WIN32
	#pragma once
	#define WIN32_LEAN_AND_MEAN             /* Exclude rarely-used stuff from Windows headers */

#include	<windows.h>
#include	<WinSock2.h>
#include	<fwpmu.h>
#include	<initguid.h>
#include	<fwpmtypes.h>
#include	<iphlpapi.h>
#include	<netioapi.h>
#include	<ws2tcpip.h>
#include	<process.h>

#pragma	comment (lib, "Ws2_32.lib")
#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "Iphlpapi.lib")

#ifndef  __VERSION__
#ifdef _MSC_FULL_VER
#define	 __VERSION__	 "MSC"
#else
#define	 __VERSION__	"N/A"
#endif // _MSC_FULL_VER

#endif // ! __VERSION__

#else
#include	<pthread.h>
#include	<unistd.h>
#include	<netinet/ip.h>
#include	<arpa/inet.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<poll.h>
#include	<sys/ioctl.h>
#include	<net/if.h>
#include	<linux/if.h>
#include	<linux/if_tun.h>

#endif

#define	__FAC__	"SVPN"
#define	__TFAC__ __FAC__ ": "

#ifdef _DEBUG
	#ifndef	__TRACE__
		#define	__TRACE__
	#endif
#endif // DEBUG

#include	"utility_routines.h"
#include	"svpn_defs.h"



#ifdef WIN32
#define	__ba_errno__	WSAGetLastError()
#else
#define	__ba_errno__	errno
#endif // WIN32



#ifdef	WIN32
#if	(_M_X64)
#define	__ARCH__NAME__	"Win64"
#else
#define	__ARCH__NAME__	"Win32"
#endif

#elif  ANDROID
	#if defined(__arm__)
		#if defined(__ARM_ARCH_7A__)
		#if defined(__ARM_NEON__)
			#if defined(__ARM_PCS_VFP)
				#define ABI "armeabi-v7a/NEON (hard-float)"
			#else
				#define ABI "armeabi-v7a/NEON"
			#endif
			#else
			#if defined(__ARM_PCS_VFP)
				#define ABI "armeabi-v7a (hard-float)"
			#else
				#define ABI "armeabi-v7a"
			#endif
		#endif
		#else
			#define ABI "armeabi"
		#endif
	#elif defined(__i386__)
		#define ABI "x86"
	#elif defined(__x86_64__)
		#define ABI "x86_64"
	#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
		#define ABI "mips64"
	#elif defined(__mips__)
		#define ABI "mips"
	#elif defined(__aarch64__)
		#define ABI "arm64-v8a"
	#else
		#define ABI "unknown"
    #endif

    #define __ARCH__NAME__ ABI
#endif


#ifndef __ARCH__NAME__
	#define	__ARCH__NAME__	"VAX-11"
#endif // !__ARCH_NAME__

static const	ASC	__ident__ = {$ASCINI(__IDENT__ "/"  __ARCH__NAME__   "(built at "__DATE__ " " __TIME__ " with CC " __VERSION__ ")")},
	__rev__ = {$ASCINI(__REV__)};


/* Global configuration parameters */
static	const	int slen = sizeof(struct sockaddr), one = 1, off = 0;

static	int	g_exit_flag = 0, 	/* Global flag 'all must to be stop'	*/
	g_state = SVPN$K_STATECTL,	/* Initial state for SVPN-Server	*/
	g_trace = 1,			/* A flag to produce extensible logging	*/
	g_enc = SVPN$K_ENC_NONE,	/* Encryption mode, default is none	*/
	g_threads = 3,			/* A size of the worker crew threads	*/
	g_udp_sd = -1,
	g_tun_sd = -1,
	g_mss = 0,			/* MTU for datagram			*/
	g_mtu = 0;			/* MSS for TCP/SYN			*/


static const struct timespec g_locktmo = {5, 0};/* A timeout for thread's wait lock	*/
ASC	g_tun = {$ASCINI("tun33")},	/* OS specific TUN device name		*/
	g_logfspec = {0}, g_confspec = {0},
	g_auth = {0}, g_user = {0},
	g_timers = {0},
	g_linkup = {0}, g_linkdown = {0},
	g_server = {0};

char	g_salt[SVPN$SZ_SALT];

struct sockaddr_in g_server_sk = {.sin_family = AF_INET};

					/* Structure to keep timers information */
typedef	struct __svpn_timers__	{

	struct timespec	t_io,		/* General network I/O timeout	*/
			t_idle,		/* Close tunnel on non-activity	*/
			t_ping,		/* Send "ping" every <t_ping> seconds,	*/
					/* ... wait "pong" from client for <t_ping> seconds	*/

			t_max;		/* Seconds, total limit of time for established tunnel */

} SVPN_TIMERS;

static	SVPN_TIMERS	g_timers_set = { {7, 0}, {300, 0}, {13, 0}, {-1, 0}};

const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&g_confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("trace"),	&g_trace, 0,		OPTS$K_OPT},
	{$ASCINI("logfile"),	&g_logfspec, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("devtun"),	&g_tun, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("auth"),	&g_auth, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("threads"),	&g_threads,	0,	OPTS$K_INT},
	{$ASCINI("linkup"),	&g_linkup, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("linkdown"),	&g_linkdown, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("server"),	&g_server, ASC$K_SZ,	OPTS$K_STR},

	OPTS_NULL
};


static	int	config_process	(void)
{
int	status = STS$K_SUCCESS;
char	user[SVPN$SZ_USER + 8];

	/* Extract username from the <auth> */
	if ( !sscanf($ASCPTR(&g_auth), "%32[^:\n]", user) )
		$LOG(STS$K_ERROR, "Cannot extract username part from '%.*s'", $ASC(&g_auth));

	__util$str2asc (user, &g_user);

	return	STS$K_SUCCESS;
}



static int	udp_init	(
		int	*sd
			)
{
int	status;
char	ia [32] = {0}, pn [32]={0};
unsigned short npn = 0;
struct  sockaddr_in a = {0};

	if ( sscanf($ASCPTR(&g_server), "%32[^:\n]:%8[0-9]", ia, pn) )
		{
		if (  (npn = atoi(pn)) )
			g_server_sk.sin_port = htons(npn);

		if ( 0 > (status = inet_pton(AF_INET, ia, &g_server_sk.sin_addr)) )
				return	$LOG(STS$K_ERROR, "inet_pton(%s)->%d, errno=%d", ia, status, errno);
		}
	else	return	$LOG(STS$K_ERROR, "Illegal or illformed IP:Port (%.*s)", $ASC(&g_server));

	inet_ntop(AF_INET, &g_server_sk.sin_addr, ia, sizeof(ia));

	$LOG(STS$K_INFO, "Server socket:%s:%d", ia, ntohs(g_server_sk.sin_port));
	$ASCLEN(&g_server) = sprintf ($ASCPTR(&g_server), "%s:%d", ia, ntohs(g_server_sk.sin_port));

	g_server_sk.sin_family = AF_INET;

	if ( 0 > (*sd = socket(AF_INET, SOCK_DGRAM, 0)) )
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);



	status = sizeof(struct sockaddr);
	if ( 0 > (status = getsockname (*sd, &a,  (socklen_t *) &status)) )
		$LOG(STS$K_ERROR, "getsockname(#%d)->%d, errno=%d", sd, status, __ba_errno__);

	inet_ntop(AF_INET, &a.sin_addr, ia, sizeof(ia));

	return	$LOG(STS$K_SUCCESS, "[#%d]UDP socket is initialized %s:%d", *sd, ia, ntohs(a.sin_port));
}


static	int	tun_init	(
			int	*fd
				)
{
struct ifreq ifr = {0};
int	err;

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	if ( 0 > (*fd = open("/dev/net/tun", O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(/dev/net/tun), errno=%d", errno);

	if ( err = ioctl(*fd, TUNSETIFF, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
		}

	return	STS$K_SUCCESS;
}



/*
**  DESCRIPTION: Compute time from timespec to milisecond - input for poll()
**
**  INPUT:
**	src:	source time in timespec format
**
**  OUTPUT: NONE
**
**  RETURN:
**	time in miliseconds
**
*/
inline static int timespec2msec (
		struct timespec	*src
				)
{
	return (src->tv_sec  * 1024) + (src->tv_nsec / 1024);
}

/*
 *   DESCRIPTION: Read specified number of  bytes from the network socket, wait if not all data has been get
 *		but no more then timeout. Optionaly check address of sender.
 *		If from.sin_addr == INADDR_ANY - accept UDP datagram from any source
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer to accept data
 *	bufsz:	A number of bytes to be read
 *	from:	Remote sender socket to check
 *
 *  OUTPUT:
 *	buf:	Received data
 *	retlen:	A length of data has been received to the buffer
 *	from:	Remote sender socket
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
static inline	int recv_pkt
			(
			int	sd,
			void	*buf,
			int	bufsz,
		struct timespec	*delta,
		struct sockaddr_in *from,
			int	*retlen
			)
{
int	status;
#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLIN, 0};
#else
struct pollfd pfd = {sd, POLLIN, 0};
#endif // WIN32

struct timespec	now, etime;
char	*bufp = (char *) buf;\
struct	sockaddr_in rsock = {0};
int	slen = sizeof(struct sockaddr_in);

/* Compute an end of I/O operation time	*/
#ifdef WIN32
	timespec_get(&now, TIME_UTC);
#else
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, __ba_errno__);
#endif

	__util$add_time (&now, delta, &etime);

	while ( !g_exit_flag )
		{
		/* Do we reach the end of I/O time ? */
#ifdef WIN32
		timespec_get(&now, TIME_UTC);
#else
		clock_gettime(CLOCK_REALTIME, &now);
#endif

		if ( 0 < __util$cmp_time(&now, &etime) )
			break;


#ifdef WIN32
		if( 0 >  (status = WSAPoll(&pfd, 1, timespec2msec (delta))) && (__ba_errno__ != WSAEINTR) )
#else
		if( 0 >  (status = poll(&pfd, 1, timespec2msec (delta))) && (__ba_errno__ != EINTR) )
#endif // WIN32
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, errno=%d", sd, status, __ba_errno__);

#ifdef WIN32
		if ( (status < 0) && (__ba_errno__ == WSAEINTR) )
#else
		if ( (status < 0) && (__ba_errno__ == EINTR) )
#endif
			{
			$LOG(STS$K_WARN, "[#%d] poll()->%d, errno=%d", sd, status, __ba_errno__);
			continue;
			}


		if ( pfd.revents & (~POLLIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, __ba_errno__);

		if ( !(pfd.revents & POLLIN) )	/* Non-interesting event ?		*/
			continue;

		/* Retrieve data from socket buffer	*/
		if ( 0 < (status = recvfrom(sd, bufp, bufsz, 0, &rsock, &slen)) )
			{
			/* Optionaly check source address of sender */
			if ( (from->sin_addr.s_addr != INADDR_ANY) && (from->sin_addr.s_addr != rsock.sin_addr.s_addr) )
				continue;

			*retlen = status;
			*from = rsock;
			return	STS$K_SUCCESS; /* Bingo! We has been received a requested amount of data */
			}

#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= status) && (errno != EINPROGRESS) )
#endif
			{
			$LOG(STS$K_ERROR, "[#%d] recv()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, __ba_errno__);
			break;
			}
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not get data from socket in %d msecs", sd, timespec2msec (delta));
}

/*
 *   DESCRIPTION: Write specified number of bytes to the network socket, wait if not all data has been get
 *		but no more then timeout;
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer with data to be sent
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	NONE
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
static inline int	xmit_pkt
			(
			int	sd,
			void	*buf,
			int	bufsz,
		struct sockaddr_in	*to
			)
{
int	status;
#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLOUT, 0};
#else
struct pollfd pfd = {sd, POLLOUT, 0};
#endif // WIN32
struct timespec	now, etime;
char	*bufp = (char *) buf;

	if ( !bufsz )
		return	STS$K_SUCCESS;


	/* Compute an end of I/O operation time	*/
#ifdef WIN32
	timespec_get(&now, TIME_UTC);
#else
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, __ba_errno__);
#endif

	__util$add_time (&now, &g_timers_set.t_idle, &etime);

	while ( !g_exit_flag )
		{
		/* Do we reach the end of I/O time ? */
#ifdef WIN32
		timespec_get(&now, TIME_UTC);
#else
		clock_gettime(CLOCK_REALTIME, &now);
#endif

		if ( 0 < __util$cmp_time(&now, &etime) )
			break;

#ifdef WIN32
		if( 0 >  (status = WSAPoll(&pfd, 1, 1000)) && (__ba_errno__ != WSAEINTR) )
#else
		if( 0 >  (status = poll(&pfd, 1, 1000)) && (__ba_errno__ != EINTR) )
#endif // WIN32
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, errno=%d", sd, status, __ba_errno__);

#ifdef WIN32
		if ( (status < 0) && (__ba_errno__ == WSAEINTR) )
#else
		if ( (status < 0) && (__ba_errno__ == EINTR) )
#endif
			{
			$LOG(STS$K_WARN, "[#%d] poll()->%d, errno=%d", sd, status, __ba_errno__);
			continue;
			}

#ifdef WIN32
		if ( pfd.revents & (~POLLOUT) && (__ba_errno__ != EAGAIN) )	/* Unexpected events ?!			*/
#else
		if ( pfd.revents & (~POLLOUT) && (__ba_errno__ != EAGAIN) )	/* Unexpected events ?!			*/
#endif
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, __ba_errno__);

		if ( !(pfd.revents & POLLOUT) )	/* No interesting event			*/
			continue;

		/* Send data to socket buffer	*/
#ifdef WIN32
		if ( bufsz == (status = send(sd, bufp, bufsz, 0)) )
#else
		if ( bufsz == (status = sendto (sd, bufp, bufsz, MSG_NOSIGNAL, to , slen)) )
#endif
			return	STS$K_SUCCESS; /* Bingo! We has been sent a requested amount of data */


		/* Error !!! */
		$LOG(STS$K_ERROR, "[#%d] send(%d octets)->%d, .revents=%08x(%08x), errno=%d",
					sd, bufsz, status, pfd.revents, pfd.events, errno);
		break;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not send requested %d octets", sd, bufsz);
}

static	void	sig_handler (int signo)
{
	if ( g_exit_flag )
		{
		fprintf(stdout, "Exit flag has been set, exiting ...\n");
		fflush(stdout);
		_exit(signo);
		}
	else if ( (signo == SIGTERM) || (signo == SIGINT) )
		{
	#ifdef WIN32
		fprintf(stdout, "Get the %d/%#x signal, set exit_flag!\n", signo, signo);
	#else
		fprintf(stdout, "Get the %d/%#x (%s) signal, set exit_flag!\n", signo, signo, strsignal(signo));
	#endif // WIN32

		fflush(stdout);
		g_exit_flag = 1;
		return;
		}
	else	{
	#ifdef WIN32
		fprintf(stdout, "Get the %d/%#x signal\n", signo, signo);
	#else
		fprintf(stdout, "Get the %d/%#x (%s) signal\n", signo, signo, strsignal(signo));
	#endif // WIN32
		fflush(stdout);
		}

	_exit(signo);
}

static	void	init_sig_handler(void)
{
const int siglist [] = {SIGTERM, SIGINT, 0 };
int	i;

	for ( i = 0; siglist[i]; i++)
		{
		if ( (signal(siglist[i], sig_handler)) == SIG_ERR )
			$LOG(STS$K_ERROR, "Error establishing handler for signal %d/%#x, error=%d", siglist[i], siglist[i], __ba_errno__);
		}
}





static int	worker	(void)
{
int	status, td = -1;
struct pollfd pfd[] = {{g_udp_sd, POLLIN,0 }, {0, POLLIN, 0}};

	$LOG(STS$K_INFO, "Starting ...");

	/* Open channel to TUN device */
	if ( !(1 & (status = tun_init(&td))) )
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error allocating TUN device");



	/* We suppose to be use poll() on the TUN and UDP channels to performs
	 * I/O asyncronously
	 */
	pfd[1].fd = td;

	$LOG(STS$K_INFO, "[#%d-#%d]Main loop ...", td, g_udp_sd);

	while ( !g_exit_flag )
		{
		status = 3;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32
		}


	return	$LOG(STS$K_INFO, "Terminated");
}



/*
 *   DESCRIPTION: Performs accept and process request from remote client/peer according Phase I
 *	protocol
 *
 *   IMPLICITE INPUT
 *
 *   IMPLICITE OUTPUT
 */
static int	control	(void)
{
int	status, bufsz, adjlen = 0, buflen = 0, retlen = 0, v_type = 0, ulen = 0, plen = 0;
struct pollfd pfd = {g_udp_sd, POLLIN, 0 };
char buf[SVPN$SZ_IOBUF], salt[32], *bufp, user[SVPN$SZ_USER], pass[SVPN$SZ_PASS];
SVPN_PDU *pdu = (SVPN_PDU *) buf;
char	digest[SVPN$SZ_DIGEST];
SHA1Context	sha = {0};

	/* Send HELLO from <USER> request ... */
	memcpy(pdu->magic, SVPN$T_MAZIC, SVPN$SZ_MAZIC);
	pdu->proto = SVPN$K_PROTO_V1;
	pdu->req = SVPN$K_REQ_HELLO;
	buflen = SVPN$SZ_PDUHDR;

	tlv_put (pdu->data, SVPN$SZ_USER, SVPN$K_TAG_USER, SVPN$K_BBLOCK, $ASCPTR(&g_user), $ASCLEN(&g_user), &adjlen);
	buflen += adjlen;

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, &g_server_sk)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send HELLO to %.*s", g_udp_sd, $ASC(&g_server));



	/* Wait for WELCOME + Salt ... */
	$IFTRACE(g_trace, "[#%d]Wait for WELCOME from %.*s (timeout is %d msec) ...", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	if ( !(1 & recv_pkt (g_udp_sd, buf, sizeof(buf), &g_timers_set.t_io, &g_server_sk, &retlen)) )
		return	$LOG(STS$K_WARN, "[#%d]No WELCOME from %.*s in %d msec, cancel session setup", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	/* Check length and magic prefix of the packet, just drop unrelated packets */
	if ( (retlen < SVPN$SZ_PDUHDR) && (memcmp(pdu->magic, SVPN$T_MAZIC,  SVPN$SZ_MAZIC)) )
		return	$LOG(STS$K_ERROR, "[#%d]Drop request code %#x, from %.*s, length=%d octets", g_udp_sd, pdu->req, $ASC(&g_server), retlen);

	if ( pdu->proto != SVPN$K_PROTO_V1  )
		return	$LOG(STS$K_ERROR, "[#%d]Unsupported protocol version=%d", g_udp_sd, pdu->proto);

	if ( pdu->req != SVPN$K_REQ_WELCOME )
		return	$LOG(STS$K_ERROR, "[#%d]Ignored unexpected request from %.*s, code=%#x", g_udp_sd, $ASC(&g_server), pdu->req);

	/* Process WELCOME response from server request: extract Salt  */
	adjlen = SVPN$SZ_SALT;
	if ( !(1 & tlv_get (pdu->data, retlen - SVPN$SZ_PDUHDR, SVPN$K_TAG_SALT, &v_type, g_salt, &adjlen)) )
		return	$LOG(STS$K_ERROR, "[%d]No Salt in request", g_udp_sd);


	/* Prepare & send LOGIN request ... */
	memcpy(pdu->magic, SVPN$T_MAZIC, SVPN$SZ_MAZIC);
	pdu->proto = SVPN$K_PROTO_V1;
	pdu->req = SVPN$K_REQ_LOGIN;
	buflen = SVPN$SZ_PDUHDR;

	SHA1Reset(&sha);	/* Compute HASH: PDU header (w/o digest field!) + PDU's payload + <username>:<password> */
	SHA1Input(&sha, pdu, SVPN$SZ_HASHED);
	SHA1Input(&sha, $ASCPTR(&g_auth), $ASCLEN(&g_auth));
	SHA1Result(&sha);

	memcpy(pdu->digest, sha.Message_Digest, SVPN$SZ_DIGEST);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, &g_server_sk)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send HELLO to %.*s", g_udp_sd, $ASC(&g_server));


	/* Wait for ACCEPT ... */
	$IFTRACE(g_trace, "[#%d]Wait for ACCEPT from %.*s (timeout is %d msec) ...", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	if ( !(1 & recv_pkt (g_udp_sd, buf, sizeof(buf), &g_timers_set.t_io, &g_server_sk, &retlen)) )
		return	$LOG(STS$K_WARN, "[#%d]No ACCEPT from %.*s in %d msec, cancel session setup", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	/* Check length and magic prefix of the packet, just drop unrelated packets */
	if ( (retlen < SVPN$SZ_PDUHDR) && (memcmp(pdu->magic, SVPN$T_MAZIC,  SVPN$SZ_MAZIC)) )
		return	$LOG(STS$K_ERROR, "[#%d]Drop request code %#x, from %.*s, length=%d octets", g_udp_sd, pdu->req, $ASC(&g_server), retlen);

	if ( pdu->proto != SVPN$K_PROTO_V1  )
		return	$LOG(STS$K_ERROR, "[#%d]Unsupported protocol version=%d", g_udp_sd, pdu->proto);

	if ( pdu->req != SVPN$K_REQ_ACCEPT )
		return	$LOG(STS$K_ERROR, "[#%d]Ignored unexpected request from %.*s, code=%#x", g_udp_sd, $ASC(&g_server), pdu->req);

	/* Process ACCEPT  request: compute local hash to compare with the pdu.digest */
	SHA1Reset(&sha);	/* Compute HASH: PDU header (w/o digest field!) + PDU's payload + <username>:<password> */
	SHA1Input(&sha, pdu, SVPN$SZ_HASHED);
	SHA1Input(&sha, pdu->data, retlen - SVPN$SZ_PDUHDR);
	SHA1Input(&sha, $ASCPTR(&g_auth), $ASCLEN(&g_auth));
	SHA1Result(&sha);

	if ( memcmp(sha.Message_Digest, pdu->digest, SVPN$SZ_DIGEST) )
		return	$LOG(STS$K_ERROR, "[%d]Hash checking error", g_udp_sd);

	/* Extract attributes from ACCEPT packet */

	return	$LOG(STS$K_SUCCESS, "Session is establied");
}


/*
 *   DESCRIPTION: A main routine for demonstration using of  BAgent API routines.
 *	Process configuration option from command line and configuration file (if option -config is took place);
 *	initialize single BAgent's instance context by calls of bagen_init();
 *	start processing (thread) by call bagent_start();
 *	do nothing in empty loop ...;
 *	stop processing thread by calling  bagent_stop();
 *
 *   INPUT:
 *	NONE
 *
 *   OUTPUT:
 *	NONE
 */

int	main	(int argc, char **argv)
{
int	status;

pthread_t	tid;

	$LOG(STS$K_INFO, "Rev: " __IDENT__ "/"  __ARCH__NAME__   ", (built  at "__DATE__ " " __TIME__ " with CC " __VERSION__ ")");

	/*
	 * Process command line arguments
	 */
	__util$getparams(argc, argv, optstbl);

	if ( $ASCLEN(&g_logfspec) )
		{
		__util$deflog($ASCPTR(&g_logfspec), NULL);

		$LOG(STS$K_INFO, "Rev: " __IDENT__ "/"  __ARCH__NAME__   ", (built  at "__DATE__ " " __TIME__ " with CC " __VERSION__ ")");
		}

	if ( g_trace )
		__util$showparams(optstbl);

	/* Additionaly parse and validate configuration options  */
	config_process();


	/* Initialize TUN device */
	if ( !(1 & tun_init (&g_tun_sd)) )
		return	$LOG(STS$K_ERROR, "Error initialization of the TUN device. Start aborted.");

	/* Initialize UDP socket */
	if ( !(1 & udp_init (&g_udp_sd)) )
		return	$LOG(STS$K_ERROR, "Error initialization of the UDP socket. Start aborted.");


	/* Just for fun */
	init_sig_handler ();

#if 0
	/* Create crew workers */
	for ( int i = 0; i < g_threads; i++ )
		if ( status = pthread_create(&tid, NULL, worker, NULL) )
			return	$LOG(STS$K_FATAL, "Cannot start worker thread, pthread_create()->%d, errno=%d", status, errno);
#endif

	/**/
	while ( !g_exit_flag )
		{
		if ( g_state == SVPN$K_STATECTL )
			control ();


		status = 3;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32
		}

	/* Get out !*/
	$LOG(STS$K_INFO, "Exiting with exit_flag=%d!", g_exit_flag);
}
