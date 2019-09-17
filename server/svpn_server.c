#define	__MODULE__	"SVPNSRV"
#define	__IDENT__	"X.00-01"
#define	__REV__		"0.0.01"

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
	#pragma	GCC diagnostic ignored	"-Wmissing-braces"
#endif


/*++
**
**  FACILITY:  StarLet VPN - cross-platform VPN, light weight, high performance
**
**  DESCRIPTION: This is a main module, implement server functionality.
**	Runs as standalone process, accept client's connection request, check authentication,
**	create logical link for data transfers from/to client.
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
**  CREATION DATE:  20-AUG-2019
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
#include	<linux/limits.h>
#include	<stdatomic.h>

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
static const char magic [SVPN$SZ_MAGIC] = {SVPN$T_MAGIC};
static const unsigned long long *magic64 = (unsigned long long *) &magic;

static	int	g_exit_flag = 0, 	/* Global flag 'all must to be stop'	*/
	g_state = SVPN$K_STATECTL,	/* Initial state for SVPN-Server	*/
	g_trace = 1,			/* A flag to produce extensible logging	*/
	g_enc = SVPN$K_ENC_NONE,	/* Encryption mode, default is none	*/
	g_threads = 3,			/* A size of the worker crew threads	*/
	g_udp_sd = -1,
	g_tun_fd = -1,
	g_mss = 0,			/* MTU for datagram			*/
	g_mtu = 0,			/* MSS for TCP/SYN			*/
	g_seq = 1;			/* A global sequence number		*/

static	atomic_ullong g_input_count = 0;/* Should be increment by receiving from UDP */


static const struct timespec g_locktmo = {5, 0};/* A timeout for thread's wait lock	*/
ASC	g_tun = {$ASCINI("tunX:")},	/* OS specific TUN device name		*/
	g_logfspec = {0}, g_confspec = {0},
	g_bind = {0}, g_cliname = {0}, g_auth = {0},
	g_network = {$ASCINI("192.168.1.0/24")}, g_cliaddr = {$ASCINI("192.168.1.2")}, g_locaddr = {$ASCINI("192.168.1.1")},
	g_timers = {$ASCINI("7, 300, 13, 15")},
	g_climsg = {0}, g_linkup = {0}, g_linkdown = {0};


struct in_addr g_ia_network = {0}, g_ia_local = {0}, g_ia_cliaddr = {0} , g_netmask = {-1};

struct sockaddr_in g_server_sk = {.sin_family = AF_INET}, g_client_sk = {.sin_family = AF_INET};

char	g_key[SVPN$SZ_DIGEST];

					/* Structure to keep timers information */
typedef	struct __svpn_timers__	{

	struct timespec	t_io,		/* General network I/O timeout	*/
			t_idle,		/* Close tunnel on non-activity	*/
			t_ping,		/* Send "ping" every <t_ping> seconds,	*/
					/* ... wait "pong" from client for <t_ping> seconds	*/

			t_max;		/* Seconds, total limit of time for established tunnel */

} SVPN_TIMERS;

static	SVPN_TIMERS	g_timers_set = { {7, 0}, {300, 0}, {13, 0}, {15, 0}};


					/* PTHREAD's stuff is supposed to be used to control worker's
					 * crew threads
					 */
static	pthread_mutex_t crew_mtx = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	crea_cond = PTHREAD_COND_INITIALIZER;



typedef struct	__svpn_stat
	{
	atomic_ullong
		btunrd,
		btunwr,
		bnetrd,
		bnetwr;

	atomic_ullong
		ptunrd,
		ptunwr,
		pnetrd,
		pnetwr;

} SVPN_STAT;
SVPN_STAT	g_stat = {0};

const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&g_confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("trace"),	&g_trace, 0,		OPTS$K_OPT},
	{$ASCINI("bind"),	&g_bind, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("logfile"),	&g_logfspec, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("devtun"),	&g_tun, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("cliname"),	&g_cliname, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("cliaddr"),	&g_cliaddr, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("climsg"),	&g_climsg, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("locaddr"),	&g_locaddr, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("auth"),	&g_auth, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("network"),	&g_network, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("timers"),	&g_timers, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("encryption"),	&g_enc,	0,		OPTS$K_INT},
	{$ASCINI("threads"),	&g_threads,	0,	OPTS$K_INT},
	{$ASCINI("linkup"),	&g_linkup, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("linkdown"),	&g_linkdown, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("MTU"),	&g_mtu,	0,		OPTS$K_INT},
	{$ASCINI("MSS"),	&g_mss,	0,		OPTS$K_INT},

	OPTS_NULL
};


int	exec_script	(
		ASC	*script
		)
{
int	status;
char	cmd[NAME_MAX], ia[32];

	if ( !$ASCLEN(script) )	/* Nothing to do */
		return	STS$K_SUCCESS;

	sprintf(cmd, "%.*s %s:%d", $ASC(script),
		inet_ntop(AF_INET, &g_client_sk.sin_addr, ia, sizeof(ia)),
		ntohs(g_client_sk.sin_port));

	$IFTRACE(g_trace, "Executing %s ...", cmd);

	if ( status = system(cmd) )
		return $LOG(STS$K_ERROR, "system(%s)->%d, errno=%d", cmd, status, errno);

	return	STS$K_SUCCESS;
}


static	int	config_process	(void)
{
int	status = STS$K_SUCCESS;
char	*cp, *saveptr = NULL, *endptr = NULL, ia [ 32 ], mask [ 32];

	/* /TIMERS*/
	$ASCLEN(&g_timers) = __util$uncomment ($ASCPTR(&g_timers), $ASCLEN(&g_timers), '!');
	$ASCLEN(&g_timers) = __util$collapse ($ASCPTR(&g_timers), $ASCLEN(&g_timers));

	if ( $ASCLEN(&g_timers) )
		{
		if ( cp = strtok_r( $ASCPTR(&g_timers), ",", &saveptr) )
			{
			status = strtoul(cp, &endptr, 0);
			g_timers_set.t_io.tv_sec = status;
			}

		if ( cp = strtok_r( $ASCPTR(&g_timers), ",", &saveptr) )
			{
			status = strtoul(cp, &endptr, 0);
			g_timers_set.t_idle.tv_sec = status;
			}

		if ( cp = strtok_r( NULL, ",", &saveptr) )
			{
			status = strtoul(cp, &endptr, 0);
			g_timers_set.t_ping.tv_sec = status;
			}

		if ( cp = strtok_r( NULL, ",", &saveptr) )
			{
			status = strtoul(cp, &endptr, 0);
			g_timers_set.t_max.tv_sec = status;
			}
		}

	sscanf($ASCPTR(&g_network), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_network) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_network));

	sscanf($ASCPTR(&g_cliaddr), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_cliaddr) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_cliaddr));

	sscanf($ASCPTR(&g_locaddr), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_local) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_locaddr));

	return	STS$K_SUCCESS;
}



static int	udp_init(
		int	*sd
			)
{
int	status;
char	ia [32] = {0}, pn [32]={0};
unsigned short npn = 0;
socklen_t slen = sizeof(struct sockaddr);

	g_server_sk.sin_port = htons(SVPN$K_DEFPORT);

	if ( sscanf($ASCPTR(&g_bind), "%32[^:\n]:%8[0-9]", ia, pn) )
		{
		if (  (npn = atoi(pn)) )
			g_server_sk.sin_port = htons(npn);

		if ( 0 > (status = inet_pton(AF_INET, ia, &g_server_sk.sin_addr)) )
				return	$LOG(STS$K_ERROR, "inet_pton(%s)->%d, errno=%d", ia, status, errno);
		}
	else	return	$LOG(STS$K_ERROR, "Illegal or illformed IP:Port (%.*s)", $ASC(&g_bind));

	inet_ntop(AF_INET, &g_server_sk.sin_addr, ia, slen);

	$LOG(STS$K_INFO, "Initialize listener on : %s:%d", ia, ntohs(g_server_sk.sin_port));

	g_server_sk.sin_family = AF_INET;

	if ( 0 > (*sd = socket(AF_INET, SOCK_DGRAM, 0)) )
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);

	/* avoid EADDRINUSE error on bind() */
#ifdef	SO_REUSEADDR
	if( 0 > setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one))  )
		$LOG(STS$K_WARN, "setsockopt(%d, SO_REUSEADDR), errno=%d", *sd, errno);
#endif	/* SO_REUSEADDR */


#ifdef	SO_REUSEPORT
	if( 0 > setsockopt(*sd, SOL_SOCKET, SO_REUSEPORT, (char *)&one, sizeof(one))  )
		$LOG(STS$K_WARN, "setsockopt(%d, SO_REUSEPORT), errno=%d", *sd, errno);
#endif	/* SO_REUSEADDR */


	if ( 0 > bind(*sd, (struct sockaddr*) &g_server_sk, slen) )
		{
		close(*sd);
		return	$LOG(STS$K_FATAL, "bind(%d, %s:%d), errno=%d", *sd, ia, ntohs(g_server_sk.sin_port), errno);
		}


	return	$LOG(STS$K_SUCCESS, "[#%d]UDP socket is initialized %s:%d", *sd, ia, ntohs(g_server_sk.sin_port));
}




static inline int	set_tun_state	(
		int	up_down
		)
{
struct ifreq ifr = {0};
static int	sd = -1;

	if ( sd < 0 )
		{
		if ( 0 > (sd = socket(AF_INET, SOCK_DGRAM, 0)) )
			return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);
		}

	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	/* DOWN the TUN/TAP device */
	if( ioctl(sd, SIOCGIFFLAGS, &ifr) )
		$LOG(STS$K_ERROR, "ioctl(%s)->%d", ifr.ifr_name, errno);
	else	{
		if ( up_down )
			ifr.ifr_ifru.ifru_flags |= IFF_UP;
		else	ifr.ifr_ifru.ifru_flags &= (~IFF_UP);

		if( ioctl(sd, SIOCSIFFLAGS, &ifr) )
			$LOG(STS$K_ERROR, "ioctl(%s, SIOCSIFFLAGS)->%d", ifr.ifr_name, errno);
		}

	$IFTRACE(g_trace, "set %s to %s", ifr.ifr_name, up_down ? "UP" :  "DOWN");

	return	STS$K_SUCCESS;
}



static	int	tun_init	(
			int	*fd
				)
{
struct ifreq ifr = {0};
int	err, sd = -1;
struct sockaddr_in inaddr = {0};

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	/* Allocate new /devtunX ... */
	if ( 0 > (*fd = open("/dev/net/tun", O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(/dev/net/tun), errno=%d", errno);

	if ( err = ioctl(*fd, TUNSETIFF, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
		}

	/* Make this device persisten ... */
	if( err = ioctl(*fd, TUNSETPERSIST, 1) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETPERSIST)->%d, errno=%d", err, errno);
		}

	/* Set initial state of the TUN - DOWN ... */
	if ( 0 > (sd = socket(AF_INET, SOCK_DGRAM, 0)) )
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);

	if( err = ioctl(sd, SIOCGIFFLAGS, &ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(%s, SIOCGIFFLAGS)->%d, errno=%d", ifr.ifr_name, err,  errno);
		}


	ifr.ifr_ifru.ifru_flags &= (~IFF_UP);

	if ( err = ioctl(sd, SIOCSIFFLAGS, &ifr) )
		{
		close(*fd);
		$LOG(STS$K_ERROR, "ioctl(SIOCSIFFLAGS)->%d", err, errno);
		}


	/* Assign IP address ... */
	inaddr.sin_addr = g_ia_local;
	inaddr.sin_family = AF_INET;

	memcpy(&ifr.ifr_addr, &inaddr, sizeof(struct sockaddr));

	if ( err = ioctl(sd, SIOCSIFADDR, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(SIOCSIFADDR)->%d, errno=%d", err, errno);
		}

	return	STS$K_SUCCESS;
}



static	int	tun_open	(
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



/*
 *   DESCRIPTION: process has been received PONG request.
 *
 *   INPUT:
 *
 *	bufp:	A buffer with the PONG's PDU
 *	buflen:	A size of the PDU
 *
 *   IMPLICITE OUTPUT
 */
static int	process_pong	(
				void	*buf,
				int	 buflen
				)
{
int	status, len = 0, v_type = 0, seq = 0;
SVPN_PDU *pdu = (SVPN_PDU *) buf;
struct	timespec  now ={0};
	/*
	 * Extract SEQUENCE attribute
	 */
	len = sizeof(seq);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_SEQ, &v_type, &seq, &len))) )
		$LOG(STS$K_WARN, "No attribute %#x", g_udp_sd, SVPN$K_TAG_SEQ);

	len = sizeof(now);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_TIME, &v_type, &now, &len))) )
		$LOG(STS$K_WARN, "No attribute %#x", g_udp_sd, SVPN$K_TAG_TIME);

	return	STS$K_SUCCESS;
}



/*
 *   DESCRIPTION: Main I/O processing routine, waiting for establishing signaling/data channel , start then
 *	I/O, handling signaling packets
 */
static int	worker	(void)
{
int	rc, td = -1, slen = sizeof(struct sockaddr_in);
struct pollfd pfd[] = {{g_udp_sd, POLLIN, 0 }, {0, POLLIN, 0}};
struct	sockaddr_in rsock = {0};
char	buf [SVPN$SZ_IOBUF];
SVPN_PDU *pdu = (SVPN_PDU *) buf;
struct	timespec now = {0}, etime = {0}, delta = {13, 0};

	$LOG(STS$K_INFO, "Starting ...");

	/* Open channel to TUN device */
	if ( !(1 & (rc = tun_open(&td))) )
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error allocating TUN device");

	/* We suppose to be use poll() on the TUN and UDP channels to performs
	 * I/O asyncronously
	 */
	pfd[1].fd = td;

	$LOG(STS$K_INFO, "[#%d-#%d]Main loop ...", td, g_udp_sd);

	while  ( !g_exit_flag )
		{
		/*
		 *  We performs working only is signaling/data channel has been established,
		 * so we should check that g_state == SVPN$K_STATETUN, in any other case we hibernate execution until
		 * signal.
		 */

		if ( g_state != SVPN$K_STATETUN )
			{
			if ( rc = clock_gettime(CLOCK_MONOTONIC, &now) )
				g_exit_flag = $LOG(STS$K_ERROR, "[#%d]clock_gettime()->%d, errno=%d", td, rc, errno);

			__util$add_time(&now, &delta, &etime);

			pthread_mutex_lock(&crew_mtx);
			rc = pthread_cond_timedwait(&crea_cond, &crew_mtx, &etime);
			pthread_mutex_unlock(&crew_mtx);

			if ( rc && (rc != ETIMEDOUT) )
				{
				g_exit_flag = $LOG(STS$K_ERROR, "[#%d]pthread_cond_timedwait()->%d, errno=%d", td, rc, errno);
				break;
				}


			if ( g_state != SVPN$K_STATETUN )
				continue;

			$IFTRACE(g_trace, "[#%d]Got wake-up signal, unsleep worker !", td);
			}



		/* Wait Input events from TUN or UDP device ... */
#ifdef WIN32
		if( 0 >  (rc = WSAPoll(&pfd, 2, timespec2msec (delta))) && (__ba_errno__ != WSAEINTR) )
#else
		if( 0 >  (rc = poll(pfd, 2, timespec2msec (&g_timers_set.t_io))) && (__ba_errno__ != EINTR) )
#endif // WIN32
			return	$LOG(STS$K_ERROR, "[#%d-#%d]poll()->%d, errno=%d", td, g_udp_sd, rc, __ba_errno__);


		if ( !rc )	/* Nothing to do */
			continue;

#ifdef WIN32
		if ( (rc < 0) && (__ba_errno__ == WSAEINTR) )
#else
		if ( (rc < 0) && (__ba_errno__ == EINTR) )
#endif
			{
			$LOG(STS$K_WARN, "[#%d-#%d]poll()->%d, errno=%d", td, g_udp_sd, rc, __ba_errno__);
			continue;
			}



		if ( pfd[0].revents & (~POLLIN) || pfd[1].revents & (~POLLIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					td, g_udp_sd, rc, pfd[0].revents, pfd[1].revents, __ba_errno__);

		/* Retrieve data from UDP socket -> send to TUN device	*/
		slen = sizeof(struct sockaddr_in);
		if ( (pfd[0].revents & POLLIN) && (0 < (rc = recvfrom(g_udp_sd, buf, sizeof(buf), 0, &rsock, &slen))) )
			{
			/* Check sender IP, ignore unrelated packets ... */
			if ( g_client_sk.sin_addr.s_addr != rsock.sin_addr.s_addr )
				continue;

			atomic_fetch_add(&g_stat.bnetrd, rc);
			atomic_fetch_add(&g_stat.pnetrd, 1);

			/* Is it's control packet begined with the magic prefix  ? */
			if ( pdu->magic64 == *magic64 )
				{
				$LOG(STS$K_INFO, "Got control packet, req=%d, %d octets", pdu->req, rc);

				switch (pdu->req)
					{
					case	SVPN$K_REQ_PONG:
						process_pong(buf, rc);
						atomic_fetch_add(&g_input_count, 1);	/* Increment inputs count !*/
						break;

					case	SVPN$K_REQ_LOGOUT:
						$LOG(STS$K_INFO, "Close tunnel on LOGOUT request");
						    g_state = SVPN$K_STATEOFF;
						   break;

					default:
						g_state = SVPN$K_STATEOFF;
						$LOG(STS$K_ERROR, "Close tunnel on control sequence");
					}

				/* Skip rest of processing */
				continue;
				}


			atomic_fetch_add(&g_input_count, 1);	/* Increment inputs count !*/

			if ( g_enc != SVPN$K_ENC_NONE )
				decode(g_enc, buf, rc, g_key, sizeof(g_key));

			$DUMPHEX(buf, rc);

			if ( rc != write(td, buf, rc) )
				$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on TUN device, write(%d octets), errno=%d", td, g_udp_sd, rc, __ba_errno__);

			atomic_fetch_add(&g_stat.btunwr, rc);
			atomic_fetch_add(&g_stat.ptunwr, 1);
			}
		else
#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= rc) && (errno != EINPROGRESS) )
#endif
			{
			$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					td, g_udp_sd, rc, pfd[0].revents, pfd[1].revents, __ba_errno__);
			break;
			}


		/* Retrieve data from TUN device -> send to UDP socket */
		if ( (pfd[1].revents & POLLIN) && (rc = read (td, buf, sizeof(buf))) )
			{
			slen = sizeof(struct sockaddr_in);

			atomic_fetch_add(&g_stat.btunrd, rc);
			atomic_fetch_add(&g_stat.ptunrd, 1);


			if ( g_enc != SVPN$K_ENC_NONE )
				encode(g_enc, buf, rc, g_key, sizeof(g_key));

			if ( rc != sendto(g_udp_sd, buf, rc, 0, &g_client_sk, slen) )
				$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on UDP socket, sendto(%d octets), errno=%d", td, g_udp_sd, rc, errno);

			atomic_fetch_add(&g_stat.btunwr, rc);
			atomic_fetch_add(&g_stat.ptunwr, 1);
			}
		else
#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= rc) && (errno != EINPROGRESS) )
#endif
			$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					td, g_udp_sd, rc, pfd[0].revents, pfd[1].revents, __ba_errno__);
		}


	return	$LOG(STS$K_INFO, "Terminated");
}



static inline	void	hmac_gen	(
			void	*dst,
			int	 dstsz,
				...
				)
{
void	*src;
int	srclen;
SHA1Context	sha = {0};
va_list ap;

	SHA1Reset(&sha);	/* Compute HASH: PDU header (w/o digest field!) + PDU's payload + <username>:<password> */

	va_start (ap, dstsz);

	while ( src = va_arg(ap, char *) )
		{
		srclen	= va_arg(ap, int);

		SHA1Input(&sha, src, srclen);
		}
	va_end (ap);

	SHA1Result(&sha);
	memcpy(dst, sha.Message_Digest, $MIN(dstsz, sizeof(sha.Message_Digest)));
}


static inline	int	hmac_check	(
			void	*dst,
			int	 dstsz,
				...
				)
{
void	*src;
int	srclen;
SHA1Context	sha = {0};
va_list ap;

	SHA1Reset(&sha);	/* Compute HASH: PDU header (w/o digest field!) + PDU's payload + <username>:<password> */

	va_start (ap, dstsz);

	while ( src = va_arg(ap, char *) )
		{
		srclen	= va_arg(ap, int);

		SHA1Input(&sha, src, srclen);
		}
	va_end (ap);

	SHA1Result(&sha);
	return	!memcmp(dst, sha.Message_Digest, $MIN(dstsz, sizeof(sha.Message_Digest)));
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
int	status, bufsz, adjlen = 0, buflen = 0, v_type = 0, ulen = 0, plen = 0;
struct pollfd pfd = {g_udp_sd, POLLIN, 0 };
char buf[SVPN$SZ_IOBUF], salt[SVPN$SZ_SALT], *bufp, sfrom[64] = {0}, user[SVPN$SZ_USER], pass[SVPN$SZ_PASS];
SVPN_PDU *pdu = (SVPN_PDU *) buf;
struct sockaddr_in from = {0};
char	digest[SVPN$SZ_DIGEST];
SHA1Context	sha = {0};

	/* Accept LOGIN request from any IP ... */
	from.sin_family = AF_INET;
	from.sin_addr.s_addr = INADDR_ANY;


	/* Wait for LOGIN from <USER> request ... */
	$IFTRACE(g_trace, "[#%d]Wait for LOGIN from remote client ...", g_udp_sd);

	if ( !(1 & recv_pkt (g_udp_sd, buf, sizeof(buf), &g_timers_set.t_max, &from, &buflen)) )
		return	$LOG(STS$K_WARN, "[#%d]No LOGIN from remote client ...", g_udp_sd);

	inet_ntop(AF_INET, &from.sin_addr, sfrom, sizeof(sfrom));
	$IFTRACE(g_trace, "[#%d]Got request code %#x, from %s:%d, %d octets", g_udp_sd, pdu->req, sfrom, ntohs(from.sin_port), buflen);


	/* Check length and magic prefix of the packet, just drop unrelated packets */
	if ( (buflen < SVPN$SZ_PDUHDR) && (memcmp(pdu->magic, SVPN$T_MAGIC,  SVPN$SZ_MAGIC)) )
		return	$LOG(STS$K_ERROR, "[#%d]Drop request code %#x, from %s:%d, %d octets", g_udp_sd, pdu->req, buflen);

	if ( pdu->proto != SVPN$K_PROTO_V1  )
		return	$LOG(STS$K_ERROR, "[#%d]Unsupported protocol version %d", g_udp_sd, pdu->proto);

	if ( pdu->req != SVPN$K_REQ_LOGIN )
		return	$LOG(STS$K_ERROR, "[#%d]Ignored unhandled request from %s:%d, code=%#x", g_udp_sd, sfrom, ntohs(from.sin_port), pdu->req);

	/* Check  HMAC*/
	if ( !(1 & hmac_check(pdu->digest, SVPN$SZ_DIGEST,
			pdu, SVPN$SZ_HASHED, pdu->data, buflen - SVPN$SZ_PDUHDR, $ASCPTR(&g_auth), $ASCLEN(&g_auth),
				NULL /* End-of-arguments marger !*/)) )
		return	$LOG(STS$K_ERROR, "[#%d]Hash checking error", g_udp_sd);

	ulen = sizeof(user);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_USER, &v_type, user, &ulen)) )
		return	$LOG(STS$K_ERROR, "[#%d]No USERNAME in request", g_udp_sd);

	$IFTRACE(g_trace, "[#%d]Got LOGIN from  %.*s@%s:%d, %d octets", g_udp_sd,
		 ulen, user, sfrom, ntohs(from.sin_port), buflen);


	/* So, authenticaion was successfull, now we can form client's option list and send ACCEPT;
	 *	form PDU with the options list ...
	 */
	bufp = pdu->data;
	bufsz = sizeof(buf) - (buflen = SVPN$SZ_PDUHDR);
	pdu->req = SVPN$K_REQ_ACCEPT;


	/* Add configuration options for remote SVPN instance ... */
	if ( $ASCLEN(&g_cliname) )
		{
		if ( !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_NAME, SVPN$K_BBLOCK, $ASCPTR(&g_cliname), $ASCLEN(&g_cliname), &adjlen))) )
			return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);
		buflen += adjlen;
		bufsz -= adjlen;
		}

	if ( $ASCLEN(&g_climsg) )
		{
		if (  !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_MSG, SVPN$K_BBLOCK, $ASCPTR(&g_climsg), $ASCLEN(&g_climsg), &adjlen))) )
			return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);

		buflen += adjlen;
		bufsz -= adjlen;
		}

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_NET, SVPN$K_IP, &g_ia_network, sizeof(struct in_addr), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_NETMASK, SVPN$K_IP, &g_netmask, sizeof(struct in_addr), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_CLIADDR, SVPN$K_IP, &g_ia_cliaddr, sizeof(struct in_addr), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_ENC, SVPN$K_LONG, &g_enc, sizeof(g_enc), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_KEEPALIVE, SVPN$K_LONG, &g_timers_set.t_ping, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_IDLE, SVPN$K_LONG, &g_timers_set.t_idle, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TOTAL, SVPN$K_LONG, &g_timers_set.t_max, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;


	tlv_dump(pdu->data, buflen - SVPN$SZ_PDUHDR);

	/* Generate  HMAC */
	hmac_gen(pdu->digest, SVPN$SZ_DIGEST,
			pdu, SVPN$SZ_HASHED, pdu->data, buflen - SVPN$SZ_PDUHDR, $ASCPTR(&g_auth), $ASCLEN(&g_auth),
				NULL /* End-of-arguments marger !*/);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, &from)) )
		return	$LOG(STS$K_ERROR, "Error send ACCEPT to %s:$d", sfrom, ntohs(from.sin_port));

	$IFTRACE(g_trace, "[#%d]Sent ACCEPT to  %.*s@%s:%d, %d octets", g_udp_sd,
		 ulen, user, sfrom, ntohs(from.sin_port), buflen);

	/* Store client IP for future use */
	g_client_sk = from;

	return	STS$K_SUCCESS;
}




/*
 *   DESCRIPTION: prepare and send PING request with attributes: current time and sequence number.
 *	Be advised that we don't sign the packet.
 *
 *   INPUT:
 *	sd:	UDP socket descriptor
 *	to:	A remote client socket
 *
 *   IMPLICITE OUTPUT
 */
static int	process_ping	(
				int	 sd,
		struct	sockaddr_in	*to
				)
{
int	status, bufsz, adjlen = 0, buflen = 0, v_type = 0, ulen = 0, plen = 0;
char buf[SVPN$SZ_IOBUF], *bufp;
SVPN_PDU *pdu = (SVPN_PDU *) buf;
SHA1Context	sha = {0};
struct timespec now;

	g_seq++;

	/* Prepare PING request ... */
	pdu->magic64 = *magic64;
	pdu->req = SVPN$K_REQ_PING;
	pdu->proto = SVPN$K_PROTO_V1;

	bufp = pdu->data;
	bufsz = sizeof(buf) - (buflen = SVPN$SZ_PDUHDR);

	/*
	 * We should add current time and sequence number to performs out-of-sequence checking and
	 * computing RTT
	 */
	clock_gettime(CLOCK_MONOTONIC, &now);

	if ( !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TIME, SVPN$K_BBLOCK, &now, sizeof(now), &adjlen))) )
		return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);
	buflen += adjlen;
	bufsz -= adjlen;

	if ( !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_SEQ, SVPN$K_LONG, &g_seq, sizeof(g_seq), &adjlen))) )
		return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_dump(pdu->data, buflen - SVPN$SZ_PDUHDR);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, to)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send PING #%#x", g_udp_sd, g_seq);

	$IFTRACE(g_trace, "[#%d]Sent PING #%#x", g_udp_sd, g_seq);

	return	STS$K_SUCCESS;
}




/*
 *   DESCRIPTION:
 *
 *   INPUT:
 *	NONE
 *
 *   OUTPUT:
 *	NONE
 */

int	main	(int argc, char **argv)
{
int	status, idle_count;
pthread_t	tid;
SVPN_STAT	l_stat = {0};

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

	/* Open channel to TUN device */
	if ( !(1 & (status = tun_init(&g_tun_fd))) )
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error allocating TUN device");

	close(g_tun_fd);


	/* Initialize UDP socket */
	if ( !(1 & udp_init (&g_udp_sd)) )
		return	$LOG(STS$K_ERROR, "Aborted");


	/* Just for fun */
	init_sig_handler ();

	/* Generate session key ... */
	hmac_gen(g_key, sizeof(g_key), $ASCPTR(&g_auth), $ASCLEN(&g_auth), NULL);

	/* Create crew workers */
	for ( int i = 0; i < g_threads; i++ )
		{
		if ( status = pthread_create(&tid, NULL, worker, NULL) )
			return	$LOG(STS$K_FATAL, "Cannot start worker thread, pthread_create()->%d, errno=%d", status, errno);
		}


	/**/
	for ( idle_count = 0; !g_exit_flag; )
		{
		if ( g_state == SVPN$K_STATECTL )
			{
			if ( 1 & control () )
				{
				g_state = SVPN$K_STATEON;
				$LOG(STS$K_INFO, "State is ON");

				set_tun_state(1);	/* UP the tunX */
				}
			else	continue;
			}


		if ( g_state == SVPN$K_STATEON )	/* Client/user has been authenticated so we can start workers crew
							 * to performs works on data tunneling
							 */
			{
			idle_count = 0;

			exec_script(&g_linkup);

			g_state = SVPN$K_STATETUN;
			$LOG(STS$K_INFO, "State is TUNNELING");

			/* Send signal to the workers ... */
			pthread_mutex_unlock (&crew_mtx);
			status = pthread_cond_broadcast (&crea_cond);
			pthread_mutex_unlock (&crew_mtx);
			}


		if ( g_state == SVPN$K_STATEOFF )	/* I/O workers should be hibernated, call external script,
							 * switch our stet into the "wait for initial control requests"
							 */
			{
			set_tun_state(0);	/* Down the tunX */

			exec_script(&g_linkdown);

			g_state = SVPN$K_STATECTL;
			$LOG(STS$K_INFO, "State is CONTROL");

			continue;
			}


		if ( g_state == SVPN$K_STATETUN )
			{
			/* Check that we need to send PING request to performs that data channel is alive */
			if ( !atomic_load(&g_input_count) )
				{
				if ( (++idle_count) > 3 )
					{
					$LOG(STS$K_ERROR, "Zero activity has been detected, close data channel");
					g_state = SVPN$K_STATEOFF;
					continue;
					}
				else	{
					$IFTRACE(g_trace, "No inputs from remote SVPN client, idle count is %d", idle_count);
					process_ping(g_udp_sd, &g_client_sk);
					}
				}
			else	{
				$IFTRACE(g_trace, "Inputs counter is %d", g_input_count);
				idle_count = 0;
				}

			atomic_store(&g_input_count, 0); /* Reset inputs counter */
			}


		/* Just hibernate for some interval to reduce consuming CPU ... */
		status = 5;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32

		$IFTRACE(g_trace, "TUN RD: %llu packets, %llu octets, WR: %llu packets, %llu octets", g_stat.ptunrd, g_stat.btunrd, g_stat.ptunwr, g_stat.btunwr);
		$IFTRACE(g_trace, "UDP RD: %llu packets, %llu octets, WR: %llu packets, %llu octets", g_stat.ptunrd, g_stat.btunrd, g_stat.ptunwr, g_stat.btunwr);
		}

	/* Get out !*/
	$LOG(STS$K_INFO, "Exiting with exit_flag=%d!", g_exit_flag);

	return	STS$K_SUCCESS;
}
