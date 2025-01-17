#define	__MODULE__	"SVPNCLNT"
#define	__IDENT__	"V.01-00"
#define	__REV__		"1.00.0"


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
**	17-SEP-2019	RRL	Now SVPN Client is pthread powered program.
**
**	 8-OCT-2019	RRL	Added version output on "-v" and display usage;
**				added 'logsize' configuration option.
**
**	 9-OCT-2019	RRL	Added handling of the TRACE option from server.
**
**	10-OCT-2019	RRL	Improved diagnostic output.
**
**	30-OCT-2019	RRL	Fixed consuming CPU by incorrect using CLOCK_MONOTONIC for pthread_cond_timewait()
**
**	21-NOV-2019	RRL	X.00-08 : Added assingment of the NETWORK MASK on the TUN device.
**
**	23-NOV-2019	RRL	X.00-09 : Changed default mode for TUN device to TUN
**
**	 3-OCT-2020	RRL	V.01-00 : Added support of unpacking multiple IP-packets from single UDP datagram
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
#include	<stdatomic.h>
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
static const char magic [SVPN$SZ_MAGIC] = {SVPN$T_MAGIC};
static const unsigned long long *magic64 = (unsigned long long *) &magic;

static const uint64_t	g_options = SVPN$K_OPT_AGGR; /* We support aggregation		*/

static	int	g_exit_flag = 0, 	/* Global flag 'all must to be stop'	*/
	g_state = SVPN$K_STATECTL,	/* Initial state for SVPN-Server	*/
	g_trace = 0,			/* A flag to produce extensible logging	*/
	g_enc = SVPN$K_ENC_NONE,	/* Encryption mode, default is none	*/
	g_threads = 1,			/* A size of the worker crew threads	*/
	g_udp_sd = -1,
	g_tun_fd = -1,
	g_tun_sdctl = -1,
	g_mss = 0,			/* MSS for TCP/SYN			*/
	g_mtu = 0,			/* MTU for datagram			*/
	g_logsize = 0,			/* A maximum logfile size in octets	*/
	g_tunflags = IFF_TUN,		/* Default type of the '/dev/net/tun'	*/
	g_run_options,			/* A negotiated set of options		*/
	g_delay = 0;			/* A time to accumulate IP-packets before aggregate */

static	atomic_ullong g_input_count = 0;/* Should be increment by receiving from UDP */


static const struct timespec g_locktmo = {5, 0};/* A timeout for thread's wait lock	*/
ASC	g_tun = {$ASCINI("tun33")},	/* OS specific TUN device name		*/
	g_logfspec = {0}, g_confspec = {0},
	g_auth = {0}, g_user = {0},
	g_timers = {0},
	g_linkup = {0}, g_linkdown = {0},
	g_server = {0}, g_cliname = {0}, g_climsg = {0};

char	g_salt[SVPN$SZ_SALT];
char	g_key[SVPN$SZ_DIGEST];

struct in_addr g_ia_network = {0}, g_ia_cliaddr = {0}, g_ia_netmask = {0};

struct sockaddr_in g_server_sk = {.sin_family = AF_INET};

					/* Structure to keep timers information */
/* Structure to keep timers information */
typedef	struct __svpn_timers__	{

struct timespec	t_io,			/* General network I/O timeout	*/
		t_idle,			/* Close tunnel on non-activity	*/
		t_ping,			/* Send "ping" every <t_ping> seconds,	*/
					/* ... wait "pong" from client for <t_ping> seconds	*/

		t_max;			/* Seconds, total limit of time for established tunnel */
		int	retry;

} SVPN_TIMERS;

static	SVPN_TIMERS	g_timers_set = { {3, 0}, {120, 0}, {3, 0}, {600, 0}, 3};

static	pthread_mutex_t crew_mtx = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	crea_cond = PTHREAD_COND_INITIALIZER;

const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&g_confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("trace"),	&g_trace, 0,		OPTS$K_OPT},
	{$ASCINI("logfile"),	&g_logfspec, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("logsize"),	&g_logsize, 0,		OPTS$K_INT},
	{$ASCINI("devtun"),	&g_tun, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("auth"),	&g_auth, ASC$K_SZ,	OPTS$K_STR},
	//{$ASCINI("threads"),	&g_threads,	0,	OPTS$K_INT},
	{$ASCINI("linkup"),	&g_linkup, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("linkdown"),	&g_linkdown, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("server"),	&g_server, ASC$K_SZ,	OPTS$K_STR},

	OPTS_NULL
};



extern void	tlv_dump (const void *buf, unsigned bufsz);

const char	help [] = { "Usage:\n" \
	"$ %s [<options_list>]\n\n" \
	"\t/CONFIG=<file>    configuration options file path\n" \
	"\t/TRACE            enable extensible diagnostic output\n" \
	"\t/LOGFILE=<file>   a specification of file to accept logging\n" \
	"\t/LOGSIZE=<number> a maximum size of file in octets\n" \
	"\t/LINKUP=<file>    script to be executed on tunnel up\n" \
	"\t/LINKDOWN=<file>  script to be executed on tunnel down\n" \
	"\t/AUTH=<user:pass> username and password pair\n" \
	"\t/SERVER=<ip:port> IP address of name and port pair of remote SVPN server\n" \
	"\n\tExample of usage:\n\t $ %s -config=svpn_client.conf /trace\n" };

int	exec_script	(
		ASC	*script
		)
{
int	status;
char	cmd[1024], ia[32];

	if ( !$ASCLEN(script) )	/* Nothing to do */
		return	STS$K_SUCCESS;

	sprintf(cmd, "%.*s", $ASC(script));

	$IFTRACE(g_trace, "Executing %s ...", cmd);

	if ( status = system(cmd) )
		return $LOG(STS$K_ERROR, "system(%s)->%d, errno=%d", cmd, status, errno);

	return	STS$K_SUCCESS;
}



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

	/* Parse server's IP and port */
	if ( sscanf($ASCPTR(&g_server), "%32[^:\n]:%8[0-9]", ia, pn) )
		{
		if (  (npn = atoi(pn)) )
			g_server_sk.sin_port = htons(npn);

		if ( 0 > (status = inet_pton(AF_INET, ia, &g_server_sk.sin_addr)) )
				return	$LOG(STS$K_ERROR, "inet_pton(%s)->%d, errno=%d", ia, status, errno);
		}
	else	return	$LOG(STS$K_ERROR, "Illegal or illformed IP:Port (%.*s)", $ASC(&g_server));

	/* Convert to internal representative for future use */
	inet_ntop(AF_INET, &g_server_sk.sin_addr, ia, sizeof(ia));

	$LOG(STS$K_INFO, "Server socket:%s:%d", ia, ntohs(g_server_sk.sin_port));
	$ASCLEN(&g_server) = sprintf ($ASCPTR(&g_server), "%s:%d", ia, ntohs(g_server_sk.sin_port));

	g_server_sk.sin_family = AF_INET;


	/* Create UDP socket to be used for communicattion with server */
	if ( 0 > (*sd = socket(AF_INET, SOCK_DGRAM, 0)) )
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);


	/* It looks like that local UDP port will be allocated on first send,
	 * so just send something to somwhere ...
	 */
	sendto(*sd, ia, sizeof(ia), 0, (struct sockaddr *)&a, slen);

	status = sizeof(struct sockaddr);
	if ( 0 > (status = getsockname (*sd, (struct sockaddr *) &a,  (socklen_t *) &status)) )
		$LOG(STS$K_ERROR, "getsockname(#%d)->%d, errno=%d", sd, status, __ba_errno__);

	inet_ntop(AF_INET, &a.sin_addr, ia, sizeof(ia));

	return	$LOG(STS$K_SUCCESS, "[#%d]UDP socket is initialized %s:%d", *sd, ia, ntohs(a.sin_port));
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

	/* UP/OWN the TUN/TAP device */
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

static char tundev_path[512] = {"/dev/tun"};

static	int	tun_init	(
			int	*fd
				)
{
struct ifreq ifr = {0};
int	err, sd = -1;
struct sockaddr_in inaddr = {0};

	if ( access ("/dev/tun", F_OK) )
		{ /* /dev/tun - not found */
		if ( access ("/dev/net/tun", F_OK) )
			return	$LOG(STS$K_ERROR, "Error check paths: /dev/tun or /dev/net/tun");
		else	strcpy(tundev_path, "/dev/net/tun" );
		}

	$IFTRACE(g_trace, "TUN's path: %s", tundev_path);


	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = g_tunflags  /*IFF_TAP*/ | IFF_NO_PI; // | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	/* Allocate new /devtunX ... */
	if ( 0 > (*fd = open(tundev_path, O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(%s), errno=%d", tundev_path, errno);

	if ( err = ioctl(*fd, TUNSETIFF, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
		}

	/* Disable persistence for the TUN device */
	if( err = ioctl(*fd, TUNSETPERSIST, 0) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETPERSIST)->%d, errno=%d", err, errno);
		}

	/* Set initial state of the TUN - DOWN ... */
	if ( 0 > (g_tun_sdctl = socket(AF_INET, SOCK_DGRAM, 0)) )
		{
		close(*fd);
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);
		}

	if( err = ioctl(g_tun_sdctl, SIOCGIFFLAGS, &ifr) )
		{
		close(*fd);
		close(g_tun_sdctl);
		return	$LOG(STS$K_ERROR, "ioctl(%s, SIOCGIFFLAGS)->%d, errno=%d", ifr.ifr_name, err,  errno);
		}

	ifr.ifr_ifru.ifru_flags &= (~IFF_UP);

	if ( err = ioctl(g_tun_sdctl, SIOCSIFFLAGS, &ifr) )
		{
		close(*fd);
		close(g_tun_sdctl);
		return	$LOG(STS$K_ERROR, "ioctl(SIOCSIFFLAGS)->%d", err, errno);
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
	ifr.ifr_flags = g_tunflags /* IFF_TAP */ | IFF_NO_PI; // | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	if ( 0 > (*fd = open(tundev_path, O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(*s), errno=%d", tundev_path, errno);

	if ( err = ioctl(*fd, TUNSETIFF, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
		}

	$LOG(STS$K_INFO, "TUN's device type is %s", g_tunflags == IFF_TAP ? "TAP (no Ethernet headers)" : "TUN");

	return	STS$K_SUCCESS;
}


static	int	tun_setip(void)
{
struct ifreq ifr = {0};
int	err, fd = -1;
struct sockaddr_in inaddr = {0};


	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = g_tunflags /* IFF_TAP */ | IFF_NO_PI; // | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

#if 0
	if ( 0 > (fd = open(tundev_path, O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(*s), errno=%d", tundev_path, errno);


	if ( err = ioctl(fd, TUNSETIFF, (void *)&ifr) )
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
#endif

	$LOG(STS$K_INFO, "TUN's device type is %s", g_tunflags == IFF_TAP ? "TAP (no Ethernet headers)" : "TUN");



	/* Assign IP address ... */
	inaddr.sin_addr = g_ia_cliaddr;
	inaddr.sin_family = AF_INET;

	memcpy(&ifr.ifr_addr, &inaddr, sizeof(struct sockaddr));

	if ( err = ioctl(g_tun_sdctl, SIOCSIFADDR, (void *)&ifr) )
		return	$LOG(STS$K_ERROR, "Error set IP on TUN, ioctl(SIOCSIFADDR)->%d, errno=%d", err, errno);

	/* Assign Network mask ... */
	inaddr.sin_addr = g_ia_netmask;
	inaddr.sin_family = AF_INET;

	memcpy(&ifr.ifr_netmask, &inaddr, sizeof(struct sockaddr));

	if ( err = ioctl(g_tun_sdctl, SIOCSIFNETMASK, (void *)&ifr) )
		return	$LOG(STS$K_ERROR, "Error set NETMASK for TUN, ioctl(SIOCSIFNETMASK)->%d, errno=%d", err, errno);

	/* Set state of the TUN - UP ... */
	if( err = ioctl(g_tun_sdctl, SIOCGIFFLAGS, &ifr) )
		return	$LOG(STS$K_ERROR, "ioctl(%s, SIOCGIFFLAGS)->%d, errno=%d", ifr.ifr_name, err,  errno);


	ifr.ifr_ifru.ifru_flags |= IFF_UP;

	if ( err = ioctl(g_tun_sdctl, SIOCSIFFLAGS, &ifr) )
		return	$LOG(STS$K_ERROR, "Error set TUN to UP state, ioctl(SIOCSIFFLAGS)->%d", err, errno);


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
		if ( 0 < (status = recvfrom(sd, bufp, bufsz, 0, (struct sockaddr *)&rsock, &slen)) )
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

	__util$add_time (&now, &g_timers_set.t_io, &etime);

	while ( 1 )
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
		if( 0 >  (status = WSAPoll(pfd, 1, 1000)) && (__ba_errno__ != WSAEINTR) )
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
		if ( bufsz == (status = sendto (sd, bufp, bufsz, MSG_NOSIGNAL, (struct sockaddr *) to , slen)) )
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
		else	$IFTRACE(g_trace, "Set signal handler for #%d (%s)", siglist[i], strsignal(siglist[i]));
		}
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
 *   DESCRIPTION: Establihing control channel with the server according Phase I:
 *	send LOGIN
 *	process ACCEPT
 *	accept parameters, setup TUN
 *
 *   IMPLICITE INPUT
 *
 *   IMPLICITE OUTPUT
 */
static int	control	(void)
{
int	len = 0, buflen = 0, v_type = 0, bufsz = 0;
char buf[SVPN$SZ_IOBUF];
SVPN_PDU *pdu = (SVPN_PDU *) buf;


	/* Send LOGIN <user> <password> request
	 *	pdu->digest = sha(header, salt, payload);
	 */
	pdu->magic64 = *magic64; /* memcpy(pdu->magic, SVPN$T_MAGIC, SVPN$SZ_MAGIC); */
	pdu->proto = SVPN$K_PROTO_V1;
	pdu->req = SVPN$K_REQ_LOGIN;
	bufsz = sizeof(buf) - (buflen = SVPN$SZ_PDUHDR);

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_REV, SVPN$K_BBLOCK, $ASCPTR(&__ident__), $ASCLEN(&__ident__), &len);
	buflen += len;
	bufsz -= len;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_USER, SVPN$K_BBLOCK, $ASCPTR(&g_user), $ASCLEN(&g_user), &len);
	buflen += len;
	bufsz -= len;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_OPTS, SVPN$K_LONG, &g_options, sizeof(g_options), &len);
	buflen += len;
	bufsz -= len;

	/* Compute HMAC*/
	hmac_gen(pdu->digest, SVPN$SZ_DIGEST,
			pdu, SVPN$SZ_HASHED, pdu->data, buflen - SVPN$SZ_PDUHDR, $ASCPTR(&g_auth), $ASCLEN(&g_auth),
				NULL /* End-of-arguments marqer !*/);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, &g_server_sk)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send HELLO to %.*s", g_udp_sd, $ASC(&g_server));

	$IFTRACE(g_trace, "[#%d]Sent LOGIN to %.*s, %d octets", g_udp_sd, $ASC(&g_server), buflen);

	/* Wait for ACCEPT ... */
	$IFTRACE(g_trace, "[#%d]Wait for ACCEPT from %.*s (timeout is %d msec) ...", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	if ( !(1 & recv_pkt (g_udp_sd, buf, sizeof(buf), &g_timers_set.t_io, &g_server_sk, &buflen)) )
		return	$LOG(STS$K_WARN, "[#%d]No ACCEPT from %.*s in %d msec, cancel session setup", g_udp_sd, $ASC(&g_server), timespec2msec (&g_timers_set.t_io));

	/* Check length and magic prefix of the packet, just drop unrelated packets */
	if ( (buflen < SVPN$SZ_PDUHDR) && (memcmp(pdu->magic, SVPN$T_MAGIC,  SVPN$SZ_MAGIC)) )
		return	$LOG(STS$K_ERROR, "[#%d]Drop request code %#x, from %.*s, length=%d octets", g_udp_sd, pdu->req, $ASC(&g_server), buflen);

	if ( pdu->proto != SVPN$K_PROTO_V1  )
		return	$LOG(STS$K_ERROR, "[#%d]Unsupported protocol version=%d", g_udp_sd, pdu->proto);

	if ( pdu->req != SVPN$K_REQ_ACCEPT )
		return	$LOG(STS$K_ERROR, "[#%d]Ignored unexpected request from %.*s, code=%#x", g_udp_sd, $ASC(&g_server), pdu->req);

	$IFTRACE(g_trace, "[%d]Got request code %#x, from %.*s, %d octets", g_udp_sd, pdu->req, $ASC(&g_server), buflen);

	/* Process ACCEPT  request: check HMAC */
	if ( !(1 & hmac_check(pdu->digest, SVPN$SZ_DIGEST,
			pdu, SVPN$SZ_HASHED, pdu->data, buflen - SVPN$SZ_PDUHDR, $ASCPTR(&g_auth), $ASCLEN(&g_auth),
				NULL /* End-of-arguments marger !*/)) )
		return	$LOG(STS$K_ERROR, "[%d]Hash checking error", g_udp_sd);

	if ( g_trace )
		tlv_dump(pdu->data, buflen - SVPN$SZ_PDUHDR);

	/* Extract attributes from ACCEPT packet */
	len = ASC$K_SZ;
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_NAME, &v_type, $ASCPTR(&g_cliname), &len)) )
		$LOG(STS$K_WARN, "[%d]No attribute %#x", g_udp_sd, SVPN$K_TAG_NAME);

	$ASCLEN(&g_cliname) = (unsigned char) len;

	len = ASC$K_SZ;
	$ASCLEN(&g_climsg) = 0;
	if ( (1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_MSG, &v_type, $ASCPTR(&g_climsg), &len)) )
		$ASCLEN(&g_climsg) = (unsigned char) len;

	len = sizeof(g_ia_network);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_NET, &v_type, &g_ia_network, &len)) )
		return	$LOG(STS$K_ERROR, "[%d]Error get attribute", g_udp_sd);

	len = sizeof(g_ia_netmask);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_NETMASK, &v_type, &g_ia_netmask, &len)) )
		return	$LOG(STS$K_ERROR, "[%d]Error get attribute", g_udp_sd);

	len = sizeof(g_ia_cliaddr);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_CLIADDR, &v_type, &g_ia_cliaddr, &len)) )
		return	$LOG(STS$K_ERROR, "[%d]Error get attribute", g_udp_sd);

	len = sizeof(g_enc);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_ENC, &v_type, &g_enc, &len))) )
		$LOG(STS$K_WARN, "[%d]No attribute %#x", g_udp_sd, SVPN$K_TAG_ENC);

	len = sizeof(int);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_PING, &v_type, &g_timers_set.t_ping.tv_sec, &len);

	len = sizeof(int);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_RETRY, &v_type, &g_timers_set.retry, &len);

	len = sizeof(int);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_IDLE, &v_type, &g_timers_set.t_idle.tv_sec, &len);

	len = sizeof(int);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_TOTAL, &v_type, &g_timers_set.t_max.tv_sec, &len);

	len = sizeof(int);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_TRACE, &v_type, &g_trace, &len);

	len = sizeof(g_tunflags);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_TUNTYPE, &v_type, &g_tunflags, &len);

	len = sizeof(g_run_options);
	tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_OPTS, &v_type, &g_run_options, &len);

	/* Display session parameters ... */
	$LOG(STS$K_INFO, "Session parameters  :");

	$LOG(STS$K_INFO, "\tTrace      : %s", g_trace ? "ON" : "OFF");
	$LOG(STS$K_INFO, "\tNetwork    : %s", inet_ntop(AF_INET, &g_ia_network, buf, sizeof(buf)));
	$LOG(STS$K_INFO, "\tNetmask    : %s", inet_ntop(AF_INET, &g_ia_netmask, buf, sizeof(buf)));
	$LOG(STS$K_INFO, "\tTUN/IP     : %s", inet_ntop(AF_INET, &g_ia_cliaddr, buf, sizeof(buf)));
	$LOG(STS$K_INFO, "\tEncryption : %d", g_enc);
	$LOG(STS$K_INFO, "\tMessage    : %.*s", $ASC(&g_climsg));
	$LOG(STS$K_INFO, "\tTUN Type   : %s", g_tunflags == IFF_TAP ? "TAP (no Ethernet headers)" : "TUN");

	$LOG(STS$K_INFO, "\tTimers     : ping=%u, idle=%u, total=%u, retry=%d",
	     g_timers_set.t_ping.tv_sec, g_timers_set.t_idle.tv_sec, g_timers_set.t_max.tv_sec, g_timers_set.retry);

	$LOG(STS$K_INFO, "\tLcl options: %08x, Rmt options: %08x ", g_options, g_run_options);
	g_run_options &= g_options;
	$LOG(STS$K_INFO, "\tRun options: %08x (negotiated)", g_run_options);

	return	$LOG(STS$K_SUCCESS, "Session is established");
}





/*
 *   DESCRIPTION: process has been received PING request.
 *
 *   INPUT:
 *	sd:	UDP socket descriptor
 *	to:	A remote client socket
 *	bufp:	A buffer with the PING's PDU
 *	buflen:	A size of the PDU
 *
 *   IMPLICITE OUTPUT
 */
static int	do_pong	(
				int	 sd,
		struct	sockaddr_in	*to,
				void	*buf,
				int	 buflen
				)
{
int	status, len = 0, v_type = 0, seq = 0;
SVPN_PDU *pdu = (SVPN_PDU *) buf;

	/*
	 * Extract SEQUENCE attribute
	 */
	len = sizeof(seq);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_SEQ, &v_type, &seq, &len))) )
		$LOG(STS$K_WARN, "[%d]No attribute %#x", g_udp_sd, SVPN$K_TAG_SEQ);

	$IFTRACE(g_trace, "[#%d]Received PING #%#x", g_udp_sd, seq);

	/* Do nothign with request - just sent it back as PONG request ... */
	pdu->req = SVPN$K_REQ_PONG;

	if ( !(1 & xmit_pkt (sd, buf, buflen, to)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send PONG #%#x", sd, seq);

	$IFTRACE(g_trace, "[#%d]Sent PONG #%#x", sd, seq);

	return	STS$K_SUCCESS;
}


/*
 *   DESCRIPTION: Send LOGOUT control sequence
 *
 *   INPUT:
 *	sd:	UDP socket descriptor
 *	to:	A remote client socket
 *	bufp:	A buffer with the PING's PDU
 *	buflen:	A size of the PDU
 *
 *   IMPLICITE OUTPUT
 */
static int	do_logout	(
				int	 sd,
		struct	sockaddr_in	*to
				)
{
SVPN_PDU pdu = {0};

	/* Form LOGOUT control packet ... */
	pdu.magic64 = *magic64;
	pdu.req = SVPN$K_REQ_LOGOUT;
	pdu.proto = SVPN$K_PROTO_V1;

	if ( !(1 & xmit_pkt (sd, &pdu, SVPN$SZ_PDUHDR, to)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send LOGOUT", sd);

	return	STS$K_SUCCESS;
}

/*
 *   DESCRIPTION: Retrieve from the given buffer frame/packet and send it to the TUN/TAP device.
 *
 *   INPUTS:
 *	td:	TUN/TAP device I/O descriptor
 *	buf:	A buffer with frames/packets to process
 *	buflen:	Actual length of data in the buffer
 *
 *   IMPLICITE INPUTS:
 *	g_tunflags
 *
 *   OUTPUTS:
 *	NONE
 *
 *   RETURNS:
 *	condition code
 */
static inline	int	__multiple_write(
				int	td,
				char	*buf,
				int	buflen
					)
{
int	len;
struct ethhdr	*eth;
struct iphdr	*iph;

	/* Heh, sanity check ... */
	if ( !buflen )
		return STS$K_SUCCESS;


	/* Compute a size of the data to be write depending on type of TUN/TAP device */
	if ( g_tunflags & IFF_TUN )
		{
		eth = (struct ethhdr *) buf;
		iph = (struct iphdr *)  (buf + ETH_HLEN);

		len = ETH_HLEN + ntohs(iph->tot_len) + ETH_FCS_LEN;
		}
	else	{ /* if ( g_tunflags & IFF_TAP ) */
		iph = (struct iphdr *) buf;

		len = ntohs(iph->tot_len);
		}

	/* Write frame or IP-packet to the TUN/TAP device */
	if ( len != write(td, buf, len) )
		$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on TUN device, write(%d octets), errno=%d", td, g_udp_sd, len, __ba_errno__);

	/* Is there unprocessed data in the buffer ? */
	if ( buflen -= len )
		return	__multiple_write(td, buf + len, buflen);


	return	STS$K_SUCCESS;
}



enum { SVPN$K_NET_FD = 0, SVPN$K_TUN_FD, SVPN$K_MAX_FD};

static int	s_worker	(void *a_arg)
{

int	l_rc = 0, l_tun_fd = -1,  l_slen = sizeof(struct sockaddr_in);
#ifdef WIN32
WSAPOLLFD  l_pfd[SVPN$K_MAX_FD] = {{g_udp_sd, POLLIN,0 }, {0, POLLIN, 0}};
#else
struct pollfd l_pfd[SVPN$K_MAX_FD] = {{g_udp_sd, POLLIN, 0 }, {l_tun_fd, POLLIN, 0}};
#endif // WIN32
struct timespec	l_now, l_etime;
char	l_buf [SVPN$SZ_IOBUF];
SVPN_PDU *l_pdu = (SVPN_PDU *) l_buf;

struct	sockaddr_in l_rsock = {0};

	$LOG(STS$K_INFO, "Starting ...");

	/* Open channel to TUN device */
	if ( !(1 & (l_rc = tun_open(&l_tun_fd))) )
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error allocating TUN device");

	/* We suppose to be use poll() on the TUN and UDP channels to performs
	 * I/O asyncronously
	 */
	l_pfd[SVPN$K_TUN_FD].fd = l_tun_fd;

	$LOG(STS$K_INFO, "[#%d-#%d]Main loop ...", l_tun_fd, g_udp_sd);

	for  ( ; !g_exit_flag; )
		{
		/*
		 *  We performs working only is signaling/data channel has been established,
		 * so we should check that g_state == SVPN$K_STATETUN, in any other case we hibernate execution until
		 * signal.
		 */

		if ( g_state != SVPN$K_STATETUN )
			{
			if ( l_rc = clock_gettime(CLOCK_REALTIME, &l_now) )
				g_exit_flag = $LOG(STS$K_ERROR, "[#%d]clock_gettime()->%d, errno=%d", l_tun_fd, l_rc, errno);

			__util$add_time(&l_now, &g_timers_set.t_ping, &l_etime);

			pthread_mutex_lock(&crew_mtx);
			l_rc = pthread_cond_timedwait(&crea_cond, &crew_mtx, &l_etime);
			pthread_mutex_unlock(&crew_mtx);

			if ( l_rc && (l_rc != ETIMEDOUT) )
				{
				g_exit_flag = $LOG(STS$K_ERROR, "[#%d]pthread_cond_timedwait()->%d, errno=%d", l_tun_fd, l_rc, errno);
				break;
				}


			if ( g_state != SVPN$K_STATETUN )
				continue;

			$IFTRACE(g_trace, "[#%d]Got wake-up signal, unsleep worker !", l_tun_fd);
			}



		/* Wait Input events from TUN or UDP device ... */
#ifdef WIN32
		if( 0 >  (rc = WSAPoll(pfd, 2, timespec2msec (delta))) && (__ba_errno__ != WSAEINTR) )
#else
		if( 0 >  (l_rc = poll(l_pfd, SVPN$K_MAX_FD, timespec2msec (&g_timers_set.t_io))) && (__ba_errno__ != EINTR) )
#endif // WIN32
			return	$LOG(STS$K_ERROR, "[#%d-#%d]poll()->%d, errno=%d", l_tun_fd, g_udp_sd, l_rc, __ba_errno__);


		if ( !l_rc )	/* Nothing to do */
			continue;


#ifdef WIN32
		if ( (rc < 0) && (__ba_errno__ == WSAEINTR) )
#else
		if ( (l_rc < 0) && (__ba_errno__ == EINTR) )
#endif
			{
			$LOG(STS$K_WARN, "[#%d-#%d]poll()->%d, errno=%d", l_tun_fd, g_udp_sd, l_rc, __ba_errno__);
			continue;
			}



		if ( l_pfd[SVPN$K_NET_FD].revents & (~POLLIN) || l_pfd[SVPN$K_TUN_FD].revents & (~POLLIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					l_tun_fd, g_udp_sd, l_rc, l_pfd[0].revents, l_pfd[1].revents, __ba_errno__);

		/* Retrieve data from UDP socket -> send to TUN device	*/
		l_slen = sizeof(struct sockaddr_in);
		if ( (l_pfd[SVPN$K_NET_FD].revents & POLLIN) && (0 < (l_rc = recvfrom(g_udp_sd, l_buf, sizeof(l_buf), 0, (struct sockaddr *) &l_rsock, &l_slen))) )
			{
			/* Check sender IP, ignore unrelated packets ... */
			if ( g_server_sk.sin_addr.s_addr != l_rsock.sin_addr.s_addr )
				continue;

			atomic_fetch_add(&g_input_count, 1);

			/* Is it's control packet begined with the magic prefix  ? */
			if ( l_pdu->magic64 == *magic64 )
				{
				$IFTRACE(g_trace, "Got control packet, req=%d, %d octets", l_pdu->req, l_rc);

				switch ( l_pdu->req )
					{
					case	SVPN$K_REQ_PING:
						do_pong (g_udp_sd, &g_server_sk, l_pdu, l_rc);
						break;

					case	SVPN$K_REQ_LOGOUT:
						$LOG(STS$K_INFO, "Close tunnel by LOGOUT request");
						g_state = SVPN$K_STATEOFF;
						do_logout (g_udp_sd, &g_server_sk);
						g_exit_flag = 1;
						break;
					}

				/* Skip rest of processing */
				continue;
				}

			//$IFTRACE(g_trace, "UDP RD: %d octets", rc);


			if ( g_enc != SVPN$K_ENC_NONE )
				decode(g_enc, l_buf, l_rc, g_key, sizeof(g_key));

			/* If aggregation option is take place we need to retrieve frame/IP-packet from datagrame */

			if ( SVPN$K_OPT_AGGR & g_run_options )
				__multiple_write(l_tun_fd, l_buf, l_rc);
			else if ( l_rc != write(l_tun_fd, l_buf, l_rc) )
				$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on TUN device, write(%d octets), errno=%d", l_tun_fd, g_udp_sd, l_rc, __ba_errno__);

			//$IFTRACE(g_trace, "TUN WR: %d octets", rc);
			}
		else
#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= l_rc) && (errno != EINPROGRESS) )
#endif
			{
			$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					l_tun_fd, g_udp_sd, l_rc, l_pfd[0].revents, l_pfd[1].revents, __ba_errno__);
			break;
			}


		/* Retrieve data from TUN device -> send to UDP socket */
		if ( (l_pfd[SVPN$K_TUN_FD].revents & POLLIN) && (0 < (l_rc = read (l_tun_fd, l_buf, sizeof(l_buf)))) )
			{
			l_slen = sizeof(struct sockaddr_in);


			//$IFTRACE(g_trace, "TUN RD: %d octets", rc);

			if ( g_enc != SVPN$K_ENC_NONE )
				encode(g_enc, l_buf, l_rc, g_key, sizeof(g_key));

			if ( l_rc != sendto(g_udp_sd, l_buf, l_rc, 0, (struct sockaddr *) &g_server_sk, l_slen) )
				$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on UDP socket, sendto(%d octets), errno=%d", l_tun_fd, g_udp_sd, l_rc, errno);


			//$IFTRACE(g_trace, "UDP WR: %d octets", rc);
			}
		else
#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= l_rc) && (errno != EINPROGRESS) )
#endif
			$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
					l_tun_fd, g_udp_sd, l_rc, l_pfd[0].revents, l_pfd[1].revents, __ba_errno__);
		}


	return	$LOG(STS$K_INFO, "Terminated");
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
typedef void *(* pthread_func_t) (void *);

int	main	(int argc, char **argv)
{
int	status, idle_count;
pthread_t	tid;


	if ( (argc == 2) && (!strcmp(argv[1], "-v")) )
		{
		fprintf(stdout, "%s\n", __REV__);
		return	1;
		}

	$LOG(STS$K_INFO, "Rev: " __IDENT__ "/"  __ARCH__NAME__   ", (built  at "__DATE__ " " __TIME__ " with CC " __VERSION__ ")");

	if ( argc < 2 )
		{
		fprintf(stdout, help, argv[0], argv[0]);
		return	-EINVAL;
		}


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
	if ( !(1 & tun_init (&g_tun_fd)) )
		return	$LOG(STS$K_ERROR, "Error initialization of the TUN device. Start aborted.");

	close(g_tun_fd);

	/* Initialize UDP socket */
	if ( !(1 & udp_init (&g_udp_sd)) )
		return	$LOG(STS$K_ERROR, "Error initialization of the UDP socket. Start aborted.");


	/* Just for fun */
	init_sig_handler ();

	/* Generate session key ... */
	hmac_gen(g_key, sizeof(g_key), $ASCPTR(&g_auth), $ASCLEN(&g_auth), NULL);

	/* Create crew workers */
	for ( int i = 0; i < g_threads; i++ )
		{
		if ( status = pthread_create(&tid, NULL, (pthread_func_t)  s_worker, NULL) )
			return	$LOG(STS$K_FATAL, "Cannot start worker thread, pthread_create()->%d, errno=%d", status, errno);
		}

	/**/
	for ( idle_count = 0;  !g_exit_flag; __util$rewindlogfile(g_logsize) )
		{
		if ( g_state == SVPN$K_STATECTL )
			{
			if ( 1 & control () )
				{
				g_state = SVPN$K_STATEON;
				$LOG(STS$K_INFO, "State is ON");

				tun_setip();		/* Assign IP, UP the tunX */
				//set_tun_state(1);	/* UP the tunX */
				}
			}

		if ( g_state == SVPN$K_STATEON )
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

		if ( g_state == SVPN$K_STATEOFF )
			{
			g_state = SVPN$K_STATECTL;
			$LOG(STS$K_INFO, "State is CONTROL");

			do_logout (g_udp_sd, &g_server_sk);

			set_tun_state(0);	/* Down the tunX */

			exec_script(&g_linkdown);
			continue;
			}

		if ( g_state == SVPN$K_STATETUN )
			{
			/* Check activity on the tunnel ... */
			if ( !atomic_load(&g_input_count) )
				{
				if ( (++idle_count) >= g_timers_set.retry )
					{
					$LOG(STS$K_ERROR, "Zero activity has been detected, close data channel");
					g_state = SVPN$K_STATEOFF;
					continue;
					}
				else	{
					$IFTRACE(g_trace, "No inputs from remote SVPN client, idle count is %d", idle_count);
					}
				}
			else	{
				$IFTRACE(g_trace, "Inputs counter is %d", g_input_count);
				idle_count = 0;
				}

			atomic_store(&g_input_count, 0); /* Reset inputs counter */
			}


		status = g_timers_set.t_ping.tv_sec;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32
		}



	set_tun_state (0);			/* Switch DOWN the tunX device */
	do_logout (g_udp_sd, &g_server_sk);	/* Send LOGOUT control packet to close session */



	/* Get out !*/
	$LOG(STS$K_INFO, "Exit with exit_flag=%d!", g_exit_flag);

	return	STS$K_SUCCESS;
}
