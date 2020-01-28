#define	__MODULE__	"SVPNSRV"
#define	__IDENT__	"X.00-14ECO5"
#define	__REV__		"0.14.5"

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
	#pragma	GCC diagnostic ignored	"-Wmissing-braces"
	#pragma	GCC diagnostic ignored	"-Wdiscarded-qualifiers"
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
**l
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
**
**			-v, -?, -h, -o <file>, -d
**
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
**	 9-OCT-2019	RRL	Added sending of TRACE option to SVPN client on LOGIN;
**				added handling of unix-style arguments: -v, -?, -h, -o <file>, -d
**
**	10-OCT-2019	RRL	Reduced diagnostic messages;
**				added /DELTAONLINE=<seconds>
**
**	11-OCT-2019	RRL	X.00-09 : Added ping/pong sequences checking;
**				added backlog of IP address
**
**	30-OCT-2019	RRL	X.00-11 : Fixed consuming CPU time has been caused by using wrong end time passed to the pthread_cond_timedwait();
**				fixed hung in the backlog_uopdate();
**
**	31-OCT-2019	RRL	X.00-12 : Added functionality to limit of volume of traffic over tunnel;
**				new configuration option: DATA_VOLUME_LIMIT=<Gigobytes>
**
**	20-NOV-2019	RRL	X.00-12ECO1 : Changed displaying of RTT from nsecs to ms.
**
**	21-NOV-2019	RRL	X.00-13 : Added record in the log file on receiving of SIGUSR2;
**				Added assigment of the NETWORK MASK on the TUN device.
**
**	22-NOV-2019	RRL	X.00-14 : Added /MODETUN=TAP|TUN, TUN is default mode;
**				fixed bug with handling of SIGUSR2
**
**	24-NOV-2019	RRL	X.00-14ECO1 : Fixed bug in RTT computation has implied bu bug in the __util$sub_time()
**				X.00-14ECO2 : fixed exiting by incorrect handling SIGUSR2.
**
**	25-JAN-2020	RRL	X.00-14ECO3 : Added some more diagnostic into the stat_write();
**				changed __REV__ format to count ECO.
**
**	27-JAN-2020	RRL	X.00-14ECO4 : Write stat record at interval basis (deltaonline).
**--
*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<time.h>
#include	<inttypes.h>
#include	<signal.h>
#include	<getopt.h>
#include	<libgen.h>
#include	<sys/uio.h>
#include	<sys/types.h>
#include	<sys/stat.h>

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
#include	<linux/limits.h>
#include	<stdatomic.h>
#include	<net/ethernet.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/tcp.h>

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
	g_trace = 0,			/* A flag to produce extensible logging	*/
	g_enc = SVPN$K_ENC_NONE,	/* Encryption mode, default is none	*/
	g_threads = 1,			/* A size of the worker crew threads	*/
	g_udp_sd = -1,
	g_tun_fd = -1,
	g_mtu = 0,			/* MTU for datagram			*/
	g_mss = 0,			/* MSS for TCP/SYN			*/
	g_outseq = 1,			/* A sequence number for sent PING	*/
	g_inpseq,			/* A sequence number for received PONG	*/
	g_logsize = 0,			/* A maximum lofgile size in octets	*/
	g_deltaonline = 300,		/* An interval of printing "Client still ONLINE" */
	g_lenbacklog = 0,
	g_tunflags = IFF_TUN;		/* Default type of the '/dev/net/tun'	*/

unsigned long long g_data_volume_limit = 0,	/* A total tunnel traffic volume limit	*/
		g_data_volume = 0;		/* Current volume of the traffic	*/

static	volatile int	reset_by_external_flag = 0;


static	atomic_ullong g_input_count = 0;/* Should be increment by receiving from UDP */


static const struct timespec g_locktmo = {5, 0};/* A timeout for thread's wait lock	*/

ASC	g_tun = {$ASCINI("tunX:")},	/* OS specific TUN device name		*/
	g_logfspec = {0}, g_confspec = {0},
	g_bind = {0}, g_cliname = {0}, g_auth = {0},
	g_network = {$ASCINI("192.168.1.0/24")}, g_cliaddr = {$ASCINI("192.168.1.2")}, g_locaddr = {$ASCINI("192.168.1.1")},
	g_timers = {$ASCINI("7, 120, 13")},
	g_keepalive = {$ASCINI("3, 3")},
	g_climsg = {0}, g_linkup = {0}, g_linkdown = {0},
	q_fstat = {0},
	g_ipbacklog = {0},
	g_fifo = {0},			/* FIFO spec to interchange by counters		*/
	g_volume = {0},			/* File to keep a traficc voulme for the tunnel	*/
	g_tunmode = {$ASCINI("TUN")};	/* Default type of the TUN device is TAP	*/


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
	int	retry;

} SVPN_TIMERS;

struct timespec	g_rtt = {.tv_sec = 1, .tv_nsec = 1};

static	SVPN_TIMERS	g_timers_set = { {7, 0}, {120, 0}, {13, 0}, {600, 0}, 3};


					/* PTHREAD's stuff is supposed to be used to control worker's
					 * crew threads
					 */
static	pthread_mutex_t crew_mtx = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	crea_cond = PTHREAD_COND_INITIALIZER;


typedef struct	__svpn_stat__
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

	struct  timespec ts;

} SVPN_STAT;
SVPN_STAT	g_stat_last = {0}, g_stat = {0}, g_stat_zero = {0};



const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&g_confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("trace"),	&g_trace, 0,		OPTS$K_OPT},
	{$ASCINI("bind"),	&g_bind, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("logfile"),	&g_logfspec, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("logsize"),	&g_logsize, 0,		OPTS$K_INT},
	{$ASCINI("devtun"),	&g_tun, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("cliname"),	&g_cliname, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("cliaddr"),	&g_cliaddr, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("climsg"),	&g_climsg, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("locaddr"),	&g_locaddr, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("auth"),	&g_auth, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("network"),	&g_network, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("timers"),	&g_timers, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("keepalive"),	&g_keepalive, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("encryption"),	&g_enc,	0,		OPTS$K_INT},
	{$ASCINI("threads"),	&g_threads,	0,	OPTS$K_INT},
	{$ASCINI("linkup"),	&g_linkup, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("linkdown"),	&g_linkdown, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("MTU"),	&g_mtu,	0,		OPTS$K_INT},
	{$ASCINI("MSS"),	&g_mss,	0,		OPTS$K_INT},
	{$ASCINI("deltaonline"),&g_deltaonline,	0,	OPTS$K_INT},
	{$ASCINI("stat"),	&q_fstat,ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("ipbacklog"),	&g_ipbacklog,ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("data_volume_limit"),	&g_data_volume_limit, 0,		OPTS$K_INT},
	{$ASCINI("modetun"),	&g_tunmode,ASC$K_SZ,	OPTS$K_STR},


	OPTS_NULL
};

const mode_t f_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

const char	help [] = { "Usage:\n" \
	"$ %s [<options_list>]\n\n" \
	"\t/CONFIG=<file>    configuration options file path\n" \
	"\t/TRACE            enable extensible diagnostic output\n" \
	"\t/LOGFILE=<file>   a specification of file to accept logging\n" \
	"\t/LOGSIZE=<number> a maximum size of file in octets\n" \
	"\t/LINKUP=<file>    script to be executed on tunnel up\n" \
	"\t/LINKDOWN=<file>  script to be executed on tunnel down\n" \
	"\t/AUTH=<user:pass> username and password pair\n" \
	"\n\tExample of usage:\n\t $ %s -config=svpn_server.conf /trace\n\n" };



/*
 *  DESCRIPTION: Read old content of the IP Backlog file, add new entry at begin of file,
 *	write new content to file.
 *
 *  INPUT:
 *	ip:	IP address to be added
 *
 *  IMPLICITE INPUT:
 *	g_backlog
 *	g_lenbacklog
 *
 *  OUTPUT:
 *	NONE
 *
 *  RETURN
 *	condition code
 *
 */
int	backlog_update	(
		struct	in_addr *ip
			)
{
int	fd = -1, status;
struct in_addr iparr [SVPN$SZ_MAXIPBLOG] = {0};


	if ( !$ASCLEN(&g_ipbacklog) )
		return	STS$K_SUCCESS;


	if ( 0 > (fd = open($ASCPTR(&g_ipbacklog), O_RDWR | O_CREAT, f_mode)) )
		return	$LOG(STS$K_ERROR, "IP Backlog file open(%s), errno=%d", $ASCPTR(&g_ipbacklog), errno);


	if ( 0 > (status = read(fd, iparr, sizeof(iparr))) )
		status = $LOG(STS$K_ERROR, "IP Backlog file read(%s), errno=%d", $ASCPTR(&g_ipbacklog), errno);
	else	{
		/* Set file pointer at begin of the backlog file */
		lseek(fd, SEEK_SET, 0);

		/* Add new entry at top of array */
		memmove(&iparr[1], &iparr[0], (g_lenbacklog - 1) * sizeof(iparr[0]));
		iparr[0] = *ip;

		/* Zeroing rest of array */
		memset(&iparr[g_lenbacklog], 0, (SVPN$SZ_MAXIPBLOG - g_lenbacklog) * sizeof(iparr[0]));

		/* Write IPs array back to the file */
		if ( 0 > (status = write (fd, iparr, sizeof(iparr))) )
			status = $LOG(STS$K_ERROR, "IP Backlog file write(%s), errno=%d", $ASCPTR(&g_ipbacklog), errno);
		else	status = STS$K_SUCCESS;
		}

	close(fd);

	return	status;
}



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


static inline void	__bits2inaddr	(
			int	bits,
			void	*mask
				)
{
unsigned	lmask = 0xFFFFFFFFUL;

	*((unsigned *) mask) = htonl((lmask << (32 - bits)));
}


static	int	config_process	(void)
{
int	status = STS$K_SUCCESS, bits, fd = -1;
char	*cp, *saveptr = NULL, *endptr = NULL, ia [ 64 ], mask [ 64], fspec[255];

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
			g_timers_set.t_max.tv_sec = status;
			}
		}

	if ( $ASCLEN(&g_ipbacklog) )
		{
		sscanf($ASCPTR(&g_ipbacklog), "%[^,\n],%[^\n]" , fspec, mask);
		__util$str2asc (fspec, &g_ipbacklog);
		g_lenbacklog = atoi(mask);
		g_lenbacklog = g_lenbacklog ? g_lenbacklog : 5;

		$IFTRACE(g_trace, "ipbacklog=%.*s, lenipbacklog=%d", $ASC(&g_ipbacklog), g_lenbacklog);
		}


	sscanf($ASCPTR(&g_network), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_network) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_network));

	if ( bits = atoi(mask) )
		__bits2inaddr(bits, &g_netmask);

	inet_ntop(AF_INET, &g_netmask, mask, sizeof(mask));
	$IFTRACE(g_trace, "NETWORK:%s/%s", ia, mask);

	sscanf($ASCPTR(&g_cliaddr), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_cliaddr) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_cliaddr));

	sscanf($ASCPTR(&g_locaddr), "%[^/\n]/%[^\n]" , ia, mask);
	if ( !inet_pton(AF_INET, ia, &g_ia_local) )
		return	$LOG(STS$K_ERROR, "Error converting IA=%s from %.*s", ia, $ASCPTR(&g_locaddr));

	status = sscanf($ASCPTR(&g_keepalive), "%d , %d" , &g_timers_set.t_ping.tv_sec, &g_timers_set.retry);

	/* FIFO channel to put statistic vector */
	$ASCLEN(&g_fifo) = (unsigned char) snprintf($ASCPTR(&g_fifo), ASC$K_SZ, "/tmp/svpn-%.*s", $ASC(&g_tun));

	if ( mkfifo($ASCPTR(&g_fifo), 0777) && (errno != EEXIST) )
		$LOG(STS$K_ERROR, "mkfifo(%.*s), errno=%d", $ASC(&g_fifo), errno);
	else	$LOG(STS$K_SUCCESS, "FIFO device '%.*s' has been created", $ASC(&g_fifo));

	/* Make file name for tunnel volume of traffic */
	if ( $ASCLEN(&q_fstat) )
		{
		char fn[256] = {0};

		/* Set limit Volume Data is in Gbytes to very big value */
		g_data_volume_limit *= 1024*1024*1024;

		/* Make a copy of the string to exclude modufication of the original value */
		strncpy(fn, $ASCPTR(&q_fstat), $MIN(ASC$K_SZ, sizeof(fn) - 1));

		if ( !(cp = dirname( fn)) )
			cp = "./";

		$ASCLEN(&g_volume) = (unsigned char) snprintf($ASCPTR(&g_volume), ASC$K_SZ, "%s/volume-%.*s.dat", cp, $ASC(&g_tun));

		$LOG(STS$K_SUCCESS, "Keep volume traffic for device in '%.*s', volume limits is %llu (0 - unlimited)", $ASC(&g_volume), g_data_volume_limit);

		/*
		 * Check for existen Data Volume file and load value from it
		 */
		if ( 0 > (fd = open($ASCPTR(&g_volume), O_RDONLY)) )
			$LOG(STS$K_WARN, "open(%s), errno=%d", $ASCPTR(&g_volume), errno);
		else if ( sizeof(g_data_volume) != read (fd, &g_data_volume, sizeof(g_data_volume)) )
			$LOG(STS$K_ERROR, "read(%s, %d octets), errno=%d", $ASCPTR(&g_volume), sizeof(g_data_volume), errno);
		else	$IFTRACE(g_trace, "Current Data Volume is %llu octets", g_data_volume);

		close(fd);
		}

	/* /MODEUN=TAP|[TUN] */
	if ( $ASCLEN(&g_tunmode) >= 2 )
		{
		cp  = $ASCPTR(&g_tunmode);
		cp++;

		switch ( toupper(*cp))
			{
			case	'U':	/* TUN */
				g_tunflags = IFF_TUN;
				break;

			case	'A':	/* TAP */
				g_tunflags = IFF_TAP;
				break;

			default:
				$LOG(STS$K_ERROR, "Unrecognized TUN's mode='%.*s'", $ASC(&g_tunmode));

			}
		}

	$LOG(STS$K_INFO, "TUN's device mode is %s", g_tunflags == IFF_TAP ? "TAP (no Ethernet headers)" : "TUN");

	return	STS$K_SUCCESS;
}


int	stat_write	(void)
{
struct	tm	tmnow = {0};
char	fname [ NAME_MAX] = {0};
struct iovec iov [] = { {&tmnow, sizeof(tmnow)}, {&g_stat, sizeof(g_stat)} };
int	fd = -1, iovlen = sizeof(tmnow) + sizeof(g_stat);

	$IFTRACE(g_trace, "Stat file/path '%.*s'", $ASC(&q_fstat) );

	if ( !$ASCLEN(&q_fstat) )
		return	STS$K_SUCCESS;

	/* Generate a final file specification by adding year and month at end of file specification from configuration option:
	 * e.g. :
	 *	./tmp/starlet-zilla/tun135.stat
	 * -->
	 *	./tmp/starlet-zilla/tun135.stat-2019-01
	 */
	__util$timbuf(NULL, &tmnow);
	sprintf(fname, "%.*s-%04d-%02d", $ASC(&q_fstat), tmnow.tm_year, tmnow.tm_mon);

	$IFTRACE(g_trace, "Writting statistic to '%s'", fname );

	if ( 0 > (fd = open (fname, O_CREAT | O_WRONLY | O_APPEND, f_mode)) )
		return	$LOG(STS$K_ERROR, "open(%s)->%d, errno=%d", fname, fd, errno);


	/* Write record: <timespec> <stat vector> */
	if ( iovlen  != writev(fd, iov, $ARRSZ(iov)) )
		return	$LOG(STS$K_ERROR, "Statistic write error, writev(%s, %d octets), errno=%d", fname, iovlen, errno);

	close(fd);

	$IFTRACE(g_trace, "Statistic (%d octets) has been saved '%s'", iovlen, fname );

	return	STS$K_SUCCESS;
}


void	stat_update	(void)
{
int	fd = -1;
SVPN_VSTAT vstat = {0};

	if ( !$ASCLEN(&g_fifo) )
		return;

	/* Update stat vector with computed bandwidth counters,
	 * it's not correct way to use atomic values but is acceptable at glance
	*/
	vstat.bnetrd = g_stat.bnetrd - g_stat_last.bnetrd;
	vstat.bnetwr = g_stat.bnetwr - g_stat_last.bnetwr;

	vstat.pnetrd = g_stat.pnetrd - g_stat_last.pnetrd;
	vstat.pnetwr = g_stat.pnetwr - g_stat_last.pnetwr;

	vstat.rtt = g_rtt;

	__util$sub_time(&g_stat.ts, &g_stat_last.ts, &vstat.delta);
	vstat.delta = vstat.delta.tv_sec ? vstat.delta : g_timers_set.t_ping;

	/* Save current counters for future use */
	g_stat_last = g_stat;

	/* Open FIFO device, write stat vector record, close */
	if( access($ASCPTR(&g_fifo), F_OK | W_OK) )
		{
		if ( 0 > (fd = open($ASCPTR(&g_fifo), O_WRONLY | O_NONBLOCK)) )
			$IFTRACE(g_trace && (errno != ENXIO),  "open(%.*s), errno=%d", $ASC(&g_fifo), errno);
		else if ( sizeof(SVPN_VSTAT) != write(fd, &vstat, sizeof(SVPN_VSTAT)) )
			$IFTRACE(g_trace, "write(%.*s, %d octets), errno=%d", $ASC(&g_fifo), sizeof(vstat), errno);

		if ( !(fd < 0) )
			close(fd);
		}

	/* Adjust total data traffic volume */
	g_data_volume	+= g_stat.bnetrd;
	g_data_volume	+= g_stat.bnetwr;

	/*
	 * Update Data Volume counter in the file
	 */
	if ( 0 > (fd = open($ASCPTR(&g_volume), O_WRONLY | O_CREAT, f_mode)) )
		$LOG(STS$K_ERROR, "open(%s), errno=%d", $ASCPTR(&g_volume), errno);
	else if ( sizeof(g_data_volume) != write (fd, &g_data_volume, sizeof(g_data_volume)) )
		$LOG(STS$K_ERROR, "write(%s, %d octets), errno=%d", $ASCPTR(&g_volume), sizeof(g_data_volume), errno);

	if ( !(fd < 0) )
		close(fd);
}

/*
 * change TCP MSS option in SYN/SYN-ACK packets, if present
 * this is generic for IPv4 and IPv6, as the TCP header is the same
 */
#define	$TCPH_GET_DOFF(d) (((d) & 0xF0) >> 2)

/*
 * The following macro is used to update an
 * internet checksum.  "acc" is a 32-bit
 * accumulation of all the changes to the
 * checksum (adding in old 16-bit words and
 * subtracting out new words), and "cksum"
 * is the checksum value to be updated.
 */
static inline unsigned short adjust_checksum	(int acc, unsigned short csum)
{
int _acc = acc;

	_acc += (csum);

	if (_acc < 0)
		{
		_acc = -_acc;
		_acc = (_acc >> 16) + (_acc & 0xffff);
		_acc += _acc >> 16;
		(csum) = (uint16_t) ~_acc;
		}
	else	{
		_acc = (_acc >> 16) + (_acc & 0xffff);
		_acc += _acc >> 16;
		(csum) = (uint16_t) _acc;
		}

	return	csum;
}


void	mss_fixup_dowork (
			char	*buf,
			int	bufsz,
		unsigned short	maxmss
			)
{
struct tcphdr	*tcph = (struct tcphdr *) buf;
int	hlen, olen, optlen, accumulate;
uint8_t *opt;
uint16_t *mss;

	//$DUMPHEX(tcph, bufsz);
	//$IFTRACE(debug, "TH_OFF=%#x", tcph->th_off);

	hlen = tcph->th_off * 4;

	//$DUMPHEX(tcph, hlen);


	/* Invalid header length or header without options. */
	if ( (hlen <= sizeof (struct tcphdr)) || (hlen > bufsz) )
		return;

	//$DUMPHEX(tcph, hlen);

	for (olen = hlen - sizeof (struct tcphdr), opt = (uint8_t *)(tcph + 1);
		olen > 0; olen -= optlen, opt += optlen)
		{
		if (*opt == TCPOPT_EOL)
			break;
		else if (*opt == TCPOPT_NOP)
			optlen = 1;
		else	{
			optlen = *(opt + 1);

			if (optlen <= 0 || optlen > olen)
				break;

			if (*opt == TCPOPT_MAXSEG)
				{
				if (optlen != TCPOLEN_MAXSEG)
					continue;

				mss = (uint16_t *)(opt + 2);

				if (ntohs (*mss) > maxmss)
					{
					$IFTRACE(g_trace, "MSS: %d -> %d", ntohs (*mss), maxmss);

					accumulate = *mss;
					*mss = htons (maxmss);
					accumulate -= *mss;

					tcph->check = adjust_checksum (accumulate, tcph->check);
					}
				}
			}
		}
}




/*
 * Lower MSS on TCP SYN packets to fix MTU
 * problems which arise from protocol
 * encapsulation.
 */
#define	$IPH_GET_LEN(v)	(((v) & 0x0F) << 2)

/*
 * IPv4 packet: find TCP header, check flags for "SYN"
 *              if yes, hand to mss_fixup_dowork()
 */
static inline void	mss_fixup_ipv4 (
		char	*buf,
		int	 bufsz,
	unsigned short	 maxmss
			)
{
struct iphdr	*iph;
int	hlen;
struct	tcphdr	*tcph;

	/* Too short ? */
	if ( bufsz < sizeof(struct iphdr) )
		return;

	iph = (struct iphdr *) buf;
	hlen = $IPH_GET_LEN (iph->ihl);

	if ( (iph->protocol == IPPROTO_TCP)				/* MSS is only for TCP Protocol	*/
		&& (ntohs (iph->tot_len) == bufsz)			/* Check IP Header declared length against real IP packet size */
		&& ((ntohs (iph->frag_off) & IP_OFFMASK) == 0)		/* Don't try to do anything with fragments	*/
		&& (hlen <= bufsz)					/* Check IP Header length */
		&& ((bufsz - hlen) >= (int) sizeof (struct tcphdr)) )	/* Is the place for TCP Header ?*/
		{
		tcph = (struct tcphdr *)  &buf[hlen];

		if (tcph->th_flags & TH_SYN)
			mss_fixup_dowork (tcph, bufsz - hlen, maxmss);
		}
}

/*
 * IPv6 packet: find TCP header, check flags for "SYN"
 *              if yes, hand to mss_fixup_dowork()
 *              (IPv6 header structure is sufficiently different from IPv4...)
 */
static inline void	mss_fixup_ipv6 (
		char	*buf,
		int	 bufsz,
	unsigned short	 maxmss
			)
{
struct ip6_hdr *iph;
struct	tcphdr	*tcph;

	/* Too short ? */
	if ( bufsz < sizeof(struct ip6_hdr) )
		return;

	iph = (struct iphdr *) buf;

	/* do we have the full IPv6 packet?
	* "payload_len" does not include IPv6 header (+40 bytes)
	*/
	if ( bufsz != (ntohs(iph->ip6_plen) + sizeof(struct ip6_hdr)) )
		return;

	/* follow header chain until we reach final header, then check for TCP
	*
	* An IPv6 packet could, theoretically, have a chain of multiple headers
	* before the final header (TCP, UDP, ...), so we'd need to walk that
	* chain (see RFC 2460 and RFC 6564 for details).
	*
	* In practice, "most typically used" extention headers (AH, routing,
	* fragment, mobility) are very unlikely to be seen inside an OpenVPN
	* tun, so for now, we only handle the case of "single next header = TCP"
	*/
	if ( iph->ip6_nxt != IPPROTO_TCP )
		return;

	tcph = (struct tcphdr *)  &buf[sizeof(struct ip6_hdr)];

	if (tcph->th_flags & TH_SYN)
		mss_fixup_dowork (tcph, bufsz - sizeof(struct ip6_hdr), maxmss - 20);

}



static inline void	mss_fixup (
		char	*buf,
		int	 bufsz,
	unsigned short	 maxmss
			)
{
struct iphdr	*iph = (struct iphdr *) buf;



	if ( iph->version == 4 )
		return	mss_fixup_ipv4 (buf, bufsz, maxmss);

	if ( iph->version == 6 )
		return	mss_fixup_ipv6 (buf, bufsz, maxmss);

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

	$IFTRACE(g_trace, "Set %s to %s", ifr.ifr_name, up_down ? "UP" :  "DOWN");

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
	ifr.ifr_flags = g_tunflags  /*IFF_TAP*/ | IFF_NO_PI | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	/* Allocate new /devtunX ... */
	if ( 0 > (*fd = open("/dev/net/tun", O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(/dev/net/tun), errno=%d", errno);

	if ( err = ioctl(*fd, TUNSETIFF, (void *)&ifr) )
		{
		close(*fd);
		return	$LOG(STS$K_ERROR, "ioctl(TUNSETIFF)->%d, errno=%d", err, errno);
		}

	/* Disable persistence for the TUN device */
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
		return	$LOG(STS$K_ERROR, "Error set IP on TUN, ioctl(SIOCSIFADDR)->%d, errno=%d", err, errno);
		}


	/* Assign Network mask ... */
	inaddr.sin_addr = g_netmask;
	inaddr.sin_family = AF_INET;

	memcpy(&ifr.ifr_netmask, &inaddr, sizeof(struct sockaddr));

	if ( err = ioctl(sd, SIOCSIFNETMASK, (void *)&ifr) )
		$LOG(STS$K_ERROR, "Error set NETMASK for TUN, ioctl(SIOCSIFNETMASK)->%d, errno=%d", err, errno);



	return	STS$K_SUCCESS;
}



static	int	tun_shut	(
				)
{
struct ifreq ifr = {0};
int	err, sd = -1, fd = -1;

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = g_tunflags  /*IFF_TAP*/ | IFF_NO_PI | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, $ASCPTR(&g_tun), IFNAMSIZ);

	/* Allocate new /devtunX ... */
	if ( 0 > (fd = open("/dev/net/tun", O_RDWR)) )
		return	$LOG(STS$K_ERROR, "open(/dev/net/tun), errno=%d", errno);


	/* Disable persistence for the TUN device */
	if( err = ioctl(fd, TUNSETPERSIST, 0) )
		$LOG(STS$K_ERROR, "ioctl(TUNSETPERSIST)->%d, errno=%d", err, errno);

	/* Set initial state of the TUN - DOWN ... */
	if ( 0 > (sd = socket(AF_INET, SOCK_DGRAM, 0)) )
		$LOG(STS$K_FATAL, "socket(), errno=%d", errno);
	else if( err = ioctl(sd, SIOCGIFFLAGS, &ifr) )
		$LOG(STS$K_ERROR, "ioctl(%s, SIOCGIFFLAGS)->%d, errno=%d", ifr.ifr_name, err,  errno);
	else	{
		ifr.ifr_ifru.ifru_flags &= (~IFF_UP);

		if ( err = ioctl(sd, SIOCSIFFLAGS, &ifr) )
			$LOG(STS$K_ERROR, "ioctl(SIOCSIFFLAGS)->%d", err, errno);
		}

	close(sd);
	close(fd);

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
	ifr.ifr_flags = g_tunflags  /*IFF_TAP*/ | IFF_NO_PI | IFF_MULTI_QUEUE;
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
		if( (0 >  (status = poll(&pfd, 1, timespec2msec (delta)))) && (__ba_errno__ != EINTR) )
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

	if ( signo == SIGUSR2 )
		{
		atomic_flag_clear (&reset_by_external_flag);
		return;
		}

	if ( (signo == SIGTERM) || (signo == SIGINT) )
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
const int siglist [] = {SIGTERM, SIGINT, SIGUSR2, 0 /* 0 - EOL*/ };
int	i;

	atomic_flag_clear (&reset_by_external_flag);

	for ( i = 0; siglist[i]; i++)
		{
		if ( (signal(siglist[i], sig_handler)) == SIG_ERR )
			$LOG(STS$K_ERROR, "Error establishing handler for signal %d/%#x, error=%d", siglist[i], siglist[i], __ba_errno__);
		else	$IFTRACE(g_trace, "Set signal handler for #%d (%s)", siglist[i], strsignal(siglist[i]));
		}
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
int	status, len = 0, v_type = 0, seq = 0;
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
 *   DESCRIPTION: process has been received PONG request.
 *
 *   INPUT:
 *
 *	bufp:	A buffer with the PONG's PDU
 *	buflen:	A size of the PDU
 *
 *   IMPLICITE OUTPUT
 */
static int	do_pong	(
				void	*buf,
				int	 buflen
				)
{
int	status, len = 0, v_type = 0, inpseq = 0;
SVPN_PDU *pdu = (SVPN_PDU *) buf;
struct	timespec  rtt ={0}, now;
char	lobuf[64];

	/*
	 * Extract SEQUENCE attribute
	 */
	len = sizeof(inpseq);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_SEQ, &v_type, &inpseq, &len))) )
		$LOG(STS$K_WARN, "No attribute %#x", g_udp_sd, SVPN$K_TAG_SEQ);

	len = sizeof(rtt);
	if ( !(1 & (tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_TIME, &v_type, &rtt, &len))) )
		$LOG(STS$K_WARN, "No attribute %#x", g_udp_sd, SVPN$K_TAG_TIME);

	$IFTRACE(g_trace, "[#%d]Received PONG #%#x", g_udp_sd, inpseq);

	/* Check sequence */
	if ( g_outseq - inpseq )
		$LOG(STS$K_WARN, "PONG #%d is out of sequence (#%d)", g_inpseq, g_outseq);

	/* Compute RTT */
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);

	__util$sub_time(&now, &rtt, &g_rtt);


	/* Save last seen PONG's sequence for future using */
	g_inpseq = inpseq;

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
struct iphdr *iph;

	/* Place of the IP's Header in the network packet depending on TUN's mode */
	iph = g_tunflags & IFF_TAP ? &buf[ETH_HLEN] : buf;


	/* Open channel to TUN device */
	if ( !(1 & (rc = tun_open(&td))) )
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error open a channell to TUN device");

	/* We suppose to be use poll() on the TUN and UDP channels to performs
	 * I/O asyncronously
	 */
	pfd[1].fd = td;

	$IFTRACE(g_trace, "[#%d-#%d]Main loop ...", td, g_udp_sd);

	while  ( !g_exit_flag )
		{
		/*
		 *  We performs working only is signaling/data channel has been established,
		 * so we should check that g_state == SVPN$K_STATETUN, in any other case we hibernate execution until
		 * signal.
		 */

		if ( g_state != SVPN$K_STATETUN )
			{
			if ( rc = clock_gettime(CLOCK_REALTIME, &now) )
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
				$IFTRACE(g_trace, "Got control packet, req=%d, %d octets", pdu->req, rc);

				switch (pdu->req)
					{
					case	SVPN$K_REQ_PONG:
						do_pong(buf, rc);
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

			if ( rc != write(td, buf, rc) )
				$LOG(STS$K_ERROR, "[#%d-#%d]I/O error on TUN device, write(%d octets), errno=%d", td, g_udp_sd, rc, __ba_errno__);

			atomic_fetch_add(&g_stat.btunwr, rc);
			atomic_fetch_add(&g_stat.ptunwr, 1);
			}
#ifdef WIN32
		else if ( (0 >= rc) && (errno != WSAEINPROGRESS) )
#else
		else if ( (0 >= rc) ) // && (errno != EINPROGRESS) )
#endif
				{
				$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
						td, g_udp_sd, rc, pfd[0].revents, pfd[1].revents, __ba_errno__);
				break;
				}

		/* Retrieve data from TUN device -> send to UDP socket */
		if ( (pfd[1].revents & POLLIN) && (0 < (rc = read (td, buf, sizeof(buf)))) )
			{

			slen = sizeof(struct sockaddr_in);

			atomic_fetch_add(&g_stat.btunrd, rc);
			atomic_fetch_add(&g_stat.ptunrd, 1);


			/* TCP's MSS Fixup */
			if ( g_mss && (iph->protocol == IPPROTO_TCP) )
				{
				mss_fixup (iph, g_tunflags & IFF_TAP ?  rc - ETHER_HDR_LEN : rc , g_mss);
				}

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
			if ( (0 >= rc) ) // && (errno != EINPROGRESS) )
#endif
				$LOG(STS$K_ERROR, "[#%d-#%d]recv()->%d, UDP/TUN.revents=%08x/%08x, errno=%d",
						td, g_udp_sd, rc, pfd[0].revents, pfd[1].revents, __ba_errno__);

		}


	$IFTRACE(g_trace, "Terminated");
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
int	status, bufsz, adjlen = 0, buflen = 0, v_type = 0, ulen = 0, plen = 0, revlen = 0;
struct pollfd pfd = {g_udp_sd, POLLIN, 0 };
char	buf[SVPN$SZ_IOBUF], salt[SVPN$SZ_SALT], *bufp, sfrom[64] = {0}, user[SVPN$SZ_USER], pass[SVPN$SZ_PASS],
	digest[SVPN$SZ_DIGEST], rev[255] = {0};
SVPN_PDU *pdu = (SVPN_PDU *) buf;
struct sockaddr_in from = {0};
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
		return	$LOG(STS$K_ERROR, "[#%d]Autorization error", g_udp_sd);

	ulen = sizeof(user);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_USER, &v_type, user, &ulen)) )
		return	$LOG(STS$K_ERROR, "[#%d]No USERNAME in request", g_udp_sd);

	revlen = sizeof(rev);
	if ( !(1 & tlv_get (pdu->data, buflen - SVPN$SZ_PDUHDR, SVPN$K_TAG_REV, &v_type, rev, &revlen)) )
		$LOG(STS$K_WARN, "[#%d]No REVISION in request", g_udp_sd);


	$LOG(STS$K_INFO, "[#%d]Got LOGIN from  %.*s@%s:%d (%.*s), %d octets", g_udp_sd,
		 ulen, user, sfrom, ntohs(from.sin_port), revlen, rev, buflen);


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


	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TUNTYPE, SVPN$K_LONG, &g_tunflags, sizeof(g_tunflags), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;


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

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_PING, SVPN$K_LONG, &g_timers_set.t_ping.tv_sec, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_RETRY, SVPN$K_LONG, &g_timers_set.retry, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_IDLE, SVPN$K_LONG, &g_timers_set.t_idle.tv_sec, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TOTAL, SVPN$K_LONG, &g_timers_set.t_max.tv_sec, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TRACE, SVPN$K_LONG, &g_trace, sizeof(int), &adjlen);
	buflen += adjlen;
	bufsz -= adjlen;

	if ( g_trace )
		tlv_dump(pdu->data, buflen - SVPN$SZ_PDUHDR);

	/* Generate  HMAC */
	hmac_gen(pdu->digest, SVPN$SZ_DIGEST,
			pdu, SVPN$SZ_HASHED, pdu->data, buflen - SVPN$SZ_PDUHDR, $ASCPTR(&g_auth), $ASCLEN(&g_auth),
				NULL /* End-of-arguments marger !*/);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, &from)) )
		return	$LOG(STS$K_ERROR, "Error send ACCEPT to %s:$d", sfrom, ntohs(from.sin_port));

	$LOG(STS$K_SUCCESS, "[#%d]Sent ACCEPT to  %.*s@%s:%d, %d octets", g_udp_sd,
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
static int	do_ping	(
				int	 sd,
		struct	sockaddr_in	*to
				)
{
int	status, bufsz, adjlen = 0, buflen = 0, v_type = 0, ulen = 0, plen = 0;
char buf[SVPN$SZ_IOBUF], *bufp;
SVPN_PDU *pdu = (SVPN_PDU *) buf;
SHA1Context	sha = {0};
struct timespec now;

	g_outseq++;

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
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);

	if ( !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_TIME, SVPN$K_BBLOCK, &now, sizeof(now), &adjlen))) )
		return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);
	buflen += adjlen;
	bufsz -= adjlen;

	if ( !(1 & (status = tlv_put (&buf[buflen], bufsz, SVPN$K_TAG_SEQ, SVPN$K_LONG, &g_outseq, sizeof(g_outseq), &adjlen))) )
		return	$LOG(status, "[#%d]Error put attribute", g_udp_sd);
	buflen += adjlen;
	bufsz -= adjlen;

	if ( g_trace )
		tlv_dump(pdu->data, buflen - SVPN$SZ_PDUHDR);

	if ( !(1 & xmit_pkt (g_udp_sd, buf, buflen, to)) )
		return	$LOG(STS$K_ERROR, "[#%d]Error send PING #%#x", g_udp_sd, g_outseq);

	$IFTRACE(g_trace, "[#%d]Sent PING #%#x", g_udp_sd, g_outseq);

	return	STS$K_SUCCESS;
}


int	handle_cmd_args(int argc, char *argv[])
{
int	option, idx, optval;
struct option stat_opts[] = {
     {"stat",     optional_argument, &optval,  1 },
     {0, 0, 0,  0 }
 };


	/* Check command line options */
	while( (option = getopt_long(argc, argv, "vdo:", stat_opts, &idx)) >= 0 )
		{
		switch(option)
			{
			case 'o':
				__util$readconfig (optarg, optstbl);
				break;

			case 'd':
				g_trace = 1;
				break;

			case 'v':
				fprintf(stdout, "%s\n", __REV__);
				exit (0);

			case 'h':
			case '?':
				fprintf(stdout, help, argv[0], argv[0]);
				exit (0);
			}
		}

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
char	buf[1024];
struct timespec deltaonline = {0, 0}, now;

	handle_cmd_args(argc, argv);

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
		{
		tun_shut();
		return	g_exit_flag = $LOG(STS$K_ERROR, "Error allocating TUN device");
		}

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
	for ( idle_count = 0; !g_exit_flag; __util$rewindlogfile(g_logsize) )
		{
		if ( !atomic_flag_test_and_set(&reset_by_external_flag) )
			$LOG(STS$K_INFO, "Resetting has been initated by sTunMon Control Process");

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
			/* Reset seession specific counters */
			idle_count = 0;
			g_stat_last = g_stat = g_stat_zero;
			deltaonline.tv_sec = deltaonline.tv_nsec = 0;
			g_outseq = g_inpseq = 0;
			g_input_count = 0;


			exec_script(&g_linkup);

			backlog_update (&g_client_sk.sin_addr);

			g_state = SVPN$K_STATETUN;
			$LOG(STS$K_INFO, "IP: %s is ONLINE", inet_ntop(AF_INET, &g_client_sk.sin_addr, buf, sizeof(buf)));

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

			/* Write session statistic record */
			stat_write();

			g_state = SVPN$K_STATECTL;
			$LOG(STS$K_INFO, "IP: %s is OFFLINE", inet_ntop(AF_INET, &g_client_sk.sin_addr, buf, sizeof(buf)));

			continue;
			}


		if ( g_state == SVPN$K_STATETUN )
			{

			/* Check that we need to send PING request to performs that data channel is alive */
			if ( !atomic_load(&g_input_count) )
				{
				if ( (g_outseq - g_inpseq) > g_timers_set.retry )
					{
					$LOG(STS$K_ERROR, "Heartbeat lost detected (PING #%d - PONG #%d)", g_outseq, g_inpseq);
					g_state = SVPN$K_STATEOFF;
					continue;
					}
				else	{
					$IFTRACE(g_trace, "No inputs from remote SVPN client, idle count is %d", idle_count);
					do_ping(g_udp_sd, &g_client_sk);

					if ( (g_outseq - g_inpseq) > 1 )
						$LOG(STS$K_WARN, "Heartbeat lost detected (#%d/#%d)", (g_outseq - g_inpseq) - 1, g_timers_set.retry);
					}
				}
			else	{
				$IFTRACE(g_trace, "Inputs counter is %d", g_input_count);
				idle_count = 0;
				}

			atomic_store(&g_input_count, 0); /* Reset inputs counter */



			if ( g_deltaonline && ((g_outseq - g_inpseq) <= 1) )
				{
				struct timespec ts = {g_deltaonline, 0};

				#ifdef WIN32
					timespec_get(&now, TIME_UTC);
				#else
					clock_gettime(CLOCK_REALTIME, &now);
				#endif

				if ( __util$iszero(&deltaonline, sizeof(deltaonline)) )
					__util$add_time(&now, &ts, &deltaonline);
				else if ( 0 < __util$cmp_time(&now, &deltaonline) )
					{
					$LOG(STS$K_INFO, "IP: %s is still ONLINE, RTT %5.2f ms", inet_ntop(AF_INET, &g_client_sk.sin_addr, buf, sizeof(buf)),
						((float) g_rtt.tv_nsec)/(1000.0*1000.0) );

					__util$add_time(&now, &ts, &deltaonline);


					stat_write();
					}
				}



			}


		/* Just hibernate for some interval to reduce consuming CPU ... */
		status = g_timers_set.t_ping.tv_sec;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32

		$IFTRACE(g_trace, "TUN RD: %llu packets, %llu octets, WR: %llu packets, %llu octets", g_stat.ptunrd, g_stat.btunrd, g_stat.ptunwr, g_stat.btunwr);
		$IFTRACE(g_trace, "UDP RD: %llu packets, %llu octets, WR: %llu packets, %llu octets", g_stat.ptunrd, g_stat.btunrd, g_stat.ptunwr, g_stat.btunwr);

		/* Update state counters
		 * Do we reach limit ?!
		 */
		stat_update();

		if ( g_data_volume_limit && (g_data_volume > g_data_volume_limit) )
			g_exit_flag = $LOG(STS$K_FATAL, "Data Volume limit (%llu > %llu) is reached! Set exit_flag!", g_data_volume, g_data_volume_limit);
		}

	set_tun_state(0);		/* Down the tunX */
	tun_shut();
	exec_script(&g_linkdown);	/* Switch /dev/tunX DOWN */
	stat_write();			/* Write session statistic record */

	/* Get out !*/
	$LOG(STS$K_INFO, "Exit with exit_flag=%d!", g_exit_flag);

	return	STS$K_SUCCESS;
}
