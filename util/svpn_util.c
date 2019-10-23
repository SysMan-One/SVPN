#define	__MODULE__	"SVPUTL"
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
**  DESCRIPTION: Report generation utility.
**
**  USAGE:
**		$ ./SVPN_UTIL	[options]
**
**			-v, -?, -h, -o <file>, -d
**
**			/CONFIG=<configuration_file>
**			/TRACE
**			/SHOW[STAT]=<statkwd>
**				statkwd:	L[ive]
**						I[PBacklog]
**						Y[year]
**						M[onthly]
**						D[aily]
**						H[ourly]
**
**
**  AUTHORS: Ruslan R. (The BadAss SysMan) Laishev
**
**  CREATION DATE:  20-OCT-2019
**
**  MODIFICATION HISTORY:
**
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
#include	<libgen.h>

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
#include	<unistd.h>
#include	<netinet/ip.h>
#include	<arpa/inet.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<linux/limits.h>
#include	<stdatomic.h>
#include	<sys/types.h>
#include	<dirent.h>
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
static	int	g_exit_flag = 0, 	/* Global flag 'all must to be stop'	*/
	g_trace = 0,			/* A flag to produce extensible logging	*/
	g_lenbacklog = 5;

ASC	g_confspec = {0},
	g_fstat = {0}, g_dstat = {0},
	g_ipbacklog = {0},
	g_show = {0},
	g_tun = {$ASCINI("tunX:")};	/* OS specific TUN device name		*/

typedef struct	__svpn_stat
	{
	struct	tm	ts;
	unsigned long long
		btunrd,			/* Octets counters	*/
		btunwr,
		bnetrd,
		bnetwr,
		ptunrd,			/* Packets counters	*/
		ptunwr,
		pnetrd,
		pnetwr;
} SVPN_STAT;


const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&g_confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("trace"),	&g_trace, 0,		OPTS$K_OPT},
	{$ASCINI("stat"),	&g_fstat, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("ipbacklog"),	&g_ipbacklog, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("show"),	&g_show, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("devtun"),	&g_tun, ASC$K_SZ,	OPTS$K_STR},

	OPTS_NULL
};


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
int	backlog_show	( void )
{
int	fd = -1, status, i;
struct in_addr iparr [SVPN$SZ_MAXIPBLOG] = {0};
char	ipbuf[32];


	if ( !$ASCLEN(&g_ipbacklog) )
		return	$LOG(STS$K_ERROR, "No IP Backlog file has been specified");

	if ( 0 > (fd = open($ASCPTR(&g_ipbacklog), O_RDONLY)) )
		return	$LOG(STS$K_ERROR, "IP Backlog file open(%s), errno=%d", $ASCPTR(&g_ipbacklog), errno);


	if ( 0 > (status = read(fd, iparr, sizeof(iparr))) )
		status = $LOG(STS$K_ERROR, "IP Backlog file read(%s), errno=%d", $ASCPTR(&g_ipbacklog), errno);

	else	status = STS$K_SUCCESS;

	close(fd);

	if ( !(1 & status) )
		return;

	for ( i = 1; i <= g_lenbacklog; i++)
		{
		inet_ntop(AF_INET, &iparr[i], ipbuf, sizeof(ipbuf));
		$LOG(STS$K_INFO, "#%02d : IP-%s", i, ipbuf);
		}

	return	status;
}



static	int	config_process	(int argc, char **argv)
{
int	status = STS$K_SUCCESS, bits;
char	*cp, *saveptr = NULL, *endptr = NULL, ia [ 64 ], mask [ 64], fspec[255];
ASC	l_fstat = g_fstat;

	if ( $ASCLEN(&g_ipbacklog) )
		{
		sscanf($ASCPTR(&g_ipbacklog), "%[^,\n],%[^\n]" , fspec, mask);
		__util$str2asc (fspec, &g_ipbacklog);

		g_lenbacklog = atoi(mask);

		$IFTRACE(g_trace, "IPBACKLOG=%.*s, LENIPBACKLOG=%d", $ASC(&g_ipbacklog), g_lenbacklog);
		}

	if ( !$ASCLEN(&l_fstat) || !(cp = dirname($ASCPTR(&l_fstat))) )
		cp = dirname(argv[0]);

	__util$str2asc (cp, &g_dstat);

	return	STS$K_SUCCESS;
}


/*
 * DESCRIPTION: Display statistic on the screen depending on the option 'what'.
 *
 * IMPLICITE INPUT:
 *	stat_file_path
 *
 * INPUT:
 *	fmask:	A file mask to select stat files to be processed
 *
 * OUTPUT:
 *	strec:	A buffer to accept readed record
 *
 * RETURN:
 *	condition code
 */
int	stat_read_rec	(
		char		*fmask,
		SVPN_STAT	*strec
			)
{
static	status, fd = -1;
static	DIR *dir = NULL;
struct  dirent *dent = NULL;
static char	fspec[NAME_MAX];

	/* At first call we need to open directory to be scanned for .stat files */
	if ( !dir )
		{
		/* Preparing for  scanning stat' directory for files */
		if ( !(dir = opendir($ASCPTR(&g_dstat))) )
			return	$LOG(STS$K_FATAL, "Opening directory '%s', errno=%d", $ASCPTR(&g_dstat), errno);
		}

	/* If there is no open file - get next directory's entry - check for pattern, open for reading. */
	if ( 0 > fd )
		{
		while ( dent = readdir(dir) )
			{
			//$IFTRACE(g_trace, "Matching: '%s' against mask '%s'...", dent->d_name, fmask);

			/* Check against pattern ... */
			if ( 1 & __util$pattern_match(dent->d_name, fmask) )
				{
				/* Make full path to file to be opened */
				sprintf(fspec, "%s/%s", $ASCPTR(&g_dstat), dent->d_name);

				if ( 0 < (fd = open(fspec, O_RDONLY, 0)) )
					{
					//$IFTRACE(g_trace, "Process file: %s ...", fspec);
					break; /* Success! Out from loop */
					}

				$LOG(STS$K_FATAL, "Error open '%s' - skip, errno=%d", fspec, errno);
				}
			}

		if ( !dent )
			{
			closedir(dir);
			fd = -1;

			return	STS$K_WARN; //$LOG(STS$K_WARN, "No more files");
			}
		}

	/* Check current status */
	if ( fd < 0 )
		return	STS$K_WARN; //$LOG(STS$K_WARN, "No more files");

	if ( !(status = read (fd, strec, sizeof(SVPN_STAT))) )
		{
		/* 0 - EOF, close current file, set fd to -1 */
		close(fd );
		fd = -1;

		return	stat_read_rec (fmask, strec);
		}
	else if ( status < 0 )
		return	$LOG(STS$K_FATAL, "Error reading file '%s', errno=%d", fspec, errno);


	//$IFTRACE(g_trace, "Read %d octets from '%s', HH:%02d", status, fspec, strec->ts.tm_hour);

	/* Success! */
	return	STS$K_SUCCESS;
}



/*
 * DESCRIPTION: Format given counter to <units> with appropriate prefix, like:
 *	1024000 -> 100 K<units
 *
 * INPUT:
 *	count:	a value to be converted
 *	unit:	a unit of measurement
 *
 * OUTPUT:
 *	out:	a buffer to accept result string
 *	outsz:	a size of buffer
 *
 * RETURN:
 *	length of the formated string
 */
const char	unit_octets [] = "b",
		unit_packets [] = "pkts";

static inline int	__fao_traffic	(
		unsigned long long	count,
			char		*out,
			int		outsz,
			char		*unit
				)
{
int	outlen = 0;
const unsigned long long kilo = 1024ULL;
double	fcount = count;


	if ( !(count/kilo) )
		outlen = snprintf(out, outsz, "%4u %s", (unsigned) count, unit);
	else if ( !(count/(kilo*kilo)) )
		outlen = snprintf(out, outsz, "%4.2f K%s", fcount/kilo, unit);
	else if ( !(count/(kilo*kilo*kilo)) )
		outlen = snprintf(out, outsz, "%4.2f M%s",  fcount/(kilo*kilo), unit);
	else if ( !(count/(kilo*kilo*kilo*kilo)) )
		outlen = snprintf(out, outsz, "%4.2f G%s",  fcount/(kilo*kilo*kilo), unit);

	return	outlen;
}


/*
 * DESCRIPTION: Display statistic on the screen depending on the option 'what'.
 *
 * INPUT:
 *	what:	statistic option: 'live', 'hourly', 'daily', 'monthly, 'year', 'ip'
 *
 * OUTPUT:
 *	NONE
 *
 * RETURN:
 *	NONE
 */
typedef struct __stat_vec__ {			/* Structure to keep a live statistic		*/
	double	bwbnetrd, bwbnetwr, bwbtunrd, bwbtunwr,
		bwpnetrd, bwpnetwr, bwptunrd, bwptunwr;
	struct timespec	rtt;			/* A round trip time of the control channel, msec*/
} STAT_VEC;


int	stat_show	(char *what)
{
int	fd = -1, hh, dd, mm, status = 0;
char	sname[MAXNAMLEN] = {0}, buf1[128] = {0}, buf2[128] = {0}, buf3[128] = {0}, buf4[128] = {0},
	*cp;

SVPN_STAT strec = {0};
STAT_VEC stvec = {0};
unsigned long long	nsnd, nrcv, tsnd, trcv;
struct tm now;

	/* Sanity check */
	what = what ? what : "l";

	if ( *what == 'i' )		/* Dump IP Backlog file	*/
		{
		backlog_show ();
		return	STS$K_SUCCESS;
		}

	if ( *what == 'l' )		/* Live statistic	*/
		{
		/* FIFO channel to put statistic vector */
		snprintf(sname, sizeof(sname) - 1, "/tmp/stun-%.*s", $ASC(&g_tun));

		if ( 0 > (fd = open(sname, O_RDONLY /* O_NONBLOCK*/ )) )
			return	$LOG(STS$K_ERROR, "open(%s), errno=%d", sname, errno);

		$LOG(STS$K_INFO, " ---- Live stat for %.*s----", $ASC(&g_tun));

		while ( 0 < (status = read(fd, &stvec, sizeof(STAT_VEC))) )
			{
			__fao_traffic (stvec.bwbnetrd, buf1, sizeof(buf1), unit_octets);
			__fao_traffic (stvec.bwbnetwr, buf2, sizeof(buf2), unit_octets);

			$LOG(STS$K_INFO, "%.*s   BW Rx: %s/s   BW Tx: %s/s, RTT: %02d.%d",
				$ASC(&g_tun), buf1, buf2, stvec.rtt.tv_sec, stvec.rtt.tv_nsec/(1000*1000) );
			}

		close (fd);
		return	STS$K_SUCCESS;
		}


	/* Prepare file mask to matching */
	__util$timbuf (NULL, &now);
	cp = basename( $ASCPTR(&g_fstat) );

	snprintf(sname, sizeof(sname) - 1, "%s-%04d-%%%%", cp ? cp : "*", now.tm_year);


	switch (*what)
		{
		case	'h':	/* from begin of day	*/


			$LOG(STS$K_INFO, " ---- Hourly stat for %.*s ----", $ASC(&g_tun));

			for ( hh = nsnd = nrcv = tsnd = trcv = 0;  1 & (status = stat_read_rec(sname, &strec)); )
				{
				if ( (now.tm_mday != strec.ts.tm_mday) || (now.tm_mon != strec.ts.tm_mon) )
					continue;

				if ( hh != strec.ts.tm_hour )
					{
					__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
					__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
					__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
					__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

					$LOG(STS$K_INFO, "%02d:00  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", hh, buf1, buf2, buf3, buf4);

					/* Switch to next hour, reset local counters */
					hh = strec.ts.tm_hour;
					nsnd	= strec.bnetwr;
					nrcv	= strec.bnetrd;
					tsnd	= strec.btunwr;
					trcv	= strec.btunrd;

					continue;
					}

				nsnd	+= strec.bnetwr;
				nrcv	+= strec.bnetrd;
				tsnd	+= strec.btunwr;
				trcv	+= strec.btunrd;
				}

			if ( nsnd  || nrcv )
				{
				__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
				__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
				__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
				__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

				$LOG(STS$K_INFO, "%02d:00  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", hh, buf1, buf2, buf3, buf4);
				}

			break;

		case	'd':	/* from begin of month	*/
			$LOG(STS$K_INFO, " ---- Daily stat for %.*s----", $ASC(&g_tun));

			for ( dd = 1, nsnd = nrcv = tsnd = trcv = 0; 1 & (status = stat_read_rec(sname, &strec)); )
				{
				if ( (now.tm_mon != strec.ts.tm_mon) )
					continue;

				if ( dd != strec.ts.tm_mday )
					{
					__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
					__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
					__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
					__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

					$LOG(STS$K_INFO, "%02d-%02d  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", dd, strec.ts.tm_mon, buf1, buf2, buf3, buf4);

					/* Switch to next day, reset local counters */
					dd = strec.ts.tm_mday;
					nsnd	= strec.bnetwr;
					nrcv	= strec.bnetrd;
					tsnd	= strec.btunwr;
					trcv	= strec.btunrd;

					continue;
					}

				nsnd	+= strec.bnetwr;
				nrcv	+= strec.bnetrd;
				tsnd	+= strec.btunwr;
				trcv	+= strec.btunrd;

				}

			if ( nsnd  || nrcv )
				{
				__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
				__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
				__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
				__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

				$LOG(STS$K_INFO, "%02d-%02d  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", dd, strec.ts.tm_mon, buf1, buf2, buf3, buf4);
				}

			break;

		case	'm':	/* from begin of year	*/
			$LOG(STS$K_INFO, " ---- Monthly for %.*s ----", $ASC(&g_tun));

			for ( mm = 1, nsnd = nrcv = tsnd = trcv = 0; 1 & (status = stat_read_rec(sname, &strec)); )
				{
				if ( mm != strec.ts.tm_mon )
					{
					__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
					__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
					__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
					__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

					$LOG(STS$K_INFO, "%02d-%04d  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", mm, strec.ts.tm_year, buf1, buf2, buf3, buf4);

					/* Switch to next day, reset local counters */
					mm = strec.ts.tm_mon;
					nsnd	= strec.bnetwr;
					nrcv	= strec.bnetrd;
					tsnd	= strec.btunwr;
					trcv	= strec.btunrd;

					continue;
					}
				nsnd	+= strec.bnetwr;
				nrcv	+= strec.bnetrd;
				tsnd	+= strec.btunwr;
				trcv	+= strec.btunrd;
				}

			if ( nsnd  || nrcv )
				{
				__fao_traffic (nrcv, buf1, sizeof(buf1), unit_octets);
				__fao_traffic (nsnd, buf2, sizeof(buf2), unit_octets);
				__fao_traffic (trcv, buf3, sizeof(buf3), unit_octets);
				__fao_traffic (tsnd, buf4, sizeof(buf4), unit_octets);

				$LOG(STS$K_INFO, "%02d-%04d  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", mm, strec.ts.tm_year, buf1, buf2, buf3, buf4);
				}

			break;

		case	'y':	/* --//--	year	*/
			$LOG(STS$K_INFO, " ---- Year stat for %.*s ----", $ASC(&g_tun));

			for ( nsnd = nrcv = tsnd = trcv = 0; 1 & (status = stat_read_rec(sname, &strec)); )
				{
				nsnd	+= strec.bnetwr;
				nrcv	+= strec.bnetrd;
				tsnd	+= strec.btunwr;
				trcv	+= strec.btunrd;
				}

			__fao_traffic (strec.bnetrd, buf1, sizeof(buf1), unit_octets);
			__fao_traffic (strec.bnetwr, buf2, sizeof(buf2), unit_octets);
			__fao_traffic (strec.btunrd, buf3, sizeof(buf3), unit_octets);
			__fao_traffic (strec.btunwr, buf4, sizeof(buf4), unit_octets);

			$LOG(STS$K_INFO, " %04d  --  NET Rx: %s   Tx: %s, TAP Rx: %s   Tx: %s", strec.ts.tm_year, buf1, buf2, buf3, buf4);
			break;

		default:
			$LOG(STS$K_ERROR, "Unsupported option '%s'", what);
		}


	fflush(stdout);

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

	$LOG(STS$K_INFO, "Rev: " __IDENT__ "/"  __ARCH__NAME__   ", (built  at "__DATE__ " " __TIME__ " with CC " __VERSION__ ")");

	/*
	 * Process command line arguments
	 */
	__util$getparams(argc, argv, optstbl);


	if ( g_trace )
		__util$showparams(optstbl);

	/* Additionaly parse and validate configuration options  */
	config_process(argc, argv);

	if ( $ASCLEN(&g_show) )
		stat_show ( $ASCPTR(&g_show) );


	return	STS$K_SUCCESS;
}
