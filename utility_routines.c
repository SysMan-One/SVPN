#define	__MODULE__	"UTIL$"

/*
**  Abstract: General purpose and utility routines
**
**  Author: Ruslan R. Laishev
**
**  Creation date: 4-SEP-2017
**
**  Modification history:
**
**	25-SEP-2017	RRL	Added __util$log2buf(): format a message into the given buffer.
**
**	 5-OCT-2017	RRL	Added __util$syslog() : format and send a message to SYSLOG server;
**				recoding __util$setlogfile -> util$deflog() to accept a SYSLOG IP address
**				as argument;
**
**	 6-OCT-2017	RRL	Adopted __util$syslog() for M$ Windows.
**
**	12-OCT-2017	RRL	Added conditional blocks on the __SYSLOG__;
**				other changes to improve stability of code;
**
**	27-APR-2018	RRL	Changed handling of the OPTS$K_INT to allow accept decimals and hexadecimals,
**				replaced atoi() with strtoul().
**
**	28-MAY-2018	RRL	Correct text of message.
**
**	 6-AUG-2018	SYS	Added a support for 64-bits long in the routines related option's processing.
**
**	10-NOV-2018	RRL	Recoded logging related routines to use 'fd' instead of FILE;
**
**	12-NOV-2018	RRL	Changed __util$rewindlog() to truncate file at begin after rewinding.
**
**	23-NOV-2018	RRL	Fixed lseek()->29 on STDOUT_FILENO in the __util$rewindlogfile();
*/


#ifdef	_WIN32
#define _CRT_SECURE_NO_WARNINGS	1

#include        <winsock2.h>
#include	<windows.h>

#include	<sys/timeb.h>
#include	<stdio.h>



#endif

#include	<stddef.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	<time.h>
#include	<ctype.h>
#include	<string.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>

#ifndef	_WIN32
#include	<unistd.h>
//#include	<execinfo.h>
#include	<arpa/inet.h>
#include	<syslog.h>

#define	PID_FMT	"%6d"


	#define	TIMSPECDEVIDER	1000000	/* Used to convert timespec's nanosec tro miliseconds */
#elif	_WIN32
	#define	gettid()	GetCurrentThreadId()
	//#define	gettid()	GetCurrentProcessId()
	#define	TIMSPECDEVIDER	1000	/* Used to convert timeval's microseconds to miliseconds */
	#define	PID_FMT	"%6d"
#else
	#define	gettid()	(0xDEADBEEF)
#endif

#ifndef	__TRACE__
#define		__TRACE__	/* Enable $TRACE facility macro				*/
#endif

#include	"utility_routines.h"


#ifndef	WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored  "-Wparentheses"
#endif
int	logoutput = STDOUT_FILENO;	/* Default descriptor for default output device		*/

struct sockaddr_in slogsock;	/* SYSLOG Host socket					*/

#ifndef	WIN32
#include	<features.h>

#ifndef	_GNU_SOURCE
#define	_GNU_SOURCE	1
#endif

#include	<sys/syscall.h>

static inline pid_t	gettid(void)
{
	return	syscall ( SYS_gettid );
}
#endif





/*
 *
 *  Description: a simplified analog of the C RTL syslog() routine is supposed to used to
 *	format and send a message directly to IP (has been defined by $deflog();
 *
 *  Usage:
 *	__util$deflog(NULL, "172.28.4.112");
 *	...
 *	char msg [] = "GAMEOVER, all your base are belong to us";
 *	__util$syslog(LOG_KERN, LOG_DEBUG, "NOXBIT", msg, sizeof(msg));
 *
 *  Input:
 *	fac:	SYSLOG Facility code, see LOG_* constants
 *	pri:	SYSLOG Severity code, see LOG_* constants
 *	tag:	A tag string - a part of the MSG part :-)
 *	msg:	message buffer to be send
 *	msglen:	message length
 *
 *
 *  Return:
 *	SS$_NORMAL
 *
 */

unsigned	__util$syslog
		(
		int		fac,
		int		sev,
		const char *	tag,
		const char *	msg,
		int		msglen
		)
{
static int	sd = -1;
char	buf[128];

#ifdef	_WIN32

WSAMSG msg_desc = { 0 };
WSABUF   bufv[] = {{buf, 0}, {msg, msglen}};

#else
struct	iovec bufv[] = {{buf, 0}, {msg, msglen}};
struct	msghdr  msg_desc = {0};
#endif


	if ( sd == -1 )
		{
		/*
		inet_aton("172.28.4.112", &slogsock.sin_addr);
		slogsock.sin_port = htons(514);
		slogsock.sin_family = AF_INET;
		*/
#ifdef	_WIN32
		WSADATA wsa_data;
		int status;

		if ( status = WSAStartup(MAKEWORD(2,2), &wsa_data) )
			{
			perror("WSAstartup");
			abort();
			}

#endif
		if ( 0 > (sd = socket(AF_INET, SOCK_DGRAM, 0)) )
			{
			perror("socket");
			return	STS$K_ERROR;
			}
		}

	/* Prepare the msghdr structure */
#ifdef	_WIN32
	msg_desc.name = &slogsock;
	msg_desc.namelen = sizeof(slogsock);

	msg_desc.lpBuffers = (void *) &bufv;
	msg_desc.dwBufferCount = sizeof(bufv)/sizeof(bufv[0]);

	/* Form <priority + severity> part, add the tag field */
	bufv[0].len = sprintf(buf, "<%d> %s: ", fac  + sev, tag);

	if ( 0 >  WSASendMsg (sd, &msg_desc, 0, 0, 0, 0) )
		{
		perror("sendto");
		return	STS$K_ERROR;
		}


#else
	msg_desc.msg_name = &slogsock;
	msg_desc.msg_namelen = sizeof(slogsock);

	msg_desc.msg_iov = (void *) &bufv;
	msg_desc.msg_iovlen = sizeof(bufv)/sizeof(bufv[0]);

	/* Form <priority + severity> part, add the tag field */
	bufv[0].iov_len = sprintf(buf, "<%d> %16s: ", fac  + sev, tag);
	if ( 0 >  sendmsg (sd, &msg_desc, 0) )
		{
		perror("sendto");
		return	STS$K_ERROR;
		}

#endif


	return	STS$K_SUCCESS;
}

/*
 *
 *  Description: out to the current SYS$OUTPUT option's name  and values.
 *
 *  Input:
 *
 *	opts:	options' table, address of array terminated by 'NUL' entry
 *
 *
 *  Return:
 *	SS$_NORMAL
 *
 */
int	__util$showparams	(
			OPTS *	opts
			)
{
OPTS	*optp;

	for (optp = opts; $ASCLEN(&optp->name); optp++)
		{
		switch ( optp->type )
			{
			case	OPTS$K_PORT:
				$LOG(STS$K_INFO, "%.*s = %d (0x%04.4x)", $ASC(&optp->name),
					 *((unsigned short *) optp->ptr), *((unsigned short *) optp->ptr));
				break;

			case	OPTS$K_IP4:
				$LOG(STS$K_INFO, "%.*s = %s", $ASC(&optp->name), inet_ntoa( *((struct in_addr *) optp->ptr)) );
				break;

			case	OPTS$K_OPT:
				$LOG(STS$K_INFO, "%.*s = %s", $ASC(&optp->name), * ((int *)optp->ptr) ? "ON" : "OFF");
				break;

			 case	OPTS$K_INT:
				switch ( optp->sz )
					{
					case (sizeof (unsigned long long)):
						$LOG(STS$K_INFO, "%.*s = %llu (%#llx)", $ASC(&optp->name), *((unsigned long long *) optp->ptr),
							*((unsigned long long *) optp->ptr));
						break;

					case (sizeof (unsigned short)):
						$LOG(STS$K_INFO, "%.*s = %d (%#x)", $ASC(&optp->name), *((unsigned short *) optp->ptr),
							*((unsigned short *) optp->ptr));
						break;

					default:
						$LOG(STS$K_INFO, "%.*s = %d (%#x)", $ASC(&optp->name), *((int *) optp->ptr), *((int *) optp->ptr));
						break;
					}
				break;

			case	OPTS$K_STR:
				$LOG(STS$K_INFO, "%.*s[0:%u] ='%.*s'", $ASC(&optp->name), ((ASC *)optp->ptr)->len, $ASC(optp->ptr));
				break;

			case	OPTS$K_PWD:
				$LOG(STS$K_INFO, "%.*s[0:%u] ='<password>'", $ASC(&optp->name), ((ASC *)optp->ptr)->len, $ASC(optp->ptr));
				break;

			}
		}

	return	STS$K_SUCCESS;
}


/*
 *
 *  Description: processing command line arguments to extract parameters according of options table;
 *		performs basic syntax checking, copy options values to local storage for using at run-time.
 *  Input:
 *	fconf:	A configuration file to be processed
 *	opts:	options' table, address of array terminated by 'NUL' entry
 *
 *  Output:
 *	fills the 'runparams' vector by option
 *
 *  Return:
 *	SS$_NORMAL
 *
 */
int	__util$readconfig	(
			char *	fconf,
			OPTS *	opts
			)
{
int	i, argslen;
FILE	*finp = stdin;
char	*argp, *valp, buf[256];
OPTS	*optp;

	/*
	 * Is the configuration file has been specified ?
	 */
	if ( fconf && (*fconf) )
		{
		if ( !(finp = fopen(fconf, "r")) )
			{
			$LOG(STS$K_FATAL, "Error open file '%s', errno = %d", fconf, errno);
			return	STS$K_SUCCESS;
			}
		}

	/*
	* We expect to see opts in form: -<options_name>=<options_value>
	*/
	for ( i = 1; fgets(buf, sizeof(buf), finp); i++ )
		{
		if ( !__util$uncomment(buf, (int) strlen(buf), '!') )
			continue;

		if ( !__util$trim(buf, (int) strlen(buf)) )
			continue;

		if ( (*(argp = buf) != '-') && (*(argp = buf) != '/') )
			{
			$LOG(STS$K_ERROR, "%s : %d : Option must be started with a '-', skip : '%s'", fconf, i, buf);
			continue;
			}

		if ( valp = strchr(++argp, '=') )
			{
			argslen = (int) (valp - argp);
			valp++;
			}
		else	{
			argslen = (int) strlen(argp);
			valp = NULL;
			}


		/*
		* Compare a given from command line option name against options list,
		* we expect that options list is terminated by zero-length entry.
		*
		* We allow an shortened keywords but it can be a reao of conflicts.
		*/
		for (optp = opts; $ASCLEN(&optp->name); optp++)
			{
#if _WIN32
			if ( !(_strnicmp (argp, $ASCPTR(&optp->name), $MIN(argslen, $ASCLEN(&optp->name)))) )
#else
			if ( !(strncasecmp (argp, $ASCPTR(&optp->name), $MIN(argslen, $ASCLEN(&optp->name)))) )
#endif
				break;
			}

		if ( !optp || !$ASCLEN(&optp->name) )
			{
			$LOG(STS$K_WARN, "%s : %d : Skip unrecognized or unused option", fconf, i);
			continue;
			}


		if ( valp && *valp)
			__util$trim (valp, (int) strlen(valp));

		switch ( optp->type )
			{
			case	OPTS$K_PORT:
				* ((unsigned short  *) optp->ptr) = (unsigned short) atoi(valp);
				break;

			case	OPTS$K_IP4:
#ifdef WIN32
				if ( ! ((*(long *) optp->ptr) =  inet_addr (valp)) )
#else
				if ( !inet_aton(valp, (struct in_addr *) optp->ptr) )
#endif
					$LOG(STS$K_ERROR, "%s : %d : Error conversion '%s' to IP4 address", fconf, i, valp);
				break;

			case	OPTS$K_OPT:
				* ((int *)optp->ptr) = 1;
				break;

			case	OPTS$K_INT:
				switch ( optp->sz )
					{
					char *endptr;

					case (sizeof (unsigned long long)):
						* ((unsigned long long *) optp->ptr) =  strtoull(valp, &endptr, 0);
						break;

					default:
						* ((int *) optp->ptr) =  strtoul(valp, &endptr, 0);
						break;

					}
				break;

			case	OPTS$K_PWD:
			case	OPTS$K_STR:
				((ASC *)optp->ptr)->len  = (unsigned char) strnlen(valp, sizeof(((ASC *)optp->ptr)->sts));
				memcpy( ((ASC *)optp->ptr)->sts, valp, ((ASC *)optp->ptr)->len);
				((ASC *)optp->ptr)->sts[((ASC *)optp->ptr)->len] = '\0';
				break;

			default:
				$LOG(STS$K_ERROR, "%s : %d : Unrecognized option's '%.*s' internal type : 0x%X", fconf, i, $ASC(&optp->name), optp->type);
			}
		}

	if ( finp && (finp != stdin) )
		fclose(finp);


	return	STS$K_SUCCESS;
}


/*
 *
 *  Description: processing command line arguments to extract parameters according of options table;
 *		performs basic syntax checking, copy options values to local storage for using at run-time.
 *  Input:
 *	argc:	an argument count
 *	argv:	an array of command line options
 *	opts:	options' table, address of array terminated by 'NUL' entry
 *
 *  Output:
 *	fills the 'runparams' vector by option
 *
 *  Return:
 *	SS$_NORMAL
 *
 */
int	__util$getparams	(
			int	argc,
			char *	argv[],
			OPTS *	opts
			)
{
int	i;
size_t	argslen;
char	*argp, *valp;
OPTS	*optp;

	/*
	* We expect to see opts in form:
	*	-<options_name>=<options_value>
	*  or
	*	/<options_name>=<options_value>
	*/
	for ( i = 1; i < argc; i++ )
		{
		/* Skip zero length strings	*/
		if ( !strlen (argv[i]) )
			continue;

		/* Check option designator	*/
		if ( (*(argp = argv[i]) != '-') && (*(argp = argv[i]) != '/') )
			{
			$LOG(STS$K_ERROR, "%d: Option must be started with '-' or '/', skip : '%s'", i, argv[i]);
			continue;
			}

		if ( valp = strchr(++argp, '=') )
			{
			argslen = valp - argp;
			valp++;
			}
		else	{
			argslen = strlen(argp);
			valp = NULL;
			}

		/*
		* Compare a given from command line option name against options list,
		* we expect that options list is terminated by zero-length entry.
		*
		* We allow an shortened keywords but it can be a reao of conflicts.
		*/
		for (optp = opts; $ASCLEN(&optp->name); optp++)
			{
			if ( argslen != $ASCLEN(&optp->name) )
				continue;

#if _WIN32
			if ( !(_strnicmp (argp, $ASCPTR(&optp->name), $MIN(argslen, $ASCLEN(&optp->name)))) )
#else
			if ( !(strncasecmp (argp, $ASCPTR(&optp->name), $MIN(argslen, $ASCLEN(&optp->name)))) )
#endif
				break;
			}

		if ( !optp || !$ASCLEN(&optp->name) )
			{
			$LOG(STS$K_ERROR, "%d : Skip unrecognized option: '%s'", i, argp);
			continue;
			}

		if ( valp && *valp)
			__util$trim (valp, (int) strlen(valp));

		switch ( optp->type )
			{
			case	OPTS$K_CONF:
				if ( optp->ptr )
					{
					/* Store name of configuration file	*/
					((ASC *)optp->ptr)->len  = (unsigned char) strnlen(valp, sizeof(((ASC *)optp->ptr)->sts));
					memcpy( ((ASC *)optp->ptr)->sts, valp, ((ASC *)optp->ptr)->len);
					((ASC *)optp->ptr)->sts[((ASC *)optp->ptr)->len] = '\0';
					}

				__util$readconfig (valp, opts);
				break;

			case	OPTS$K_PORT:
				* ((unsigned short  *) optp->ptr) = (unsigned short) atoi(valp);
				break;

			case	OPTS$K_IP4:
#ifdef WIN32
				if ( ! ((*(long *) optp->ptr) =  inet_addr (valp)) )
#else
				if ( !inet_aton(valp, (struct in_addr *) optp->ptr) )
#endif
					$LOG(STS$K_ERROR, "%d : Error conversion '%s' to IP4 address", i, valp);
				break;

			case	OPTS$K_OPT:
				* ((int *)optp->ptr) = 1;
				break;

			case	OPTS$K_INT:
				switch ( optp->sz )
					{
					char *endptr;

					case (sizeof (unsigned long long)):
						* ((unsigned long long *) optp->ptr) =  strtoull(valp, &endptr, 0);
						break;

					default:
						* ((int *) optp->ptr) =  strtoul(valp, &endptr, 0);
						break;

					}
				break;

			case	OPTS$K_PWD:
			case	OPTS$K_STR:
				((ASC *)optp->ptr)->len  = (unsigned char) strnlen(valp, sizeof(((ASC *)optp->ptr)->sts));
				memcpy( ((ASC *)optp->ptr)->sts, valp, ((ASC *)optp->ptr)->len);
				((ASC *)optp->ptr)->sts[((ASC *)optp->ptr)->len] = '\0';
				break;

			default:
				$LOG(STS$K_ERROR, "%d : Unrecognized option's '%.*s' internal type : 0x%X", i, $ASC(&optp->name), optp->type);
			}
		}

	return	STS$K_SUCCESS;
}


/*
 *++
 *  Description: dump byte array to sys$output in hex, is supposed to be called indirectly by $DUMPHEX macro.
 *
 * Input:
 *	__fi:	A file name or module name string
 *	__li:	Line number in the sourve file
 *	src:	A pointer to source buffer  do be dumped
 *	srclen:	A Length of the source buffer
 *
 * Output:
 *	NONE
 * Return:
 *	NONE
 *
 *--
 */
void	__util$dumphex	(
		char *	__fi,
		unsigned	__li,
		void *	src,
		unsigned short	srclen
			)
{
const char	lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u [%s\\%u] Dump of %u octets follows:"};
char	out[80];
unsigned char *srcp = (unsigned char *) src, low, high;
unsigned olen = 0, i, j;
struct tm _tm;
struct timespec now;

	/*
	** Out to buffer "DD-MM-YYYY HH:MM:SS.msec [<function>\<line>]" prefix
	*/
	____time(&now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	olen = sprintf (out, lfmt,
		_tm.tm_mday, _tm.tm_mon + 1, 1900 + _tm.tm_year,
		_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
		__fi, __li, srclen);

	/* Add <LF> at end of record*/
	out[olen++] = '\n';
	write (logoutput, out, olen );

	memset(out, ' ', sizeof(out));

	/*
	** Format variable part of string line
	*/
	for (i = 0; i < ((srclen / 16));  i++)
		{
		olen = sprintf(out, "\t+%04x:  ", i * 16);
		memset(out + olen, ' ', sizeof(out) - olen);

		for (j = 0; j < 16; j++, srcp++)
			{
			high = (*srcp) >> 4;
			low = (*srcp) & 0x0f;

			out[olen + j * 3] = high + ((high < 10) ? '0' : 'a' - 10);
			out[olen + j * 3 + 1] = low + ((low < 10) ? '0' : 'a' - 10);

			out[olen + 16*3 + 2 + j] = isprint(*srcp) ? *srcp : '.';
			}

		/* Add <LF> at end of record*/
		out[sizeof(out) - 1] = '\n';

		/* Write to file and flush buffer depending on severity level */
		write (logoutput, out, sizeof(out) );
		}

	if ( srclen % 16 )
		{
		olen = sprintf(out, "\t+%04x:  ", i * 16);
		memset(out + olen, ' ', sizeof(out) - olen);

		for (j = 0; j < srclen % 16; j++, srcp++)
			{
			high = (*srcp) >> 4;
			low = (*srcp) & 0x0f;

			out[olen + j * 3] = high + ((high < 10) ? '0' : 'a' - 10);
			out[olen + j * 3 + 1] = low + ((low < 10) ? '0' : 'a' - 10);

			out[olen + 16*3 + 2 + j] = isprint(*srcp) ? *srcp : '.';
			}

		/* Add <LF> at end of record*/
		out[sizeof(out) - 1] = '\n';

		/* Write to file and flush buffer depending on severity level */
		write (logoutput, out, sizeof(out) );
		}
}


/*
 *++
 *  Description: dump byte array to sys$output in hex, is supposed to be called indirectly by $DUMPHEX macro.
 *
 * Input:
 *	src:	A pointer to source buffer  do be dumped
 *	srclen:	A Length of the source buffer
 *	dst:
 *	dstsz:
 *	dstlen:
 *
 * Return:
 *	NONE
 *
 *--
 */
int	__util$faohex	(
		void *	src,
		unsigned short	srclen,
		char *	out,
		unsigned short	outsz
			)
{
unsigned char *srcp = (unsigned char *) src, low, high;
unsigned j;

	memset(out, ' ', outsz);

	for (j = 0; j < 16; j++, srcp++)
		{
		high = (*srcp) >> 4;
		low = (*srcp) & 0x0f;

		out[j * 3] = high + ((high < 10) ? '0' : 'a' - 10);
		out[j * 3 + 1] = low + ((low < 10) ? '0' : 'a' - 10);

		out[16*3 + 2 + j] = isprint(*srcp) ? *srcp : '.';
		}

	out[16*3 + 2 + j] = '\0';

	return	16*3 + 2 + j;
}








/*
 *++
 *  Description: print to sys$output a programm trace information, supposed to be called from
 *		$TRACE 	macro.
 *
 * Input:
 *	fmt:	A format string
 *	__fi:	A file name or module name string
 *	__li:	Line number in the source file
 *	...	Format string arguments
 * Output:
 *	NONE
 * Return:
 *	NONE
 *
 *--
 */

void	__util$trace	(
		const char *	fmt,
		const char *	__mod,
		const char *	__fi,
		unsigned	__li,
			...
			)
{
va_list arglist;

const char	lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " [%s\\%u] "},
	mfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " [%s\\%s\\%u] "};
char	out[1024];

unsigned olen;
struct tm _tm;
struct timespec now;

	/*
	** Out to buffer "DD-MM-YYYY HH:MM:SS.msec [<function>\<line>]" prefix
	*/
	____time(&now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	olen = __mod
		? sprintf (out, mfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
		_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
		(unsigned) gettid(), __mod, __fi, __li)
		: sprintf (out, lfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
		(unsigned) gettid(), __fi, __li);


	/*
	** Format variable part of string line
	*/
	va_start (arglist, __li);
	olen += vsnprintf(out + olen, sizeof(out) - olen, fmt, arglist);
	va_end (arglist);

	/* Add <LF> at end of record*/
	out[olen++] = '\n';

	/* Write to file and flush buffer */
	write (logoutput, out, olen );

#ifdef	__SYSLOG__
#ifndef	WIN32
	va_start (arglist, __li);
	olen = vsnprintf(out, sizeof(out), fmt, arglist);
	va_end (arglist);

	__util$syslog (LOG_USER, LOG_DEBUG, __mod, out, olen);

//	syslog( LOG_PID | ((sev & 1) ? LOG_INFO : LOG_ERR), "%.*s", olen, out);
#endif
#endif	/* __SYSLOG__ */

}

/*
 *
 */
const char severity[STS$K_UNDEF + 1][16] = { "-W: ", "-S: ", "-E: ", "-I: ", "-F: ", "-?: "};

unsigned	__util$log
			(
		const char *	fac,
		unsigned	sev,
		const char *	fmt,
			...
			)

{
va_list arglist;
const char lfmt [] = "%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " %%%s%3s";
char	out[1024];
unsigned olen, _sev = sev, opcom = sev & STS$K_SYSLOG;
struct tm _tm;
struct timespec now;

	/*
	** Some sanity check
	*/
	if ( !($ISINRANGE(sev, STS$K_WARN, STS$K_FATAL)) )
		sev = STS$K_UNDEF;

	/*
	** Out to buffer "DD-MM-YYYY HH:MM:SS.msec [<function>\<line>]<FAC>-E:" prefix
	*/
	____time(&now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	olen = sprintf (out, lfmt,
		_tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
		_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
		(unsigned) gettid(), fac, severity[sev]);

	va_start (arglist, fmt);
	olen += vsnprintf(out + olen, sizeof(out) - olen, fmt, arglist);
	va_end (arglist);

	/* Add <LF> at end of record*/
	out[olen++] = '\n';

	/* Write to file and flush buffer depending on severity level */
	write (logoutput, out, olen );


#ifndef	WIN32
	if ( opcom )
		{
		va_start (arglist, fmt);
		olen = vsnprintf(out, sizeof(out), fmt, arglist);
		va_end (arglist);

		syslog( LOG_PID | ((sev & 1) ? LOG_INFO : LOG_ERR), "%.*s", olen, out);
		}
#endif

	return	_sev;
}

/**
 * @brief __util$log2buf - format a message into the given output buffer
 * @param out
 * @param outsz
 * @param outlen
 * @param fac
 * @param sev
 * @param fmt
 */
unsigned	__util$log2buf
			(
		void	*	out,
		int		outsz,
		int	*	outlen,
		const char *	fac,
		unsigned	sev,
		const char *	fmt,
			...
			)

{
va_list arglist;
const char lfmt [] = "%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " %%%s%3s";
char	*__outbuf = (char *) out;
unsigned	_sev = sev;
struct tm _tm;
struct timespec now;

	/*
	** Some sanity check
	*/
	if ( !($ISINRANGE(sev, STS$K_WARN, STS$K_FATAL)) )
		sev = STS$K_UNDEF;

	/*
	** Out to buffer "DD-MM-YYYY HH:MM:SS.msec [<function>\<line>]<FAC>-E:" prefix
	*/
	____time(&now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	*outlen = sprintf (__outbuf, lfmt,
		_tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
		_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
		(unsigned) gettid(), fac, severity[sev]);

	va_start (arglist, fmt);
	*outlen += vsnprintf(__outbuf + *outlen, outsz - *outlen, fmt, arglist);
	va_end (arglist);

	/* Add NIL at end of record*/
	__outbuf[*outlen] = '\0';

	return	_sev;
}



unsigned	__util$logd
			(
		const char *	fac,
		unsigned	sev,
		const char *	fmt,
		const char *	__mod,
		const char *	__fi,
		unsigned	__li,
			...
			)

{
va_list arglist;
const char	lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " [%s\\%u] %%%s%3s"},
	mfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u " PID_FMT " [%s\\%s\\%u] %%%s%3s"};
char	out[1024];
unsigned olen, _sev = sev, opcom = sev & STS$K_SYSLOG;
struct tm _tm = {0};
struct timespec now = {0};

	sev &= ~STS$K_SYSLOG;

	/*
	** Some sanity check
	*/
	if ( !($ISINRANGE(sev, STS$K_WARN, STS$K_FATAL)) )
		sev = STS$K_UNDEF;

	/*
	** Out to buffer "DD-MM-YYYY HH:MM:SS.msec [<function>\<line>]-E-:" prefix
	*/
	____time(&now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	olen = __mod
		? sprintf (out, mfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
			(unsigned) gettid(), __mod, __fi, __li, fac, severity[sev])
		: sprintf (out, lfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900+_tm.tm_year,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/TIMSPECDEVIDER,
			(unsigned) gettid(), __fi, __li, fac, severity[sev]);

	va_start (arglist, __li);
	olen += vsnprintf(out + olen, sizeof(out) - olen, fmt, arglist);
	va_end (arglist);

	/* Add <LF> at end of record*/
	out[olen++] = '\n';

	/* Write to file and flush buffer depending on severity level */
	write (logoutput, out, olen );

#ifdef	__SYSLOG__
#ifndef	WIN32
	va_start (arglist, __li);
	olen = vsnprintf(out, sizeof(out), fmt, arglist);
	va_end (arglist);

	__util$syslog (LOG_USER, LOG_DEBUG, fac, out, olen);

//	syslog( LOG_PID | ((sev & 1) ? LOG_INFO : LOG_ERR), "%.*s", olen, out);
#endif
#endif	/* __SYSLOG__ */

	return	_sev;
}

/*
 * Description: Open a file to be used as default output file for $TRACE/$LOG/$DUMPHEX routines.
 *		File will be opene in shared for read and append mode!
 *
 *  Input:
 *	logfile:	a log file name string, ASCIZ
 *	sloghost:	a SYSLOG Host IP address, ASCIZ
 *
 *  Implicit output:	global logoutput variable
 *
 *  Return:
 *	condition status, see STS$ constants
 */
int	__util$deflog	(
		const char *	logfile,
		const char *	sloghost
				)
{
const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
int	fd = -1;

	/* Is there SYSLOG Host IP ? */
	if ( sloghost )
		{
		inet_pton(AF_INET, sloghost, &slogsock.sin_addr);
		slogsock.sin_port = htons(514);
		slogsock.sin_family = AF_INET;
		}

	if ( !logfile )
		return	STS$K_SUCCESS;

	if ( !*logfile)
		return	STS$K_SUCCESS;

	if ( 0 > (fd = open(logfile, O_RDWR | O_CREAT, mode)) )
		return	$LOG(STS$K_ERROR, "Error opening log file '%s', errno = %d.", logfile, errno);

	lseek(fd, 0L, SEEK_END);

	logoutput = fd;

	return $LOG(STS$K_SUCCESS, "Log file '%s' has been opened.", logfile);

}


/*
 * Description: compare a current file size with the 'limit' and rewind a current file pointer at beigining of file.
 *
 *  Return:
 *	condition status, see STS$ constants
 */
int	__util$rewindlogfile	(
			int	limit
				)
{
int	status;

	if ( (logoutput == STDOUT_FILENO) || !limit )
		return	STS$K_SUCCESS;

	if ( 0 > (status = lseek (logoutput, 0, SEEK_CUR)) )
		return	$LOG(STS$K_ERROR, "lseek() -> %d", errno);

	if ( status < limit )
		return	STS$K_SUCCESS;

	if ( 0 > (status = lseek(logoutput, 0L, SEEK_SET)) )
		$LOG(STS$K_ERROR, "fseek() -> %d", errno);

#ifndef	WIN32
	if ( 0  > (ftruncate(logoutput, status )) )
		$LOG(STS$K_ERROR, "ftruncate(%d, %d) -> %d", logoutput, status, errno);
#endif


	return	STS$K_SUCCESS;
}



/*
	http://util.deltatelecom.ru/ovms82src/debug/lis/strings.lis

				Source Listing                  19-NOV-2004 08:39:18  Compaq C V6.5-001-48BCD           Page 42
								 4-MAR-2003 15:31:10  $1$DGA1016:[DEBUG_2.SRC]STRINGS.C;1
*/

/*++***********************************************************************/
/*
 * FUNCTION : C_STR$pattern_match
 *
 * FUNCTIONALITY :
 *  This function is passed a pattern and a string to match against the
 *  pattern.  The pattern may contain wildcards (*,%), where '*' matches
 *  0 or more occurrences of anything, and '%' matches any one character.
 *  In addition, a '\' in the pattern string will translate the next
 *  character as literal.  This is a recursive routine.
 *
 * COMMUNICATION :
 *
 *  PROTOTYPE/PARAMETERS :
 *      (see below)
 *
 *  RETURN VALUE :
 *      int : success or failure
 *
 *  ERROR HANDLING :
 *
 * ALGORITHM :
 *  establish a pointer to the first character in the magic string
 *  and a pointer to the first character in the text string.
 *
 *   while there are still characters:
 *    If the current character in the magic string is not a wild card
 *    and they are different, then declare it a mismatch.  If they
 *    point to identical characters, then advance each pointer by one
 *    and go aroung the loop again.
 *
 *    If the magic string pointer points at a WILD_PERCENT, then advance
 *    both pointers, regardless of what's in the test string.
 *
 *    If the magic pointer points to WILD_STAR, then try matching the
 *    rest of the magic string at each character position in the text
 *    string by calling C_STR$pattern_match (i.e. this function)
 *    recursively.  If any of those succeed then declare this one a success.
 *
 * CAVEATS :
 *  (1) pattern$ is assumed to be preprocessed, i.e, * replaced by WILD_STAR,
 *     '%' replaced by WILD_PERCENT, '\<character>' by '<character>', etc.
 *
 *  (2) str$, however, is LITERAL, ie, it does not have wildcards or
 *      '\<character>', etc.  *, %, and \ are given no special treatment.
 *
 * HISTORY :
 *
 *  V0 - V7
 *
 *  12-JUL-89   A. Seigel
 *      (1) Created this function.
 *
 *  11-SEP-89   A. Seigel
 *      (1) Fixed bug with literals (\) in pattern$.
 *

		       Source Listing                  19-NOV-2004 08:39:18  Compaq C V6.5-001-48BCD           Page 43
							4-MAR-2003 15:31:10  $1$DGA1016:[DEBUG_2.SRC]STRINGS.C;1

 *  V8
 *
 *  24-MAY-1990        J. Bell
 *      (1) ANSI-ized declaration.
 *
 *
 *	27-NOV-2015	RRL	Some reformating.
 */
/*--***********************************************************************/

#define WILD_PERCENT	'%'
#define WILD_STAR	'*'

#ifndef	FALSE
#define	FALSE	0
#endif

#ifndef	TRUE
#define	TRUE	1
#endif


int	__util$pattern_match	(
		char	*	str$,        /* A LITERAL string to match */
		char	*	pattern$     /* Pattern, with potential wildcards (*,%) to * match the string.*/
				)
{
int done = FALSE, matched_to_eos = FALSE;

	while( (*pattern$ != '\0') && (!done) && ( ((*str$=='\0') && ( (*pattern$==WILD_STAR)) ) || (*str$!='\0')) )
		{
		switch (*pattern$)
			{
			case WILD_STAR:
				pattern$++;
				matched_to_eos = FALSE;
				while ( (*str$ != '\0') && (! ( matched_to_eos = __util$pattern_match( str$++, pattern$))));

				if ( matched_to_eos )
					{
					while (*str$ != '\0') str$++;
					while (*pattern$ != '\0') pattern$++;
					}
				break;

			case WILD_PERCENT:
				pattern$++;
				str$++;
				break;

			/* case '\\':*/
			/* pattern$++;*/

			default:
				if (*str$ == *pattern$)
					{
					str$++;
					pattern$++;
					}
				else done = TRUE;
			}
		}

	while (*pattern$ == WILD_STAR) pattern$++;

	return ( (*str$ == '\0') && (*pattern$ == '\0') );


}
/******************* end of C_STR$pattern_match *******************/

#if	0
#ifndef	WIN32
void	__util$traceback	(void)
{
int	i, nptrs;
void *	buffer[128];
char **	strings;

	nptrs = backtrace(buffer, sizeof(buffer));

	$LOG(STS$K_INFO, " --------------------- TRACEBACK BEGIN (%d) ------", nptrs);

	if ( !(strings = backtrace_symbols(buffer, nptrs)) )
		{
		perror("backtrace_symbols");

		exit(EXIT_FAILURE);
		}

	for (i = 0; i < nptrs; i++)
		$LOG(STS$K_INFO, "%d\t%s", i, strings[i]);

	$LOG(STS$K_INFO, " --------------------- TRACEBACK END ------");

}

#endif
#endif


#ifndef	WIN32
#pragma GCC diagnostic pop
#endif





#ifdef	__CRC32_TAB__

extern unsigned int crc32c_tab[];


#else
#define	__CRC32_TAB__	1

/*	CRC32-C	*/
static const  unsigned int __crc32c_tab__[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};
#endif	/* __CRC32_TAB__ */

unsigned int	__util$crc32c (unsigned int crc, const void *buf, size_t buflen)
{
const unsigned char  *p = (unsigned char *) buf;

	crc = crc ^ ~0U;

	while (buflen--)
		crc = __crc32c_tab__[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}






/*
**  STRSTR/_STRSTR64
**
**  The 'strstr' function locates the first occurrence in the string pointed
**  to by 's1' of the sequence of characters in the string pointed to by 's2'.
**
**  Return values:
**
**	non-NULL    the address of the located string
**	NULL	    indicates that the string was not found
*/
char *	__util$strstr
			(
		char	* s1,
		size_t	s1len,
		char	* s2,
		size_t	s2len
			)
{
char	*p1 = s1, *p2 = s2 + 1;
size_t	p1len = s1len, cmplen = s2len - 1;

	/*
	 * Sanity check ...
	 */
	if ( !s1 || !s2 || !s1len || !s2len )
		return	NULL;

	if ( s1len < s2len )
		return	NULL;

	/*
	 * Special check for single-byte substring
	 */
	if ( !cmplen )
		return	memchr(s1, *s2, s1len);

	/*
	**  Find the first character of s2 in the remaining string.  If it is
	**  found, compare the rest of s2.
	*/
	while ( p1len && (p1 = memchr(p1, *s2, p1len)) )
		{
		/*
		 * Is the rest of the p1 is more then length of the s2 ?
		 * No ?! Stop comparing ,  return the NULL pointer.
		 */
		if ( (s1len - (p1 - s1)) < cmplen )
			return	(NULL);

		if ( !memcmp(p1 + 1,  p2, cmplen) )
			return	(p1);

		p1++;
		p1len = s1len - (p1 - s1);
		};


	/*
	**  No match.  Return the NULL pointer.
	*/
	return((char *) NULL);
}






#if __util_DEBUG__


/*
 * stc_msg_vformat
 *
 * The core formatting routine.
 * Do NOT use sprintf-style formatting codes in
 * message strings! Use the formatting directives
 * below:
 * !AD
 * !AZ
 * !AC
 * !U{L, W, B} = unsigned int, short, byte
 * !S{L, W, B} = signed int, short, byte
 * !X{L, W, B} = hexadecimal int, short, byte
 * !P = pointer
 * !! = exclamation point
 */
#ifdef	WIN32
#define	snprintf(buf, len, format,...)	_snprintf_s(buf, len, len, format, __VA_ARGS__)
#endif

static int	__util$vfao (char *fmt, char *buf, size_t bufsz, va_list ap)
{
int	len;
char	tmpbuf[32], *outp = buf;

	for ( ;bufsz && *fmt; )
		{
		if (*fmt != '!')
			{
			*outp++ = *fmt++;
			bufsz--;

			continue;
			}

		if ( !(*(++fmt)) )
			break;

		/* !!
		*/
		if (*fmt == '!')
			{
			*outp++ = *fmt++;
			bufsz--;

			continue;
			}

		/* !X{L, W, B}, U{L, W, B}, S{L, W, B}
		*/
		if (*fmt == 'U' || *fmt == 'X' || *fmt == 'S' )
			{
			unsigned long val = 0;

			if (*(fmt+1) == 'B')
				{
				val = va_arg(ap, unsigned char);
				len = snprintf(tmpbuf, sizeof(tmpbuf),  ((*fmt == 'X') ?  "0x%02X" : (*fmt == 'U') ? "%3u" : "%3d"),
					(unsigned char) val);
				}
			else if (*(fmt + 1) == 'W')
				{
				val = va_arg(ap, unsigned short);
				len = snprintf(tmpbuf, sizeof(tmpbuf),  ((*fmt == 'X') ?  "0x%04X" : ( *fmt == 'U') ? "%5u" : "%6d"),
					(unsigned short) val);
				}
			else if (*(fmt + 1) == 'L')
				{
				val = va_arg(ap, unsigned long);
				len = snprintf(tmpbuf, sizeof(tmpbuf),  ((*fmt == 'X') ?  "0x%08X": ( *fmt == 'U') ? "%11u" : "%11d"),
					(unsigned long) val);

				}
			else	continue;

			if ( len < 0 )
				break;

			if (len >= bufsz)
				len = bufsz - 1;

			memcpy(outp, tmpbuf, len);

			outp	+= len;
			bufsz	-= len;
			fmt	+= 2;

			continue;
			}




		/* !P
		*/
		if (*fmt == 'P')
			{
			if ( 0 > (len = snprintf(tmpbuf, sizeof(tmpbuf), "@%p", va_arg(ap, void *))) )
				break;

			if (len >= bufsz)
				len = bufsz - 1;

			memcpy(outp, tmpbuf, len);

			outp	+= len;
			bufsz	-= len;
			fmt	+= 1;

			continue;
			}

		/* !AD, !AC, !AZ ...	*/
		if (*fmt == 'A')
			{
			unsigned int slen = 0;
			char *ptr;

			if (*(fmt+1) == 'D')
				{
				slen	= va_arg(ap, unsigned int);
				ptr	= va_arg(ap, char *);

				}
			else if (*(fmt+1) == 'Z')
				{
				ptr	= va_arg(ap, char *);
				slen	= (unsigned int) strnlen(ptr, bufsz);
				}
			else if (*(fmt+1) == 'C')
				{
				ptr	= va_arg(ap, char *);
				slen	= *(ptr++);
				}
			else	continue;

			if (slen >= (unsigned int) bufsz)
				slen = (unsigned int)bufsz - 1;

			memcpy(outp, ptr, slen);

			outp	+= slen;
			bufsz	-= slen;
			fmt	+= 2;

			continue;
		}

	// Unrecognized directive here, just loop back up to the top
	} /* while bufsz > 0 && *fmt != null char */

	*outp = '\0';
	return (outp - buf);
}



int	__util$fao (void *fmt, void *buf, size_t bufsz, ...)
{
va_list ap;
int result;

	va_start(ap, bufsz);
	result = __util$vfao((char *) fmt, (char*) buf, bufsz, ap);
	va_end(ap);

	return result;
}



struct _stm_buf				/* One item of Stream buffer			*/
{
	ENTRY	links;			/* Left, right links, used by queue macros	*/
	int	len;			/* Actual length of data in the buffer		*/
	int	ref;			/* Count of reference				*/
	char buf[32];		/* Buffer itself				*/
} _stm_buf_area[32];		/* We declare a static buffers area		*/

QUEUE	free_bufs = QUEUE_INITIALIZER,
	busy_bufs = QUEUE_INITIALIZER;


int	main (int argc, char *argv[])
{
int count, bcnt;
char	buf[1024];


	bcnt  = __util$fao("!UL, !UW, !UB", buf, sizeof(buf), 1, 2, 3);

	for (bcnt = 0; bcnt < 32; bcnt++)
		$INSQTAIL(&free_bufs, &_stm_buf_area[bcnt], &count);

	return	1;
}




#if	0
// Factory macros
#undef	$DEFMSG

#define $DEFMSGLIST \
	$DEFMSG(util,  0, S, NORMAL,		"normal successful completion") \
	$DEFMSG(util,  1, W, WARNING,	"unknown warning") \
	$DEFMSG(util,  2, E, ERROR,		"unknown error") \
	$DEFMSG(util,  3, F, FATALERR,	"unknown fatal error") \
	$DEFMSG(util, 13, E, NUMCNVERR,	"numeric conversion error: !SL") \
	#DEFMSG(util,122, E, LIBRDERR,	"error reading library file !SZ")

#define	$DEFMSG(fac, num, sev, nam, txt) #nam,
static const char *__$msgmnemonics[] = {
	$DEFMSGLIST
};
#undef	$DEFMSG

#define $DEFMSG(fac, num, sev,nam, txt) txt,
static const char *__$msgtexts[] = {
	$DEFMSGLIST
};
#undef	$DEFMSG

#define $DEFMSG(fac, num, sev, nam, txt) #define fac##txt num
static const char *__$msgtexts[] = {
	$DEFMSGLIST
};

#define	$DEFMSG(fac, num, sev, nam, txt) fac##__##nam =  STC_CODE_##typ(msg),
typedef enum {
STATCODES
} statcode_t;
#undef STATCODE



//#define	$MSGCOUNT (sizeof(__$##fac##msgmnemonics)/sizeof(__$##fac##msgmnemonics))

#endif



#if	0
OPTS	opts [] = {
		OPTS_NULL
};


#define	IOBUFSZ		4096		/* A size of single buffer			*/
#define	IOBUFCNT	4096		/* A total number of buffers			*/

struct _stm_buf				/* One item of Stream buffer			*/
{
	ENTRY	links;			/* Left, right links, used by queue macros	*/
	int	len;			/* Actual length of data in the buffer		*/
	int	ref;			/* Count of reference				*/
	char buf[IOBUFSZ];		/* Buffer itself				*/
} _stm_buf_area[IOBUFCNT];		/* We declare a static buffers area		*/

QUEUE	free_bufs = QUEUE_INITIALIZER,
	busy_bufs = QUEUE_INITIALIZER;


DWORD WINAPI worker_f2b (void *arg)
{
int	status, count, i;
struct _stm_buf	* sbuf;

	$LOG(STS$K_INFO, "tid : %d running ...", GetCurrentThreadId());

	for (i = 0; i < 10000 * 500; i++)
		{
		if ( !(i %  10000) )
			$LOG(STS$K_INFO, "tid:%d, iteration %d", GetCurrentThreadId(), i);

		if ( !(1 & (status = $REMQHEAD(&free_bufs, &sbuf, &count))) )
			{
			$LOG(STS$K_ERROR, "$REMQHEAD() ->  %d, count = %d", status, count);
			continue;
			}

		if ( !sbuf )
			$LOG(STS$K_FATAL, "sbuf == NULL");


		if ( !(1 & (status = status = $INSQTAIL(&busy_bufs, sbuf, &count))) )
			$LOG(STS$K_ERROR, "$INSQTAIL() ->  %d", status);
		}

	return	status;
}

DWORD WINAPI worker_b2f (void *arg)
{
	int	status, count, i;
	struct _stm_buf	* sbuf;

	$LOG(STS$K_INFO, "tid : %d running ...", GetCurrentThreadId());

	for (i = 0; i < 10000 * 500; i++)
		{
		if ( !(i %  10000) )
			$LOG(STS$K_INFO, "tid:%d, iteration %d", GetCurrentThreadId(), i);

		if ( !(1 & (status = $REMQHEAD(&busy_bufs, &sbuf, &count))) )
			{
			$LOG(STS$K_ERROR, "$REMQHEAD() ->  %d, count = %d", status, count);
			continue;
			}


		if ( !sbuf )
			$LOG(STS$K_FATAL, "sbuf == NULL");


		if ( !(1 & (status = status = $INSQTAIL(&free_bufs, sbuf, &count))) )
			$LOG(STS$K_ERROR, "$INSQTAIL() ->  %d", status);
		}

	return	status;
}



int	main (int argc, char *argv[])
{
int count, i;
HANDLE scan_tid;
char	buf[1024];


	i = __util$fao("!UL, !UW, !UB", buf, sizeof(buf), 1, 2, 3);


	/*
	**
	*/
	i = __util$pattern_match("ch33---0010904935.torrent", "*.torrent");

	i = __util$pattern_match("Hello World!!!", "*llo*");




	__util$getparams(argc, argv, opts);
//	__util$setlogfile("logfile2.log");


	//InitializeSRWLock(&free_bufs.lock);


	for (i = 0; i < IOBUFCNT; i++)
		$INSQTAIL(&free_bufs, &_stm_buf_area[i], &count);



	for (i = 0; i <  32; i++)
		{
		if ( (scan_tid = CreateThread(NULL, 0, worker_f2b, NULL, 0, NULL)) == NULL )
			return $LOG(STS$K_ERROR, "Creation streaming thread was failed : %d", GetLastError());
		}


	for (i = 0; i <  32; i++)
		{
		if ( (scan_tid = CreateThread(NULL, 0, worker_b2f, NULL, 0, NULL)) == NULL )
			return $LOG(STS$K_ERROR, "Creation streaming thread was failed : %d", GetLastError());
		}

	WaitForSingleObject(scan_tid, INFINITE);

	return STS$K_SUCCESS;
}
#endif
#endif
