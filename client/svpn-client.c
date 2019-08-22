#define	__MODULE__	"BAGENT"
#define	__IDENT__	"X.00-97"
#define	__REV__		"0.0.97"

#ifdef	__GNUC__
	#pragma GCC diagnostic ignored  "-Wparentheses"
	#pragma	GCC diagnostic ignored	"-Wunused-variable"
	#pragma	GCC diagnostic ignored	"-Wmissing-braces"
#endif


/*++
**
**  FACILITY:  BroProxy-Agent - a light weight proxy agent
**
**  DESCRIPTION: This is a main module , contains routines to implement "proxy/router engine" functionality.
**
**  ABSTRACT: General logic of BroProxy Server <-> BroProxy-Agent interoperation is imagine on the follows diagram:
**
**	     Browser                |   Front-End Master     |   Router         | Victim Host    |
**	  (Opera, Chrome)           |    BroProxy (tm)       | BroProxy-Agent   |  www.ya.ru     |
**	----------------------------+------------------------+------------------+----------------+
**	                            |           <----- TCP -------              |                |
**	                            |      (Establishing signaling channel)     |                |
**	----------------------------+------------------------+------------------+----------------+
**	                  ----- TCP ------>                  |                  |                |
**	GET www.ya.ru HTTP 1.1   ------->                    |                  |                |
**	----------------------------+------------------------+------------------+----------------+
**	                            | REQ Id # GET www.ya.ru HTTP 1.1 -->       |                |
**                                  |    (over signaling channel)               |                |
**	----------------------------+------------------------+------------------+----------------+
**	                            |                        |          ---- TCP ---->           |
**	                            |                        |      GET www.ya.ru HTTP 1.1       |
**	----------------------------+------------------------+------------------+----------------+
**	                            |                        |          <--- 200  OK--           |
**	----------------------------+------------------------+------------------+----------------+
**	                            |           <----- TCP -------              |                |
**	                            |      (Establishing data channel REQ Id#)  |                |
**	----------------------------+------------------------+------------------+----------------+
**	                  <--- 200  OK--                     |                  |                |
**	----------------------------+------------------------+------------------+----------------+
**                             --- data --->            --- data --->        --- data --->       |
**	                       <--- data ---            <--- data ---        <--- data ---       |
**	----------------------------+------------------------+------------------+----------------+
**
**
**  USAGE:
**	As standalone program (#undef __CALLABLE_BAGENT__ ) :
**		$ ./BAGENT /CONFIG=<configuration_file>
**
**	As callable engine (#define  __CALLABLE_BAGENT__ ) :
**
**		int	bagent_init ( ASC *master, ASC *auth, ASC *extbind, ASC *nserver, int trace,
**				void (*cbrtn) (void *cbarg, int what, ...), void *cbarg,
**				void **ctx);
**
**		int	bagent_start( void *ctx );
**
**		int	bagent_stop ( void *ctx, int wait_flag );
**
**		int	bagent_info ( ASC *ident, ASC *ver);
**
**
**		Format of Callback routine:
**		void	cbrtn (void *cbarg, int what, ...);
**
**		where is code:
**		#define	BP$K_BAGUP	1
**		#define	BP$K_BAGDOWN	2
**		#define	BP$K_BAGCTLUP	3
**		#define	BP$K_BAGCTLDOWN	4
**		#define	BP$K_PROTSD	5	Third arguments is socked descriptior
**
**
**  AUTHORS: Ruslan R. (The BadAss SysMan) Laishev
**
**  CREATION DATE:  30-MAY-2019
**
**  MODIFICATION HISTORY:
**
**	 5-JUN-2019	RRL	X.00-61 : Small diagnostic message corrections;
**				contexts definitions redesign to support multiple control threads;
**				reorganize code to be more clear to understand;
**
**				X.00-62 : Some more comments and corrections.
**
**				X.00-63 : Added validation and checks of configuration parameters.
**
**	 6-JUN-2019	RRL	X.00-70 : POSIX Adaptation.
**
**	 7-JUN-2019	SYS	X.00-71 : POSIX - Replace fucking unix-shit gethostbyname() with resolver API
**
**	10-JUN-2019	RRL	X.00-80 : Added /EXTBIND and /NSERVER options into the POSIX's part of code,
**				no need : resolv.h and -lresolv ;
**
**	11-JUN-2019	SYS	X.00-81 : /NSERVER & /EXTBIND under Windows, only IP is accepted.
**
**	13-JUN-2019	RRL	X.00-82 : Added 'trace' parameter to the bagent_init();
**				changed cast of some parameters to be more friendly to callers;
**				added some more description text;
**
**	18-JUN-2019	RRL	X.00-83 : Resolved problem with errno redefinitions under Android;
**				added Android specific definitions;
**				fixed crash in the get_host() routine;
**
**	19-JUN-2019	RRL	X.00-86 : Improved security of the routines related to name resolution;
**				resolved problem with binding source IP to the 'extbind' under Windows.
**				resolved problem with flooding master by connection request from __th_ctl();
**				added some more diagnostic messages;
**
**	20-JUN-2019	SYS	X.00-88 : Improved communication error handling in the __th_ctl();
**				resolved problem with query NS from 'extbind' IP;
**
**	21-JUN-2019	RRL	X.00-91 : Fixed bug with unpacking name's field in the __nx_name_unpack();
**				fixed bug with incorrect NS server iteration;
**				added bagent_info() routine;
**				resolved problem with concurrent access to the NS's sockets;
**
**	23-JUN-2019	RRL	Set SO_DONTROUTE for sockets with EXTBIND Win32/POSIX
**
**	24-JUN-2019	RRL	Recoded a functionality of signaling about BAGENT's status changes;
**				removed set of SO_DONTROUTE;
**
**	26-JUN-2019	RRL	Added template of callback() routine has been based on the ARL's code snippet;
**
**	27-JUN-2019	RRL/ARL	Fixed bugs with callback() routine calling;
**				fixed potential bugs in the UDP's socket initialization;
**				resolved problem with DNS request - it's the result of the using of fucking 'block-dns-outside' option in the OpenVPN config;
**
**			RRL	Blocked from compilation unused code;
**				fixed incorrect initialization of NS;
**
**	30-JUN-2019	RRL	X.00-93 : Resolved problem with blocking of DNS requests by OpenVPN;
**
**	 1-JUL-2019	RRL	Removed unused code, improved diagnostic messages.
**
**	 2-JUL-2019	SYS	X.00-94 : fixed problem with consuming CPU in empty looping the __th_req();
**				using my cool memmem() instead of POSIX-shit.
**
**	 3-JUL-2019	RRL	Removed unused stuff;
**				set g_trace to zero!
**				added traffic counters in the th_req();
**
**	 4-JUL-2019	RRL	X.00-95 : Added caching of resolved IP name in the POSIX-version;
**
**	 6-JUL-2019	RRL	Fixed bug under WIN32 with incorrect using close() on socket instead of closesocket();
**
**	 7-JUL-2019	RRL	Implemented cache for IP-address under Win32;
**				added checking for "out of buffer space" in the __ns_2ip() and __ns_name_unpack() routines to prevent undiscovered ACCVIO;
**
**	 8-JUL-2019	SYS	X.00-96 : Improved checking of data area of working with answer from NS;
**				memmem() is excluded from compilation for ANDROID;
**				void __th_ctl() -> int __th_ctl() to be compiled for ANDROID;
**
**	 9-JUL-2019	SYS	X.00-96ECO2 : Fixed bug with lentgh's incrementation in the __ns_name_pack() has been introduced by changes in the X.00-96;
**
**	17-JUL-2019	RRL	X.00-97 : Added to the __th_ctl() calling of NS cache puring procedure.
**--
*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<time.h>
#include	<inttypes.h>
#include	<signal.h>


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
#include<ws2tcpip.h>
#include<process.h>

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

#endif

#define	__FAC__	"BAGENT"
#define	__TFAC__ __FAC__ ": "

#ifdef _DEBUG
	#ifndef	__TRACE__
		#define	__TRACE__
	#endif
#endif // DEBUG

#include"utility_routines.h"
#include"base64.h"


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
	g_trace = 0;			/* A flag to produce extensible logging	*/


static const struct timespec g_locktmo = {5, 0};/* A timeout for thread's wait lock	*/

					/* Structure to keep timers information */
typedef	struct __bp_timers__	{

	struct timespec	t_seq,		/* Interval to get initial mimimal length sequence to recognize protocol */
			t_req,		/* Interval to get whole request (HTTP's header)	*/
			t_conn,		/* Interval to connect destination host	*/
			t_xmit,		/* Interval to xmit has been received portion of the data */
			t_ns,		/* A time to wait answer from NS server	*/
			t_nspurge;	/* An interval of purging NS Cache */

} BP_TIMERS;

static	BP_TIMERS	g_timers_set = { {2, 0}, {3, 0}, {3, 0}, {15, 0}, {3, 0} , {30, 0} };


#define	BP$K_IOBUFSZ	(64*1024)
#define	BP$K_NSMAX	2		/* A number of NS-es in the context	*/
#define	BP$K_NSCACHE	1024		/* Cache size for IP4 addresses	 	*/

typedef	struct __ctlctx__	{	/* Context area for control/signaling thread	*/
#ifdef	WIN32
	unsigned		tid_ctl;		/* Id of control thread			*/
#else
	pthread_t	tid_ctl;
#endif
		ASC	master,		/* Master's IP:port pair			*/
			auth,		/* Username:password pair to login at master	*/
			extbind;		/* Bind source address for outgoing TCP and UDP	*/

					/* Callback routine entry point			*/
		void	(*cbrtn) (void *cbarg, int code, ...);
		void	*cbarg;		/* An argument to be passed to the callback routine */

					/* Primary & Backup Name Server socket		*/
	struct sockaddr_in	ns[BP$K_NSMAX],
				extbind_sk;
		int		sdns[BP$K_NSMAX];

} CTLCTX;


typedef	struct __reqctx__	{	/* Context for request processor thread		*/

		CTLCTX		*ctx;	/* A reference to control thread		*/
	unsigned long long	id;	/* Request Id has been received from the master */
		int		len;	/* Length of request data			*/
		char		req[BP$K_IOBUFSZ];
} REQCTX;

typedef struct __ns_entry__
{
	unsigned		hash;	/* Hash of the IP name			*/
	struct timespec		expdt;	/* Expiration time for record		*/
	struct in_addr		ip;	/* IP address in NBO			*/
		ASC		name;	/* IP name				*/
} NS_ENTRY;

typedef struct __ns_index__
{
	unsigned		hash;	/* Hash of the IP name			*/
	NS_ENTRY		*entp;
} NS_INDEX;

static NS_ENTRY *nscache = NULL;
static NS_ENTRY *nsindex = NULL;
static int	nscache_count;		/* A number of entries in the NS cache	*/

#ifndef	WIN32
static	pthread_rwlock_t	ns_cache_lock;
static	pthread_attr_t		g_th_attr = {0};/* */
static	pthread_mutex_t		ns_lock = PTHREAD_MUTEX_INITIALIZER;
#else
static  SRWLOCK			ns_cache_lock = SRWLOCK_INIT;
#endif

#define	BP$K_PIPESZ	512
#define	BP$K_PIPENAME	"\\\\.\\pipe\\bagent-pipe"

#define	BP$K_BAGUP	1		/* BAGENT is started, bagent_start9) has been called */
#define	BP$K_BAGDOWN	2		/* BAGENT is down, bagent_stop() --//--		*/
#define	BP$K_BAGCTLUP	3		/* BAGENT Control channel is established	*/
#define	BP$K_BAGCTLDOWN	4		/* BAGENT Control channel has been closed	*/
#define	BP$K_PROTSD	5		/* Need performs "protect-from-VPN: for socket	*/

#ifdef	WIN32
static	HANDLE	pipe_hd = INVALID_HANDLE_VALUE;
CRITICAL_SECTION pipe_lock;
CRITICAL_SECTION ns_lock;


/* c38d57d1-05a7-4c33-904f-7fbceee60e82 */
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38d57d1,
    0x05a7,
    0x4c33,
    0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
    );

/* 4a72393b-319f-44bc-84c3-ba54dcb3b6b4 */
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    0x4a72393b,
    0x319f,
    0x44bc,
    0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
    );

/* d78e1e87-8644-4ea5-9437-d809ecefc971 */
DEFINE_GUID(
    FWPM_CONDITION_ALE_APP_ID,
    0xd78e1e87,
    0x8644,
    0x4ea5,
    0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
    );

/* c35a604d-d22b-4e1a-91b4-68f674ee674b */
DEFINE_GUID(
    FWPM_CONDITION_IP_REMOTE_PORT,
    0xc35a604d,
    0xd22b,
    0x4e1a,
    0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
    );


/* UUID of WFP sublayer used by all instances of openvpn
 * 2f660d7e-6a37-11e6-a181-001e8c6e04a2 */
DEFINE_GUID(
    SUBLAYER,
    0x2f660d7e,
    0x6a37,
    0x11e6,
    0xa1, 0x81, 0x00, 0x1e, 0x8c, 0x6e, 0x04, 0xa2
    );

static WCHAR *FIREWALL_NAME = L"StarLet";
static WCHAR *FIREWALL_DESC = L"Allow to send DNS request (when OpenVPN block it)";
static	HANDLE	*engine_handle = NULL;

/*
 * Default msg handler does nothing
 */
static inline int __errmsg	(
			DWORD	err,
		const char	*msg
				)
{
char	*cstr;
int	len = 0;

	len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		err, 0, (LPTSTR) &cstr, 0, NULL);

	$LOG(STS$K_ERROR, "%s, errno=%#x, %.*s", msg, err, len, cstr);

	LocalFree(cstr);

	return	err;
}

/*
 * Add a persistent sublayer with specified uuid.
 */
static DWORD	__add_sublayer	(
			GUID	uuid
				)
{
FWPM_SESSION0 session = {0};
HANDLE	engine = NULL;
DWORD	err = 0;
FWPM_SUBLAYER0 sublayer = {0};

	if ( ERROR_SUCCESS == (err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine)) )
		{
		sublayer.subLayerKey = uuid;
		sublayer.displayData.name = FIREWALL_NAME;
		sublayer.displayData.description = FIREWALL_DESC;
		sublayer.flags = 0;
		sublayer.weight = 0x100;

		/* Add sublayer to the session */
		if ( err = FwpmSubLayerAdd0(engine, &sublayer, NULL) )
			__errmsg(err, "FwpmSubLayerAdd0()");
		}
	else    __errmsg(err, "FwpmEngineOpen0()");

	if ( engine )
		FwpmEngineClose0(engine);

	return	err;
}

/*
 *  DESCRIPTION: 'Patch' OpenVPN's filters set to allow BAGENT performing DNS requests.
 *
 *  INPUT:
 *	exe_path:	Path of executable for which traffic is permitted.
 *
 *  IMPLICITE OUTPUT:
 *	engine_handle
 *
 *  RETURNS
 *	Condition code
 *
 */

static	DWORD	__set_dns_filters(
		char	*fspec
		)
{
FWPM_SESSION0	session = {0};
FWPM_SUBLAYER0 *sublayer_ptr = NULL;
UINT64		filterid;
FWP_BYTE_BLOB	*bagentblob = NULL;
FWPM_FILTER0	Filter = {0};
FWPM_FILTER_CONDITION0 Condition[2] = {0};
DWORD		err = 0;
WCHAR		exe_path [512] = {0};

	/* Convert ASCII to WCHAR */
	mbstowcs (exe_path, fspec, strnlen(fspec, 128));

	/* Add temporary filters which don't survive reboots or crashes. */
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	engine_handle = NULL;

	if ( err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine_handle) )
		$LOG(STS$K_ERROR, "Error %#x", __errmsg(err, "FwpmEngineOpen0()"));

	$IFTRACE(g_trace, "WFP engine opened");

	/* Check sublayer exists and add one if it does not. */
	if ( FwpmSubLayerGetByKey0(engine_handle, &SUBLAYER, &sublayer_ptr) == ERROR_SUCCESS )
		{
		$LOG(STS$K_SUCCESS, "Using existing sublayer");
		FwpmFreeMemory0((void **)&sublayer_ptr);
		}
	else    { /* Add a new sublayer -- as another process may add it in the meantime,
		* do not treat "already exists" as an error */
		err = __add_sublayer(SUBLAYER);

		if (err == FWP_E_ALREADY_EXISTS || err == ERROR_SUCCESS)
			$LOG(STS$K_SUCCESS, "Added a persistent sublayer");
		else    {
			__errmsg(err, "Failed to add persistent sublayer");
			goto	out;
			}
		}

	if ( err = FwpmGetAppIdFromFileName0(exe_path, &bagentblob) )
		{
		__errmsg(err, "Get byte blob for BAGENT.EXE failed");
		goto	out;
		}

	/* Prepare filter. */
	Filter.subLayerKey = SUBLAYER;
	Filter.displayData.name = FIREWALL_NAME;
	Filter.weight.type = FWP_UINT8;
	Filter.weight.uint8 = 0xA;
	Filter.filterCondition = Condition;
	Filter.numFilterConditions = $ARRSZ(Condition);

	/* First filter. Permit IPv4 DNS queries from BAGENT itself. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	Filter.action.type = FWP_ACTION_PERMIT;

	Condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	Condition[0].matchType = FWP_MATCH_EQUAL;
	Condition[0].conditionValue.type = FWP_UINT16;
	Condition[0].conditionValue.uint16 = 53;

	Condition[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	Condition[1].matchType = FWP_MATCH_EQUAL;
	Condition[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	Condition[1].conditionValue.byteBlob = bagentblob;

	if ( err = FwpmFilterAdd0(engine_handle, &Filter, NULL, &filterid) )
		{
		__errmsg(err, "Add filter to permit IPv4 port 53 traffic failed");
		goto	out;
		}

	/* Second filter. Permit IPv6 DNS queries from BAGENT itself. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	if ( err = FwpmFilterAdd0(engine_handle, &Filter, NULL, &filterid) )
		{
		__errmsg(err, "Add filter to permit IPv6 port 53 traffic failed");
		goto	out;
		}

	$LOG(STS$K_SUCCESS, "Added permit filters for'%s'", fspec);

out:
	if ( bagentblob )
		FwpmFreeMemory0((void **) &bagentblob);

	if ( err && engine_handle )
		{
		FwpmEngineClose0(engine_handle);
		engine_handle = NULL;
		}

	return err ? STS$K_ERROR : STS$K_SUCCESS;
}

static	DWORD	__delete_dns_filters(void)
{
DWORD err = 0;

	/*
	* For dynamic sessions closing the engine removes all filters added in the session
	*/
	if (engine_handle)
		err = FwpmEngineClose0(engine_handle);

	return	err;
}


/*
 *  DESCRIPTION: Send given buffer to pipe.
 *
 *  INPUT:
 *	buf:	A buffer to be sent
 *	bufsz:	A length of the data in the buffer
 *
 *  RETURNS
 *	Condition code
 *
 */
static	int	__send_pipe	(
			void	*buf,
			int	bufsz
				)
{
int	status, bcnt;

	EnterCriticalSection(&pipe_lock);
	/* Create named pipe if need ... */
	if ( pipe_hd == INVALID_HANDLE_VALUE)
		if ( (pipe_hd = CreateNamedPipe(BP$K_PIPENAME, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				1, BP$K_PIPESZ, BP$K_PIPESZ, 0, NULL)) == INVALID_HANDLE_VALUE )
			{
			LeaveCriticalSection(&pipe_lock);
			return $LOG(STS$K_FATAL, "Named pipe '%s' creation failed, errno=%d", BP$K_PIPENAME, GetLastError());
			}

	/* Is there reader at other end ? */
	if ( !ConnectNamedPipe(pipe_hd, NULL) && ((status = GetLastError()) != ERROR_PIPE_CONNECTED) && (status != ERROR_PIPE_LISTENING) )
		{
		LeaveCriticalSection(&pipe_lock);
		return $LOG(STS$K_WARN, "ConnectNamedPipe('%s'/#%d) : errno = %d", BP$K_PIPENAME, pipe_hd, GetLastError());
		}

	if ( !(status = WriteFile(pipe_hd, buf, bufsz, &bcnt, NULL)) )
		$LOG(STS$K_FATAL, "ConnectNamedPipe('%s'/#%d) : errno = %d", BP$K_PIPENAME, pipe_hd, GetLastError());

	LeaveCriticalSection(&pipe_lock);

	return	status;
}
#endif // WIN32

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

static	inline int	__ns_cache_get2(
			char	*name,
			int	namelen,
		struct in_addr	*ip
			)
{
int	status, i;
struct timespec now;
NS_ENTRY	*entp = nscache;

	if ( !nscache_count )		/* Cache is empty	*/
		return	STS$K_ERROR;

	/* Run over cache records from begin ... */
	for ( i = nscache_count; i--; entp++)
		{
		if ( namelen != $ASCLEN(&entp->name) )
			continue;

		if ( !memcmp(name, $ASCPTR(&entp->name), namelen) )
			break;
		}

	if ( i < 0 )
		return	STS$K_ERROR;	/* Missing in cache	*/

#ifndef	WIN32
	if ( status = clock_gettime(CLOCK_MONOTONIC, &now) )
		return	$LOG(STS$K_ERROR, "NS Cache, clock_gettime()->%d, errno=%d", status, errno);
#else
	timespec_get(&now, TIME_UTC);
#endif

	if ( 0 < __util$cmp_time(&now, &entp->expdt) )
		return	STS$K_WARN;	/* Entry has expired	*/

	*ip = entp->ip;			/* Hit in cache		*/

	return	STS$K_SUCCESS;
}

static	inline int	__ns_cache_get(
			char	*name,
			int	namelen,
		struct in_addr	*ip
			)
{
int	status, rc;
struct timespec etime;
NS_ENTRY	*entp = nscache;

#ifndef	WIN32
	if ( status = clock_gettime(CLOCK_MONOTONIC, &etime) )
		return	$LOG(STS$K_ERROR, "NS Cache, clock_gettime()->%d, errno=%d", status, errno);

	__util$add_time(&etime, &g_locktmo, &etime);

	if ( rc = pthread_rwlock_timedrdlock(&ns_cache_lock, &etime) )
		return	$LOG(STS$K_ERROR, "NS Cache lock for read, pthread_rwlock_rdlock()->%d, errno=%d", rc, errno);
#else
	AcquireSRWLockShared(&ns_cache_lock);
#endif

	status = __ns_cache_get2 (name, namelen, ip);

#ifndef	WIN32
	if ( rc = pthread_rwlock_unlock(&ns_cache_lock) )
		return	$LOG(STS$K_ERROR, "pthread_rwlock_unlock()->%d, errno=%d", rc, errno);
#else
	ReleaseSRWLockShared(&ns_cache_lock);
#endif

	return	status;
}



static	inline int	__ns_cache_put2(
			char	*name,
			int	namelen,
		struct in_addr	*ip,
		int		 ttl
			)
{
int	status, i;
struct timespec now, delta = {11, 0};
NS_ENTRY	*entp;

	/* Compute expiration time for IP address */
#ifndef WIN32
	if ( status = clock_gettime(CLOCK_MONOTONIC, &now) )
		return	$LOG(STS$K_ERROR, "NS Cache, clock_gettime()->%d, errno=%d", status, errno);
#else
	timespec_get(&now, TIME_UTC);
#endif // !WIN32

	__util$add_time (&now, &delta, &now);

	for ( status = 0, entp = nscache, i = nscache_count; i; i--)
		{
		if ( namelen != $ASCLEN(&entp->name) )
			continue;

		if ( status = (!memcmp(name, $ASCPTR(&entp->name), namelen)) )
			break;
		}

	if ( 1 & status )
		{
		entp->ip = *ip;		/* Update  */
		return	STS$K_SUCCESS;
		}

	/* So we need to add new record into the cache! */

	if ( nscache_count >= BP$K_NSCACHE )	/* Is there free entry ? */
		{				/* No?! - > Remove oldest entry from top of cache */
		memmove(nscache, nscache + 1, (BP$K_NSCACHE - 1) * sizeof(NS_ENTRY));
		nscache_count--;
		}

	entp = nscache + nscache_count;

	/* Form new entry */
	entp->ip = *ip;
	entp->expdt = now;
	memcpy($ASCPTR(&entp->name), name, $ASCLEN(&entp->name) = $MIN(namelen, ASC$K_SZ));

	nscache_count++;

	return	STS$K_SUCCESS;
}


static	inline int	__ns_cache_put(
			char	*name,
			int	namelen,
		struct in_addr	*ip,
		int		 ttl
			)
{
int	status, rc;
struct timespec etime;
NS_ENTRY	*entp = nscache;

#ifndef	WIN32
	if ( status = clock_gettime(CLOCK_MONOTONIC, &etime) )
		return	$LOG(STS$K_ERROR, "NS Cache, clock_gettime()->%d, errno=%d", status, errno);

	__util$add_time(&etime, &g_locktmo, &etime);

	if ( status = pthread_rwlock_timedwrlock(&ns_cache_lock, &etime) )
		return	$LOG(STS$K_ERROR, "NS Cache lock for write, pthread_rwlock_wrlock()->%d, errno=%d", status, errno);
#else
	AcquireSRWLockExclusive(&ns_cache_lock);
#endif

	rc = __ns_cache_put2 (name, namelen, ip, ttl);

#ifndef	WIN32
	if ( status = pthread_rwlock_unlock(&ns_cache_lock) )
		return	$LOG(STS$K_ERROR, "pthread_rwlock_unlock()->%d, errno=%d", status, errno);
#else
	ReleaseSRWLockExclusive(&ns_cache_lock);
#endif
	return	rc;
}

/*
*  DESCRIPTION: Run over NS Cache records, compare record's expiration time with the 'now'
*	- performs removing expired entry.
*	This routine is required exclusive access to the NS Cache!
*
*  INPUT:
*	now:	current time to be compared
*
*  IMPLICITE OUTPUT:
*	nscache, nscache_count
*
*  RETURNS:
*	conditin code
*
*/
static	inline int	__ns_cache_purge2(struct timespec *now)
{
int	status, i, purged = 0;
NS_ENTRY	*entp;

	$IFTRACE(g_trace, "Scan for expired NS Entries (current=%d) ...", nscache_count);

	for ( status = 0, entp = nscache, i = nscache_count; i; i--)
		{
		/* Check for expiration time */
		if ( 0 > __util$cmp_time(now, &entp->expdt) )
			continue;

		purged++;

		/* Current NS Cache entry has been expired, so we need to removed it from cache */

		if ( i != 1 )	/* Is it's not last entry ?  */
			memmove(entp, entp + 1, (i - 1) * sizeof(NS_ENTRY));

		/* */
		nscache_count--;
		}

	$IFTRACE(g_trace, "Finished scan (current=%d, purged=%d)", nscache_count, purged);

	return	STS$K_SUCCESS;
}


/*
*  DESCRIPTION: Check for has been expired NS Cache puring interval (see g_timers_set),
*		tried to get exclusive access to the NS Cache, calling ns_cache_purge2()
*		to performs main action.
*
*  INPUT:
*	NONE
*
*  IMPLICITE INPUT:
*	g_timers_set.t_nspurge
*
*  RETURNS:
*	conditin code
*
*/
static	inline int	__ns_cache_purge(void)
{
int	status;
struct timespec now;
static struct  timespec nextrun = {0};

	if ( !nscache_count )
		{/* Nothing to do at all */
		return	STS$K_SUCCESS;
		}

	/* To prevent run NS Purger too frequently with locking exclusively NS Cache
	maintain 'nextrun' and performs checking ... */

#ifndef WIN32
	if ( status = clock_gettime(CLOCK_MONOTONIC, &now) )
		return	$LOG(STS$K_ERROR, "NS Cache, clock_gettime()->%d, errno=%d", status, errno);
#else
	timespec_get(&now, TIME_UTC);
#endif // !WIN32

	/* Is it's first run ? */
	if ( 1 & __util$iszero(&nextrun, sizeof(nextrun)) )
		{
		/* Set 'next run time' and exit */
		__util$add_time (&now, &g_timers_set.t_nspurge, &nextrun);
		return	STS$K_SUCCESS;
		}

	/* Is the 'run time'  has been reached ? */
	if ( 0 > __util$cmp_time(&now, &nextrun) )
		return	STS$K_SUCCESS;


		/* Try to get exclusive access to the NS Cache */
#ifndef	WIN32
	if ( pthread_rwlock_trywrlock(&ns_cache_lock) )
#else
	if ( !TryAcquireSRWLockExclusive(&ns_cache_lock) )
#endif
		return	$LOG(STS$K_INFO, "Cannot get exclusive access to NS cache");

	__ns_cache_purge2 (&now);

#ifndef	WIN32
	if ( status = pthread_rwlock_unlock(&ns_cache_lock) )
		return	$LOG(STS$K_ERROR, "pthread_rwlock_unlock()->%d, errno=%d", status, errno);
#else
	ReleaseSRWLockExclusive(&ns_cache_lock);
#endif

	/* Update 'nextrun' time */
	__util$add_time (&now, &g_timers_set.t_nspurge, &nextrun);

	return	STS$K_SUCCESS;
}


#ifdef WIN32
#define	__ba_errno__	WSAGetLastError()
#else
#define	__ba_errno__	errno
#endif // WIN32

#define	HTTP_AGENT	"StarLet/" __IDENT__ "/" __ARCH__NAME__  " (built  at "__DATE__ " " __TIME__ ")"

static	const	char http_connect_ctl [] = {		/* Request is supposed to be used to establishing control channel */
		"CONNECT %.*s HTTP/1.1" CRLF
		"Connection: keep-alive" CRLF
		"Proxy-Agent: " HTTP_AGENT CRLF
		"Proxy-Authorization: basic %.*s=" CRLF
		CRLF},

	http_connect_data [] = {			/* Request is supposed to be used to establishing data channel */
		"CONNECT %.*s HTTP/1.1" CRLF
		"Proxy-Agent: " HTTP_AGENT CRLF
		"StarLet-Context: %llx" CRLF
		"Proxy-Authorization: basic %.*s=" CRLF
		CRLF},
	http_200 []  = {
		"HTTP/1.0 200 OK" CRLF
		"Proxy-Agent: " HTTP_AGENT CRLF
		CRLF},

	http_host [] = { "Host: "};			/* HTTP's Host field */


#pragma pack(push, 1)

/* DNS header structure */
struct DNS_HEADER
{
	unsigned short id;	// identification number

	unsigned char rd :1;	// recursion desired
	unsigned char tc :1;	// truncated message
	unsigned char aa :1;	// authoritive answer
	unsigned char opcode :4;// purpose of message
	unsigned char qr :1;	// query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1;	// checking disabled
	unsigned char ad :1;	// authenticated data
	unsigned char z :1;	// its z! reserved
	unsigned char ra :1;	// recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count;// number of answer entries
	unsigned short auth_count;// number of authority entries
	unsigned short add_count;// number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

/* Constant sized fields of the resource record structure */

struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

static void	__ns_name_pack	(
		char	*src,
		int	srcsz,
		char	*dst,
		int	dstsz,
		int	*dstlen
			)
{
char	*lp, *cp = dst;

	for ( *dstlen = 1, *dst = '\0', lp = dst; (srcsz--) && (dstsz--); )
		{
		dst++;
		(*dstlen)++;

		if ( *src == '.' )
			{	/* Adjance length pointer to end of output buffer */
			lp = dst;
			}
		else	{	/* Copy single character */
			*(dst) = *(src);
			(*lp)++;
			}

		src++;
		}

	/* Add nil, length of output string is included '\0' */
	if ( dstsz )
		{
		dst++;
		(*dstlen)++;
		}

	*(dst) = '\0';
}

static int __ns_name_unpack	(
		unsigned char	*src,
		unsigned char	*rqbuf,
			int	 rqlen,
			int	*adjlen,
		unsigned char	*dst,
			int	*retlen
				)
{
unsigned char *pdst = dst;;
unsigned int count = 0, jumped = 0;
int	i;

	*adjlen = 1;

	/*
	 * Read the names in 3www6google3com format from
	 * request's query part
	 */
	for( pdst = dst; (src < (rqbuf + rqlen)) && *src; )
		{
		if ( *src >= 0xC0 )	/* 0xC0 = 192 */
			{
			count = (*src) * 256 + *(src + 1) - 0xC000; /* 0xC000 = 49152 = 11000000 00000000 */

			src = rqbuf + count - 1;

			if ( src >= (rqbuf + rqlen) )
				return	STS$K_ERROR;

			jumped = 1;	/* We have jumped to another location so counting wont go up! */
			}
		else	*(pdst++) = *src;

		src++;

		if ( !jumped )
			*(adjlen) += 1;	/* If we havent jumped to another location then we can count up	*/
		}

	if ( jumped == 1 )
		*adjlen = *adjlen + 1; /* Number of steps we actually moved forward in the packet */


	i = (pdst - dst);
	*retlen = (pdst - dst);

	$DUMPHEX(dst, i);

	return	STS$K_SUCCESS;
}

static	int	__ns_2ip	(
			int	 sd,
	struct sockaddr_in	*ns,
		unsigned char	*host,
		struct in_addr	*ip,
			int	*ttl
			)
{
char	buf[1024] = {0}, *qname, *bufp, tmpbuf[512];
int	i, adjlen, retlen, qlen, status, buflen;
struct  sockaddr_in a = {0}, dns = *ns;
struct	DNS_HEADER *dh = (struct DNS_HEADER *) buf;
struct  QUESTION   *qinfo = NULL;
struct	R_DATA	   *prd;

#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLIN, 0};
#else
struct pollfd pfd = {sd, POLLIN, 0};
#endif // WIN32

	/* Set the DNS structure to standard queries */
	dh->id = htons(135);
	dh->qr = 0;	/* This is a query */
	dh->opcode = 0;	/* This is a standard query */
	dh->aa = 0;	/* Not Authoritative */
	dh->tc = 0;	/* This message is not truncated */
	dh->rd = 1;	/* Recursion Desired */
	dh->ra = 0;	/* Recursion not available! hey we dont have it (lol) */
	dh->z  = 0;
	dh->ad = 0;
	dh->cd = 0;
	dh->rcode = 0;
	dh->q_count = htons(1); /* we have only 1 question */
	dh->ans_count = dh->auth_count = dh->add_count = 0;

	/* Point to the query portion */
	qname = &buf[sizeof(struct DNS_HEADER)];

	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                     QNAME                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QTYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QCLASS                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
	__ns_name_pack	( host, strlen(host),  qname, 128, &qlen);
	qinfo =(struct QUESTION *) &buf[sizeof(struct DNS_HEADER) + qlen ];

	qinfo->qtype  = htons(1);	/* We are requesting the ipv4 address */
	qinfo->qclass = htons(1);	/* its internet (lol) */

	{
	status = sizeof(struct sockaddr);
	if ( 0 > (status = getsockname (sd, &a,  (socklen_t *) &status)) )
		$LOG(STS$K_ERROR, "getsockname(#%d)->%d, errno=%d", sd, status, __ba_errno__);


	$IFTRACE(g_trace, "[#%d] Source %s:%d", sd,
		inet_ntop(AF_INET, &a.sin_addr, tmpbuf, sizeof (tmpbuf)), ntohs(a.sin_port));

	$IFTRACE(g_trace, "[#%d] Destination %s:%d", sd,
		inet_ntop(AF_INET, &dns.sin_addr, tmpbuf, sizeof (tmpbuf)), ntohs(dns.sin_port));
	}

	if ( 0 > (status = sendto(sd, buf, i = (sizeof(struct DNS_HEADER) + (qlen) + sizeof(struct QUESTION)), 0, (struct sockaddr *)&dns, sizeof(dns))) )
		return	$LOG(STS$K_ERROR, "Resolving '%s', sendto(#%d, %d)->%d, errno=%d", host, sd, i, status, __ba_errno__);

	$DUMPHEX(buf, i);

	/* Wait for answer with timeout	*/
#ifdef WIN32
	if( 0 >  (status = WSAPoll (&pfd, 1, status = timespec2msec (&g_timers_set.t_ns))) )
#else
	if( 0 >  (status = poll(&pfd, 1, timespec2msec (&g_timers_set.t_ns))) )
#endif // WIN32
		return	$LOG(STS$K_ERROR, "poll(#%d, POLLIN)->%d, errno=%d", pfd.fd, status, __ba_errno__);

	else	if ( !(pfd.revents & POLLIN) )
		return $LOG(STS$K_ERROR, "Resolving '%s' is timed out, (.events=%#x, .revents=%#x)", host, pfd.events, pfd.revents);

	i = sizeof(dns);

	if ( 0 > (buflen = recvfrom (sd, buf, sizeof(buf), 0 , (struct sockaddr *)&a, &i)) )
		return	$LOG(STS$K_ERROR, "Resolving '%s', recvfrom(#%d)->%d, errno=%d", host, sd, buflen, __ba_errno__);

	$DUMPHEX(buf, buflen);

	/* Check IP of an answered NS .. */
	if ( memcmp (&a, ns, slen) )
		{
		inet_ntop(AF_INET, &ns->sin_addr, buf, (sizeof (buf) / 2)  - 1);
		inet_ntop(AF_INET, &a.sin_addr, buf + sizeof (buf) / 2, sizeof (buf) / 2);
		return	$LOG(STS$K_ERROR, "Sent to %s:%d, received from %s:%d", buf, ntohs(ns->sin_port),
				buf + sizeof (buf) / 2, ntohs(a.sin_port));
		}

	/* Move ahead of the dns header and the query field */
	bufp = &buf[sizeof(struct DNS_HEADER) + (qlen) + sizeof(struct QUESTION)];

	for( retlen = 0, i = ntohs(dh->ans_count); i--; )
		{
		if ( bufp >= (buf + buflen) )
			break;	/* EOD */

		if ( !( 1 & __ns_name_unpack(bufp, buf, buflen, &adjlen, tmpbuf, &retlen)) )
			break;	/* EOD ? */

		bufp = bufp + adjlen;
		if ( adjlen == 1 )
			bufp += retlen;

		if ( bufp >= (buf + buflen) )
			break;	/* EOD */

		prd = (struct R_DATA *)(bufp);
		bufp = bufp + sizeof(struct R_DATA);

		if ( bufp >= (buf + buflen) )
			break;	/* EOD */

		$IFTRACE(g_trace, "RR.type=%d", status = ntohs(prd->type));

		if ( ntohs(prd->type) == 1 )	/* if its an IPv4 address */
			{
			*ip = *((struct in_addr *) bufp);
			*ttl = ntohl(prd->ttl);

			inet_ntop(AF_INET, ip, buf, sizeof (buf));

			$IFTRACE(g_trace, "IPv4 address : %s, TTL=%d", buf, *ttl);

			/* We return first IP in the list */
			return	STS$K_SUCCESS;
			}

		bufp = bufp + (status = ntohs(prd->data_len));

		if ( bufp >= (buf + buflen) )
			break;	/* EOD */
		}

	$DUMPHEX(buf, buflen);
	$IFTRACE(g_trace, "buf=%p, buflen=%d, bufp=%p, eob=%p", buf, buflen, bufp, buf + buflen);

	return	STS$K_ERROR;
}


static	inline	int	__ns_query (
		CTLCTX		*ctx,
		unsigned char	*host,
		struct in_addr	*ip
			)
{
int	i, namelen, ttl = 1800;
char	buf[512];

	/* Is the IP-name/address in the cache ? */
	if ( 1 & (__ns_cache_get (host, namelen = strnlen(host, ASC$K_SZ) ,ip )) )
		{
		/* Bingo!  */
		inet_ntop(AF_INET, ip, buf, sizeof (buf));
		$IFTRACE(g_trace, "NS Cache -> %.*s=%s", namelen, host, buf);

		return	STS$K_SUCCESS;
		}

#ifdef	WIN32
	EnterCriticalSection(&ns_lock);
#else
	pthread_mutex_lock(&ns_lock);
#endif

	for  ( i = 0; i < BP$K_NSMAX; i++ )
		{
		/* Call low level routine to performs Query NS over UDP */
		if ( (ctx->sdns[i] > 0) )
			{
			if ( 1 & __ns_2ip (ctx->sdns[i], &ctx->ns[i], host, ip, &ttl) )
				{
#ifdef	WIN32
				LeaveCriticalSection(&ns_lock);
#else
				pthread_mutex_unlock(&ns_lock);
#endif

				if ( 1 & (__ns_cache_put (host, strnlen(host, ASC$K_SZ) , ip,  ttl)) )
					{
					inet_ntop(AF_INET, ip, buf, sizeof (buf));
					$IFTRACE(g_trace, "NS Cache <- %.*s=%s", namelen, host, buf);
					}

				return	STS$K_SUCCESS;
				}
			else    {
				inet_ntop(AF_INET, &ctx->ns[i].sin_addr, buf, sizeof (buf));
				$LOG(STS$K_ERROR, "NS server #%02.2d=%s - failed, trying next one ...", i, buf);
				}
			}
		}

#ifdef	WIN32
	LeaveCriticalSection(&ns_lock);
#else
	pthread_mutex_unlock(&ns_lock);
#endif

	return	$LOG(STS$K_ERROR, "Resolving '%s', no more Name Server", host);
}


static	inline	int	__ns_init (
		CTLCTX		*ctx
			)
{
int	i, count, status, sd = -1;
char	buf[512];

	for  ( count = i = 0; i < BP$K_NSMAX; i++ )
		{
		/* Is the NS server has been defined and need to be initialized ? */
		if ( ctx->ns[i].sin_addr.s_addr )
			{
			if ( 0 > (sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) )
				{
				inet_ntop(AF_INET, &ctx->ns[i].sin_addr, buf, sizeof (buf));

				$LOG(STS$K_ERROR, "NS:%s, socket()->%d, errno=%d", buf, sd, __ba_errno__);

				continue;
				}


			count++;	/* Count good NS Server */

#ifdef	ANDROID
			if ( ctx->cbrtn )
				ctx->cbrtn(ctx->cbarg, BP$K_PROTSD, sd);
#endif

			if ( 0 > bind(sd, (struct sockaddr*) &ctx->extbind_sk, slen) )
				{
#ifdef WIN32
				closesocket(sd);
#else
				close(sd);
#endif // WIN32

				return	$LOG(STS$K_FATAL, "bind(#%d, %.*s:%d), errno=%d", sd, $ASC(&ctx->extbind), ntohs(ctx->extbind_sk.sin_port), __ba_errno__);
				}
			else    $LOG(STS$K_SUCCESS, "bind(#%d, %.*s:%d)", sd, $ASC(&ctx->extbind), ntohs(ctx->extbind_sk.sin_port));


#if	0
			/* Do we need to bind outgoing socket to a specific network device ?*/
			else if ( $ASCLEN(&ctx->extbind) )
				{
				struct ifreq if_bind = {0};

				memcpy(if_bind.ifr_name, $ASCPTR(&ctx->extbind), $ASCLEN(&ctx->extbind));

				if ( 0 > setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &if_bind,  sizeof(if_bind)) )
					{
#ifdef WIN32
					closesocket(sd);
#else
					close(sd);
#endif // WIN32


					return	$LOG(STS$K_FATAL, "setsockopt(#%d, SO_BINDTODEVICE->%.*s), errno=%d", sd, $ASC(&ctx->extbind), __ba_errno__);
					}
				else    $LOG(STS$K_SUCCESS, "setsockopt(#%d, SO_BINDTODEVICE->%.*s)", sd, $ASC(&ctx->extbind));
				}
#endif
			ctx->sdns[i] = sd;
			}
		}


	if ( !count )
		return	$LOG(STS$K_ERROR, "No Name Server, check configuration!");

	return	STS$K_SUCCESS;
}





static inline int	__set_nonbio_flag	(
		int	sd,
		int	flag
			)
{
int	status;

#ifdef WIN32
	if ( (status =  WSAIoctl(sd, FIONBIO, &flag, sizeof(flag),  NULL, 0, &status,  NULL, NULL)) )
		return	$LOG(STS$K_ERROR, "WSPIoctl(%d, FIONBIO)->%d, errno=%d", sd, status, WSAGetLastError());
#else
if ( 0 > (status = fcntl(sd, F_GETFL, 0)) )
		return	$LOG(STS$K_ERROR, "fcntl(%d, F_GETFL)->%d, errno=%d", sd, status, __ba_errno__);

	if ( flag && !(status & O_NONBLOCK) )
		{
		if ( 0 > (status = fcntl(sd, F_SETFL, status | O_NONBLOCK)) )
			return	$LOG(STS$K_ERROR, "fcntl(%d, F_SETFL, 0x%08x)->%d, errno=%d", sd, __ba_errno__, status | flag, __ba_errno__);
		}
	else if ( !flag && (status & O_NONBLOCK) )
		{
		if ( 0 > (status = fcntl(sd, F_SETFL, status & (~O_NONBLOCK))) )
			return	$LOG(STS$K_ERROR, "fcntl(%d, F_SETFL, 0x%08x)->%d, errno=%d", sd, __ba_errno__, status & (~O_NONBLOCK), __ba_errno__ );
		}
#endif
	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: Create socket and try to establishing TCP-connection with specified by socket remote end-point.
 *
 *  INPUT:
 *	sk:	a socket of remote end-point (ip:port)
 *
 *  OUTPUT:
 *	sd:	network socket descriptor
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */
static	int	__connect_by_sock	(
		CTLCTX		*ctx,
	struct	sockaddr_in	*sk,
			int	*sd
				)
{
int	status;
#ifdef WIN32
WSAPOLLFD  pfd = {0, POLLOUT, 0};
#else
struct pollfd pfd = {0, POLLOUT, 0};
#endif // WIN32

char	buf[512], tmp[128];
struct	sockaddr_in	lsock = {0};

	/* Create handle of socket */
	if ( 0 > (pfd.fd = socket(AF_INET, SOCK_STREAM, 0)) )
		return	$LOG(STS$K_ERROR, "socket(AF_INET, SOCK_STREAM)->%d, errno=%d", pfd.fd, __ba_errno__);


#ifdef	ANDROID
	if ( ctx->cbrtn )
		ctx->cbrtn(ctx->cbarg, BP$K_PROTSD, pfd.fd);
#endif

	/* Do we need to bind outgoing socket to a specific IP address  ? */
	if ( ctx->extbind_sk.sin_addr.s_addr )
		{
		if ( 0 > bind(pfd.fd, (struct sockaddr*) &ctx->extbind_sk, slen) )
			{
#ifdef WIN32
			closesocket(pfd.fd);
#else
			close(pfd.fd);
#endif // WIN32

			return	$LOG(STS$K_FATAL, "bind(%d, %.*s:%d), errno=%d", pfd.fd, $ASC(&ctx->extbind), ntohs(ctx->extbind_sk.sin_port), __ba_errno__);
			}
		}

#if	0
	/* Do we need to bind outgoing socket to a specific network device ? */
	else if ( $ASCLEN(&ctx->extbind) )
		{
		struct ifreq if_bind = {0};

		memcpy(if_bind.ifr_name, $ASCPTR(&ctx->extbind), $ASCLEN(&ctx->extbind));

		if( 0 > setsockopt(pfd.fd, SOL_SOCKET, SO_BINDTODEVICE, &if_bind,  sizeof(if_bind)) )
			{
#ifdef WIN32
			closesocket(pfd.fd);
#else
			close(pfd.fd);
#endif // WIN32

			return	$LOG(STS$K_FATAL, "setsockopt(#%d, SO_BINDTODEVICE->%.*s), errno=%d", pfd.fd, $ASC(&ctx->extbind), errno);
			}
		}
#endif

	/* Set NONBIO flag - we suppose performs timeout processing */
	if ( !( 1 & __set_nonbio_flag (pfd.fd, one)) )
		{
#ifdef WIN32
		closesocket(pfd.fd);
#else
		close(pfd.fd);
#endif // WIN32

		return	$LOG(STS$K_ERROR, "fcntl(%d)->%d", pfd.fd, __ba_errno__);
		}

	/* Try to connect to remote host */
	inet_ntop(AF_INET, &sk->sin_addr, buf, sizeof (buf));
	$IFTRACE (g_trace, "[#%d] Connecting to %s:%d (timeout is %d msec) ...", pfd.fd, buf, ntohs(sk->sin_port), timespec2msec (&g_timers_set.t_conn));

	if ( 0 > (status = connect(pfd.fd, (struct sockaddr *) sk, slen))
	#ifdef WIN32
		&& (__ba_errno__ != WSAEINPROGRESS) && (__ba_errno__ != WSAEALREADY) && (__ba_errno__ != WSAEWOULDBLOCK) )
	#else
		&& (errno != EINPROGRESS) && (errno != EALREADY) )
	#endif // WIN32
		$LOG(STS$K_ERROR, "connect(%s:%d)->%d, errno=%d", buf, ntohs(sk->sin_port), status, __ba_errno__);
	else	{
		/* Start waiting for establishing TCP-connection ... */
	#ifdef WIN32
		if( 0 >  (status = WSAPoll (&pfd, 1, status = timespec2msec (&g_timers_set.t_conn))) )
	#else
		if( 0 >  (status = poll(&pfd, 1, timespec2msec (&g_timers_set.t_conn))) )
	#endif // WIN32
			$LOG(STS$K_ERROR, "poll(%d, POLLOUT)->%d, errno=%d", pfd.fd, status, __ba_errno__);
		else if ( (status == 1) && (pfd.revents & POLLOUT) )
			status = 0;	/* Connected !!! */
		else	{
			$IFTRACE(g_trace, "sd=%d, status=%d, errno=%d, pfd.revents=%08x",
				pfd.fd, status, __ba_errno__, pfd.revents);

			status = $LOG(STS$K_ERROR, "[#%d] Timeout in connection request to %s:%d.", pfd.fd, buf, ntohs(sk->sin_port));
			}
		}

	/*
	 * Check result of establishing of TCP-connection
	 */
	if ( status )
		{
	#ifdef WIN32
		closesocket(pfd.fd);
	#else
		close(pfd.fd);
	#endif // WIN32
		return STS$K_ERROR;
		}

	if ( !( 1 & __set_nonbio_flag (pfd.fd, off)) )
		{
	#ifdef WIN32
		closesocket(pfd.fd);
	#else
		close(pfd.fd);
	#endif // WIN32
		return	$LOG(STS$K_ERROR, "fcntl(%u)->%d", pfd.fd, __ba_errno__);
		}

	status = sizeof(struct sockaddr);
	getsockname (pfd.fd, (struct sockaddr *) &lsock,  (socklen_t *) &status);

	$IFTRACE(g_trace, "[#%d] Connection %s:%d->%s:%d has been established", pfd.fd,
		inet_ntop(AF_INET, &lsock.sin_addr, tmp, sizeof (tmp)), ntohs(lsock.sin_port), buf, ntohs(sk->sin_port));

	*sd = pfd.fd;

	return	STS$K_SUCCESS;
}

/*
 *   DESCRIPTION: Read specified number of  bytes from the network socket, wait if not all data has been get
 *		but no more then timeout.
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer to accept data
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	buf:	Received data
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
static inline	int __recv_n
		(
		int	sd,
		void	*buf,
		int	bufsz,
	struct timespec	*delta
		)
{
int	status, restbytes = bufsz;
#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLIN, 0};
#else
struct pollfd pfd = {sd, POLLIN, 0};
#endif // WIN32

struct timespec	now, etime;
char	*bufp = (char *) buf;

	/* Compute an end of I/O operation time	*/
#ifdef WIN32
	timespec_get(&now, TIME_UTC);
#else
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, __ba_errno__);
#endif

	__util$add_time (&now, delta, &etime);

	for ( restbytes = bufsz; restbytes; )
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
			$LOG(STS$K_WARN, "[#%d] poll()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, __ba_errno__, bufsz, restbytes);
			continue;
			}


		if ( pfd.revents & (~POLLIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, __ba_errno__);

		if ( !(pfd.revents & POLLIN) )	/* Non-interesting event ?		*/
			continue;

		/* Retrieve data from socket buffer	*/
		if ( restbytes == (status = recv(sd, bufp, restbytes, 0)) )
			return	STS$K_SUCCESS; /* Bingo! We has been received a requested amount of data */

#ifdef WIN32
		if ( (0 >= status) && (errno != WSAEINPROGRESS) )
#else
		if ( (0 >= status) && (errno != EINPROGRESS) )
#endif
			{
			$LOG(STS$K_ERROR, "[#%d] recv(%d octets)->%d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, __ba_errno__);
			break;
			}

		/* Advance buffer pointer and decrease expected byte counter */
		restbytes -= status;
		bufp	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not get requested %d octets in %d msecs, rest %d octets", sd, bufsz, timespec2msec (delta), restbytes);
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
static inline int	__xmit_n
		(
		int	sd,
		void	*buf,
		int	bufsz
		)
{
int	status, restbytes = bufsz;
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

	__util$add_time (&now, &g_timers_set.t_xmit, &etime);

	for ( restbytes = bufsz; restbytes; )
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
			return	$LOG(STS$K_ERROR, "[#%d] poll()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, __ba_errno__, bufsz, restbytes);

	#ifdef WIN32
		if ( (status < 0) && (__ba_errno__ == WSAEINTR) )
	#else
		if ( (status < 0) && (__ba_errno__ == EINTR) )
	#endif
			{
			$LOG(STS$K_WARN, "[#%d] poll()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, __ba_errno__, bufsz, restbytes);
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
		if ( restbytes == (status = send(sd, bufp, restbytes, 0)) )
	#else
		if ( restbytes == (status = send(sd, bufp, restbytes, MSG_NOSIGNAL)) )
	#endif
			return	STS$K_SUCCESS; /* Bingo! We has been sent a requested amount of data */

		if ( 0 >= status )
			{
			$LOG(STS$K_ERROR, "[#%d] send(%d octets)->%d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, errno);
			break;
			}

		/* Advance buffer pointer and decrease byte counter to be sent */
		restbytes -= status;
		bufp	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not put requested %d octets, rest %d octets", sd, bufsz, restbytes);
}




/*
 *   DESCRIPTION: Read HTTP Header from the network socket.
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer to accept data
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	buf:	Received data
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
inline	static int __rx_header
		(
		int	sd,
		char	*bufp,
		int	bufsz,
		int	*buflen
		)
{
int	status;
#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLIN, 0};
#else
struct pollfd pfd = {sd, POLLIN, 0};
#endif // WIN32
char	*cp;
struct timespec	now, etime;


	*buflen = 0;


	/* Compute an end of I/O operation time	*/
#ifdef WIN32
	timespec_get(&now, TIME_UTC);
#else
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, __ba_errno__);
#endif

	__util$add_time (&now, &g_timers_set.t_req, &etime);

	for ( cp = bufp; bufsz; )
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
		if( 0 >  (status = WSAPoll(&pfd, 1, timespec2msec (&g_timers_set.t_req))) && (__ba_errno__ != WSAEINTR) )
#else
		if( 0 >  (status = poll(&pfd, 1, timespec2msec (&g_timers_set.t_req))) && (__ba_errno__ != EINTR) )
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
		if ( 1 != (status = recv(sd, cp, 1, 0)) )
			{
			$LOG(STS$K_ERROR, "[#%d] recv(1 octet)->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, errno);
			break;
			}

		cp++;
		bufsz--;

		if ( ((cp - bufp) > 4)
			&& (status = ((*((int *) (cp - sizeof(CRLFCRLF_LW)))) == CRLFCRLF_LW)) )
				{
				*buflen = cp - bufp;
				return	STS$K_SUCCESS;
				}
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not get whole HTTP request", sd);
}





/*
 *  DESCRIPTION: Initialize a context for network service, establish a connection
 *	to specified remote  address and port.
 *
 *  INPUT:
 *	host:	A remote host IP address or name
 *	port:	A TCP port number
 *
 *  OUTPUT:
 *	sd:	a socket descriptor, by address
 *	sk:	filled socket structure, by address
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */

static	int	__connect	(
		CTLCTX	*	ctx,
		ASC	*	host,
		unsigned short	port,
			int *	sd,
	struct sockaddr_in	*sk
			)
{
int	status, len;
char	buf[512], service[32] = {0}, *phost, host2[512] = {0};
struct	sockaddr_in	rsock = {0};

	$IFTRACE(g_trace, "Host's URL '%.*s' (default port=%d)", $ASC(host), port);

	host->sts[host->len] = '\0';
	memset(sk, 0, sizeof(struct sockaddr_in));

	if ( sscanf($ASCPTR(host), "%256[^:]:%6[0-9]", host2, service) )
		phost = host2;
	else	phost = $ASCPTR(host);

	rsock.sin_family = AF_INET;

	if ( status = atoi(service) )
		rsock.sin_port = htons(status);
	else	rsock.sin_port = htons(port);

	/* Is we got the IP address ? */
	if ( inet_pton(AF_INET, phost, &rsock.sin_addr) )
		{
		if ( 1 & (status = __connect_by_sock ( ctx, &rsock, sd)) )
			*sk = rsock;
		}
	else    {
		if ( !(1 & (status = __ns_query(ctx, host2, &rsock.sin_addr))) )
				return	status;

		if ( 1 & (status = __connect_by_sock ( ctx, &rsock, sd)) )
			*sk = rsock;
		}

	return	status;

}

#ifndef ANDROID
/* A simple replacement of the memmem() routine from POSIX */
static	inline	char *memmem	(
			char	*haystack,
			size_t	hlen,
			char	*needle,
			size_t	nlen
				)
{
char	*hlimit = haystack + hlen - nlen + 1;

	if ( !nlen )
		return haystack;/* degenerate edge case */

	if ( hlen < nlen )
		return 0;	/* another degenerate edge case */

	while ( haystack = memchr(haystack, *needle, hlimit - haystack) )
		{
		if ( !memcmp(haystack, needle, nlen) )
			return haystack;

		haystack++;
		}


	return 0;
}
#endif // ANDROID


/*
 *  DESCRIPTION: Extract host/port pair from the "Host:" field of the HTTP's header
 *
 *  INPUT:
 *	bufp:	A buffer with a HTTP header
 *	bufsz:	A length of the HTTP header
 *
 *  OUTPUT:
 *	host:	A remote host IP address or name
 *	port:	A TCP port number
*
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */
inline static int	__get_host	(
		char	*bufp,
		int	bufsz,
		ASC	*host,
		int	*port
			)
{
int	len = 0;
char	buf[512], buf2[512],  sport[32] = {0}, *cp, *cp2;

	host->len = 0;
	host->sts[0] = 0;

	/* Host: server.example.com:80 */
	if ( !(cp =  memmem(bufp, bufsz, http_host, sizeof(http_host) - 1)) )
		return	$LOG(STS$K_ERROR, "No '%s' field in the '%.*s", http_host, bufsz, bufp);

	cp += sizeof(http_host) - 1;

	len = bufsz - (cp - bufp);

	if ( cp2 = memchr(cp, '\r', len) )
		len = cp2 - cp;

	memcpy(buf, cp, len);
	buf[len] = '\0';

	if ( sscanf(buf, "%128[^:]:%5[0-9]", buf2, sport ) )
		{
		__util$str2asc (buf2, host);
		*port = atoi(sport);
		*port = *port ? *port : 80;

		return	STS$K_SUCCESS;
		}



	return	$LOG(STS$K_ERROR, "Cannot extract 'Host:' field from '%.*s'", bufsz, bufp);
}

/*
 *  DESCRIPTION: Thread routine to performs processing single HTTP's request by follows step-by-step procedure:
 *	1. Get the target host from HTTP's header
 *	2. Establishing TCP-connection with the target host
 *	3. Resent original HTTP request (if it's not HTTP CONNECT !)
 *	4. Establishing TCP-connection with the master proxy
 *	5. Looping receive-transmit ...
 *
 *
 *  INPUT:
 *	preq:	A context with original request data
 *
 *  OUTPUT: NONE
 *
 *  RETURN: NONE
 *
 */

 typedef	 struct __ba_counters__ {
	unsigned long long	inm,	/* Received from master */
				outm,	/* Sent to master	*/
				inh,	/* Received from target host */
				outh;	/* Sent to target host	*/
} BA_COUNTERS;

static	void	__th_req	(
			REQCTX	*preq
			)
{
ASC	host;
int	port, insd = -1,  outsd = -1, status, len, needio;
struct sockaddr_in insk = {0}, outsk = {0};
BA_COUNTERS counters = { 0 };
#ifdef WIN32
WSAPOLLFD  pfd[2] = {0};
#else
struct pollfd pfd[2] = {0};
#endif // WIN32

	$IFTRACE(g_trace, "[%llx] Entering thread", preq->id);

	/* We expect to see HTTP's request header in the buffer,
	** extract target host and try connect
	*/
	if ( !( 1 & __get_host(preq->req, preq->len, &host, &port)) )
		{
		$LOG(STS$K_ERROR, "[%llx] Cannot extrat target information from 'Host:' field", preq->id);

		free(preq);
#ifdef	WIN32
		_endthread();
#else
		pthread_exit(NULL);
#endif
		}

	/* Establishing TCP-connection with the target host */
	if ( !(1 & __connect(preq->ctx, &host, port, &outsd, &outsk)) )
		{
		$LOG(STS$K_ERROR, "[%llx] Cannot communicate with host %.*s", preq->id, $ASC(&host));

		free(preq);
#ifdef	WIN32
		_endthread();
#else
		pthread_exit(NULL);
#endif
		};

	/* Resend original request if this is not HTTP' CONNECT */
#ifdef	WIN32
	if ( strnicmp ("CONNECT", preq->req, 7) )
#else
	if ( strncasecmp ("CONNECT", preq->req, 7) )
#endif

		{
		status = __xmit_n(outsd, preq->req, preq->len);
		$IFTRACE(g_trace, "[#%d] Resent original HTTP's request, %d octets, status=%#x\n%.*s", outsd, preq->len, status, preq->len,  preq->req);
		}

	/* Establishing TCP-connection with the master host */
	if ( !(1 & __connect(preq->ctx, &preq->ctx->master, 3128, &insd, &insk)) )
		{
		$LOG(STS$K_ERROR, "[%llx] Connecton back to master, errno=%d", preq->id, __ba_errno__);

		free(preq);
#ifdef	WIN32
		closesocket(outsd);
		_endthread();
#else
		close(outsd);
		pthread_exit(NULL);
#endif
		};

	/* Form HTTP's CONNECT request to open data channel with the master */
	preq->len = snprintf(preq->req, sizeof(preq->req), http_connect_data, $ASC(&preq->ctx->master), preq->id, $ASC(&preq->ctx->auth));
	status = __xmit_n(insd, preq->req, preq->len);

	/* Get HTTP 200 OK ?	*/
	status = __rx_header(insd, preq->req, sizeof(preq->req), &len);

	/* Setup poll's stuff	*/
	pfd[0].fd = insd;
	pfd[1].fd = outsd;
	pfd[0].events = pfd[1].events = POLLIN;

	$IFTRACE(g_trace, "[%llx]  Main transmission loop ...");

	/* Main I/O loop: receive data - transmit data ... */
	while ( !g_exit_flag && (1 & status) )
		{
		needio = 0;	/* */

#ifdef WIN32
		if( !(status = WSAPoll(&pfd, 2, timespec2msec (&g_timers_set.t_xmit))) || (__ba_errno__ == WSAEINTR) )
#else
		if( !(status = poll(&pfd, 2, timespec2msec (&g_timers_set.t_xmit))) || (__ba_errno__ == EINTR) )
#endif // WIN32
			{
			status = STS$K_SUCCESS;
			continue;	/* No events, just timeout */
			}

		if ( status < 0 )
			{
			$LOG(STS$K_WARN, "[%llx] poll()->%d, errno=%d", preq->id, status, __ba_errno__);
			break;
			}

		if ( pfd[0].revents & POLLIN )
			{
			if ( 0 > (status = len = recv(insd, preq->req, sizeof(preq->req), 0)) )
				$LOG(STS$K_WARN, "[%llx] recv(%d)->%d, errno=%d", preq->id, insd, status, __ba_errno__);
			else if ( !len )	/* Remote peer has been closed connection */
				status = STS$K_ERROR;
			else    {
				counters.inm += len;

				if ( !(1 & (status = __xmit_n ( outsd, preq->req, len ))) )
					$LOG(STS$K_WARN, "[%llx] send(), errno=%d", preq->id, __ba_errno__);
				else    counters.outh += len;

				needio = 1;
				}
			}

		if ( pfd[1].revents & POLLIN )
			{
			if ( 0 > (status = len = recv(outsd, preq->req, sizeof(preq->req), 0)) )
				$LOG(STS$K_WARN, "[%llx] recv(%d)->%d, errno=%d", preq->id, outsd, status, __ba_errno__);
			else if ( !len )	/* Remote peer has been closed connection */
				status = STS$K_ERROR;
			else    {
				counters.inh += len;

				if ( !(1 & (status = __xmit_n ( insd, preq->req, len ))) )
					$LOG(STS$K_WARN, "[%llx] send(), errno=%d", preq->id, __ba_errno__);
				else    counters.outm += len;

				needio = 1;
				}
			}

		/*
		** We should be ensured that all data has been transmited, so we don't try to check disconnection if we need
		** to performs additionaly I/O
		*/
		if ( (!needio) && (pfd[0].revents & (~POLLIN)) || (pfd[1].revents & (~POLLIN)) )
			{
			$IFTRACE(g_trace, "[%llx] No I/O events (%#x, %#x)", preq->id, pfd[0].revents, pfd[1].revents);
			break;
			}
		}

	$IFTRACE(g_trace, "[%llx] Exiting thread, counters: master->host:%llu->%llu,  host->master:%llu->%llu", preq->id,
		counters.inm, counters.outh, counters.inh, counters.outm);

#ifdef WIN32
	shutdown(insd, SD_BOTH);
	shutdown(outsd, SD_BOTH);

	Sleep( timespec2msec( &g_timers_set.t_xmit) );

	closesocket(insd);
	closesocket(outsd);
#else
	close(insd);
	close(outsd);
#endif // WIN32

	free(preq);

#ifdef WIN32
	_endthread();
#endif // WIN32
}


/*
 *  DESCRIPTION: Thread routine to performs signaling data interchange with the master proxy.
 *
 *  INPUT:
 *	ctx:	A control's thread context area
 *
 *  OUTPUT: NONE
 *
 *  RETURN: NONE
 *
 */
static	int	__th_ctl	(
		CTLCTX	*ctx
			)
{
int	status, sd = -1, len;
struct sockaddr_in sk = {0};
#ifdef WIN32
WSAPOLLFD  pfd = {sd, POLLIN, 0};
#else
struct pollfd pfd = {sd, POLLIN, 0};
pthread_t	tid;
#endif // WIN32

REQCTX	*req, *preq;
char	buf[8192];

	$LOG(STS$K_INFO, "Control thread is up & running ....");

	if ( !(req = calloc(1, sizeof(REQCTX))) )
		return	$LOG(STS$K_ERROR, "Cannot allocate memory for a  %d octets", sizeof(REQCTX));

	while ( !g_exit_flag )
		{
		/* Connect or reconnect ... */
		while ( !g_exit_flag && (sd < 0) )
			{
			if ( ctx->cbrtn )
				ctx->cbrtn(ctx->cbarg, BP$K_BAGCTLDOWN);

#ifdef	WIN32
			Sleep(timespec2msec(&g_timers_set.t_conn));
#else
			{
			struct timespec delta = g_timers_set.t_conn;
			while (nanosleep(&delta, &delta));
			}
#endif

			if ( 1 & __connect(ctx, &ctx->master, 3128, &sd, &sk) )
				{
				/* Send login sequence ... */
				len = snprintf(buf, sizeof(buf), http_connect_ctl, $ASC(&ctx->master), $ASC(&ctx->auth) );

				if ( 1 & (status = __xmit_n(sd, buf, len)) )
					{
					$IFTRACE(g_trace, "Sent %d octets, status=%#x\n%.*s", len, status, len, buf);

					/* Wait for answer ... */
					len = 0;

					if ( 1 & (status = __rx_header(sd, buf, sizeof(buf), &len)) )
						{
						$IFTRACE(g_trace, "Received %d octets, status=%#x\n%.*s", len, status, len, buf);

						$LOG(STS$K_SUCCESS, "[#%d] Control channel has established", sd);


						if ( ctx->cbrtn )
							ctx->cbrtn(ctx->cbarg, BP$K_BAGCTLUP);


						pfd.fd = sd;
						break;
						}
					}

				$LOG(status, "[#%d] Error open control channel", sd);

#ifdef WIN32
				closesocket(sd);
#else
				close(sd);
#endif // WIN32
				sd = -1;
				}
			}

		/*
		 * Purge NS cache ...
		 */
		status = __ns_cache_purge ();


		/*
		* Wait for I/O event on the control channel
		*/
#ifdef WIN32
		if( 0 >  (status = WSAPoll(&pfd, 1, 3000)) && (__ba_errno__ == WSAEINTR) )
#else
		if( 0 >  (status = poll(&pfd, 1, 1000)) && (__ba_errno__ == EINTR) )
#endif // WIN32

		if ( 0 > status )
			{
			$LOG(STS$K_WARN, "[#%d] poll()->%d, errno=%d", sd, status, __ba_errno__);

#ifdef WIN32
			closesocket(sd);
#else
			close(sd);
#endif

			sd = -1;
			continue;
			}

		if ( pfd.revents & (~POLLIN) )	/* Unexpected events ?!			*/
			{
			$LOG(STS$K_ERROR, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d", sd, status, pfd.revents, pfd.events, __ba_errno__);

#ifdef WIN32
			closesocket(sd);
#else
			close(sd);
#endif

			sd = -1;
			continue;
			}

		if ( !(pfd.revents & POLLIN) )	/* Non-interesting event ?		*/
			continue;

		/* Read fixed length Request Id sequence */
		if ( !(1 & __recv_n(sd, &req->id, sizeof(req->id), &g_timers_set.t_req)) )
			{
			$LOG(STS$K_ERROR, "[#%d] Error reading ReqId", sd, status, pfd.revents, pfd.events, __ba_errno__);

#ifdef WIN32
			closesocket(sd);
#else
			close(sd);
#endif
			sd = -1;
			continue;
			}
		$IFTRACE(g_trace, "[#%d] ReqId=%llx", sd, req->id);


		/* Read HTTP Header */
		if ( !(1 & __rx_header(sd, req->req, sizeof(req->req), &req->len)) )
			{
			$LOG(STS$K_ERROR, "[#%d] Error reading ReqId", sd);

#ifdef WIN32
			closesocket(sd);
#else
			close(sd);
#endif

			sd = -1;
			continue;
			}

		$IFTRACE(g_trace, "[#%d] (%d octets)\n%.*s", sd, req->len, req->len, req->req);


		/* So, we got in to 'rqpt' from  master, allocate context for a new thread, create detached thread */
		if ( !(preq = malloc(sizeof(REQCTX))) )
			{
			$LOG(STS$K_ERROR, "[%llx] Cannot allocate memory for a request packet (%d octets)", req->id, sizeof(REQCTX));
			continue;
			}

		/* Copy data to new REQuest context*/
		preq->ctx = ctx;
		preq->id = req->id;
		memcpy(preq->req, req->req, preq->len = req->len);

#ifndef	WIN32
		if ( status = pthread_create(&tid, &g_th_attr, __th_req, preq) )
#else

		if (  0  > (status =  _beginthread( __th_req, 0, preq )) )

#endif

			{
			$LOG(STS$K_ERROR, "[%llx]Error starting thread, errno=%d", preq->id, errno);
			free(preq);

			continue;
			}
		}


	free(ctx);
	free(req);

#ifdef WIN32
	closesocket(sd);
	_endthread();
#else
	close(sd);
#endif // WIN32

	return	$LOG(STS$K_WARN, "Control thread is stopped, exit_flag=%d", g_exit_flag);
}



/*
 *  DESCRIPTION: BAGENT's API routine: initialize context area for a new control thread, it is supposed to be called
 *		one for every master. Created context is should be used on calling other  BAGENT's API routines:
 *		bagent_start();
 *		bagent_stop();
 *
 *  INPUT:
 *	master:		A master IP:Port pais string
 *	auth:		A username:password pair is supposed to be used for authorization on master
 *	extbind:	An interface name or IP address
 *	nserver:	Name Server(-s) list
 *	trace:		Turn On extensible diagnositc output
 *	cbrtn:		Callback routine
 *	cbarg:		Callback's routine arguments
 *
 *  OUTPUT:
 *	ctx:	Newly created context
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */
int	bagent_init	(
		ASC	*master,
		ASC	*auth,
		ASC	*extbind,
		ASC	*nserver,
		int	 trace,
		void	*cbrtn,
		void	*cbarg,
		void	**ctx
		)
{
int	status, i, count;
CTLCTX	*pctx = NULL;

	g_trace = trace;
	g_exit_flag  = 0;

	*ctx = NULL;

	/* Sanity cheks */
	if ( !master || !auth )
		return	$LOG(STS$K_ERROR, "No arguments");

	if ( !$ASCLEN(master) || !$ASCLEN(auth) )
		return	$LOG(STS$K_ERROR, "Checking of input arguments");

#ifndef	WIN32
	if ( status = pthread_attr_init(&g_th_attr) )
		return	$LOG(STS$K_ERROR, "Error initalize thread's attribute, pthread_attr_init()->%d, errno=%d", status, errno);

	if ( status  = pthread_attr_setdetachstate(&g_th_attr, PTHREAD_CREATE_DETACHED) )
		return	$LOG(STS$K_ERROR, "Error initalize thread's attribute, pthread_attr_setdetachstate()->%d, errno=%d", status, errno);

#endif


	/* Allocate area for a new control thread context */
	if ( !(pctx = calloc(1, sizeof(CTLCTX))) )
#ifndef WIN32
		return	$LOG(STS$K_ERROR, "Cannot allocate memory (%d octets), errno=%d", sizeof(CTLCTX), errno);
#else
		return	$LOG(STS$K_ERROR, "Cannot allocate memory (%d octets), errno=%d", sizeof(CTLCTX), GetLastError());
#endif


	/* Encode username:password sting in to the base64 */
	__util$base64($ASCPTR(auth), $ASCLEN(auth), $ASCPTR(&pctx->auth), ASC$K_SZ, &count);
	$ASCLEN(&pctx->auth) = (unsigned char) count;

	/* Make local copies of configuration parametsr */
	pctx->master = *master;

	/* Store stuff for Callback */
	pctx->cbrtn = cbrtn;
	pctx->cbarg = cbarg;


#ifdef WIN32

	InitializeCriticalSection(&pipe_lock);
	InitializeCriticalSection(&ns_lock);

	{
	WSADATA wsaData;

	if ( status = WSAStartup(MAKEWORD(2, 2), &wsaData) )
		return	$LOG(STS$K_ERROR, "Network initialization, WSAStartup->%d, errno=%d", status, __ba_errno__);
	}
#endif // WIN32


	pctx->extbind_sk.sin_addr.s_addr = htonl(INADDR_ANY);
	pctx->extbind_sk.sin_family = AF_INET;
	pctx->extbind_sk.sin_port = 0; //htons(33333);

	if ( extbind && $ASCLEN(extbind) )
		{
		$ASCLEN(extbind) = __util$collapse ($ASCPTR(extbind), $ASCLEN(extbind));

		pctx->extbind = *extbind;

		if ( !inet_pton(pctx->extbind_sk.sin_family = AF_INET, $ASCPTR(extbind), &pctx->extbind_sk.sin_addr) )
			$LOG(STS$K_WARN, "Cannot convert '%.s' to internal representative, errno=%d", $ASC(&extbind), errno );
		}


	memset(pctx->sdns, -1, sizeof(pctx->sdns));

	if ( nserver && $ASCLEN(nserver) )
		{
		char	*cp, *saveptr;

		$ASCLEN(nserver) = __util$collapse ($ASCPTR(nserver), $ASCLEN(nserver));

		for ( i = 0, saveptr = NULL;
		#ifndef WIN32
			(i < BP$K_NSMAX) && (cp = strtok_r(saveptr ? NULL : $ASCPTR(nserver), ",", &saveptr));
		#else
			(i < BP$K_NSMAX) && (cp = strtok_s(saveptr ? NULL : $ASCPTR(nserver), ",", &saveptr));
		#endif // !WIN32
				i++ )
			{
			$IFTRACE(g_trace, "#%02.2d : Parse NS '%s'", i, cp);

			if ( !inet_pton(AF_INET, cp, &pctx->ns[i].sin_addr) )
				{
				$LOG(STS$K_ERROR, "Cannot convert '%s' to IP", cp);
				continue;
				}

			pctx->ns[i].sin_port = htons(53);
			pctx->ns[i].sin_family = AF_INET;

			$IFTRACE(g_trace, "NS server #%02.2d=%s", i, cp);

			}

		if ( !(1 & __ns_init (pctx)) )
			$LOG(STS$K_ERROR, "Name Server initialization failed");
		}


	/* Return new context */
	* ((CTLCTX **) ctx) = pctx;


	/* Initialize cache for IP name-IP address */
	if ( !nscache )
		{
#ifndef WIN32
		if ( status = pthread_rwlock_init(&ns_cache_lock, 0) )
			return	$LOG(STS$K_ERROR, "NS Cache initialization error, pthread_rwlock_init(()->%d, errno=%d", status, errno);
#else
#endif

		if ( !(nscache = calloc(BP$K_NSCACHE, sizeof(NS_ENTRY))) )
#ifndef WIN32
		$LOG(STS$K_ERROR, "Cannot allocate memory (%d octets), errno=%d", sizeof(CTLCTX), errno);
#else
			$LOG(STS$K_ERROR, "Cannot allocate memory (%d octets), errno=%d", sizeof(CTLCTX), GetLastError());
#endif

		else    $LOG(STS$K_SUCCESS, "Created NS cache for %d entries", BP$K_NSCACHE);
		}




	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: BAGENT's API routine: start executing of control thread with the has been created context.
 *
 *  INPUT:
 *	ctx:	context has been intialized by bagent_init()
 *
 *  OUTPUT: NONE
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */

int	bagent_start	(
		void	*ctx
			)
{
unsigned	status;
CTLCTX	*pctx = (CTLCTX *) ctx;

	/* Sanity checks */
	if ( !ctx )
		return	$LOG(STS$K_ERROR, "No context is provided");

	$IFTRACE(g_trace, "Starting Control thread ...");

#ifndef	WIN32
	if ( status = pthread_create(&pctx->tid_ctl, &g_th_attr, __th_ctl, pctx) )
		return	$LOG(STS$K_ERROR, "Error starting control thread, pthread_create()->%d, errno=%d", status, errno);
#else

	if (  0   > (status = pctx->tid_ctl =  _beginthread( __th_ctl, 0, pctx )) )
		return	$LOG(STS$K_ERROR, "Error starting control thread, errno=%d",GetLastError());
#endif

	$IFTRACE(g_trace, "Control thread has been started, tid=%d.", pctx->tid_ctl);

	if ( pctx->cbrtn )
		pctx->cbrtn(pctx->cbarg, BP$K_BAGUP);


	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: BAGENT's API routine: set global 'stop all threads' flag, if wait flag is non-zero - take some seconds to
	finishing threads.
 *
 *  INPUT:
 *	ctx:	context has been intialized by bagent_init()
 *
 *  OUTPUT: NONE
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */
int	bagent_stop	(
		void	*ctx,
		int	wait_flag
			)
{
CTLCTX	*pctx = (CTLCTX *) ctx;

	/* Sanity checks */
	if ( !ctx )
		return	$LOG(STS$K_ERROR, "No context is provided");

	g_exit_flag = $LOG(STS$K_INFO, "Set exit flag!");

	if ( wait_flag )
#ifdef	WIN32
		Sleep(3000);
#else
		sleep(3);
#endif

	if ( pctx->cbrtn )
		pctx->cbrtn(pctx->cbarg, BP$K_BAGDOWN);

	return	STS$K_SUCCESS;
}

/*
 *  DESCRIPTION: BAGENT's API routine: set global 'stop all threads' flag, if wait flag is non-zero - take some seconds to
	finishing threads.
 *
 *  INPUT:
 *	ctx:	context has been intialized by bagent_init()
 *
 *  OUTPUT: NONE
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */
int	bagent_shut	(
		void	*ctx,
		int	wait_flag
			)
{
int	status;

	/* Sanity checks */
	if ( !ctx )
		return	$LOG(STS$K_ERROR, "No context is provided");

	g_exit_flag = $LOG(STS$K_INFO, "Set exit flag!");

	if ( wait_flag )
#ifdef	WIN32
		Sleep(3000);
#else
		sleep(3);
#endif


	free(ctx);

#ifndef	WIN32
	if ( status = pthread_rwlock_destroy(&ns_cache_lock) )
		return	$LOG(STS$K_ERROR, "pthread_rwlock_destroy()->%d, errno=%d", status, errno);
#else
#endif


#ifdef	WIN32
		DeleteCriticalSection(&pipe_lock);
		DeleteCriticalSection(&ns_lock);
#endif

	return	STS$K_SUCCESS;
}


/*
 *  DESCRIPTION: BAGENT's API routine: retrieve identefication and version string.
 *
 *  INPUT:
 *	NONE
 *
 *  OUTPUT:
 *	ident:	BAGENT API Identification string
 *	ver:	Version/revision code
 *
 *  RETURN:
 *	Condition code, see STS$K_* constants.
 */

int	bagent_info	(
		ASC	*ident,
		ASC	*rev
			)
{
	if ( ident )
		*ident = __ident__;

	if ( rev )
		*rev = __rev__;

	return	STS$K_SUCCESS;
}



#ifndef __CALLABLE_BAGENT__


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
**  DESCRIPTION: A template for the callback function. Don't forget to include <stdarg.h> in your module.
**
**  INPUT:
**	ctx:	a callback context argument has been passed into the bagent_init()
**	what:	see BP$K_* constants:
**	sd:	is an optional argument is passed if what==BP$K_PROTSD
**
**  OUTPUT:
**	NONE
**
**  RETURN:
**	NONE
*/

static	void	callback ( void *cbarg, int what, ...)
{
#if	ANDROID
/* Globals for callback function */
JavaVM* javaVM = NULL;
jclass bagentClass;
jobject bagentObj;
JNIEnv *env;
#endif	/* ANDROID */

	$IFTRACE(g_trace, "CallBack is called: ctx=%p, what=%d, ...", cbarg, what);

	switch (what)
		{
		case	BP$K_BAGUP:
		case	BP$K_BAGDOWN:
		case	BP$K_BAGCTLUP:
		case	BP$K_BAGCTLDOWN:
			$LOG(STS$K_INFO, "Got notification #%d from BAGENT", what);
			break;

#if	ANDROID
		case	BP$K_PROTSD:
			{
			int	sd = -1;
			va_list ap;

			/* ‘sd’ (to be protected from VPN routing)  is coming as third argument,
			** point pointer to next after 'what' argument in stack
			*/
			va_start(ap, what);
			sd  = (int) va_arg(ap, int);
			va_end(ap);

			$IFTRACE(g_trace, "Got sd=%d", sd);

			/* Prepare jvm and call Java method */
			(*javaVM)->AttachCurrentThread(javaVM, &env, NULL);
			jmethodID method = (*env)->GetMethodID(env, bagentClass, "protectBagentSocketCallback", "(I)V");
			(*env)->CallVoidMethod(env, bagentObj, method, sd);



			} /* case BP$K_PROTSD */
			break;
#endif	/* ANDROID */
		default:
			$LOG(STS$K_ERROR, "Uhandled function code %#x", what);
		}

	return;
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
int	status, trace;
ASC	logfspec = {0}, confspec = {0}, master = {0}, auth = {0},
	nserver = {$ASCINI("127.0.0.1")}, extbind = {0};

const OPTS optstbl [] =		/* Configuration options		*/
{
	{$ASCINI("config"),	&confspec, ASC$K_SZ,	OPTS$K_CONF},
	{$ASCINI("master"),	&master, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("auth"),	&auth, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("trace"),	&trace, 0,		OPTS$K_OPT},
	{$ASCINI("nserver"),	&nserver, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("extbind"),	&extbind, ASC$K_SZ,	OPTS$K_STR},
	{$ASCINI("logfile"),	&logfspec, ASC$K_SZ,	OPTS$K_STR},

	OPTS_NULL
};
void	*ctx = NULL;
ASC	ident = {0}, rev = {0};

	/*
	 * Process command line arguments
	 */
	__util$getparams(argc, argv, optstbl);


	if ( $ASCLEN(&logfspec) )
		{
		/* Assign output for loggin to the specified file */
		__util$deflog($ASCPTR(&logfspec), NULL);
		}



	bagent_info(&ident, &rev);
	$LOG(STS$K_INFO, "IDENT: %.*s, Revision: %.*s", $ASC(&ident), $ASC(&rev) );

	/* Printout current configuration parameters */
	if ( g_trace )
		__util$showparams(optstbl);

	/* Just for fun */
	init_sig_handler ();

#ifdef WIN32
	/* Add special condition to the OpenVPN's filters */
	status = __set_dns_filters(argv[0]);
#endif // WIN32



	/* Initialize BAGENT's internal contexts */
	if ( !(1 & (status = bagent_init(&master, &auth, &extbind, &nserver, trace, NULL, NULL, &ctx))) )
		return	$LOG(status, "Error initialization context for '%.*s'", $ASC(&master));

#if	1
	{
	//char	hostname[512] = "r3---sn-5hne6nsk.googlevideo.com";
	char	hostname [] = "detectportal.firefox.com";
	struct in_addr ip;

	g_trace = 1;

	while ( !g_exit_flag )
		{
		__ns_query (ctx, "detectportal.firefox.com", &ip);
		__ns_query (ctx, "r3---sn-5hne6nsk.googlevideo.com", &ip);
		__ns_query (ctx, "detectportal.firefox.com", &ip);
		__ns_query (ctx, "r3---sn-5hne6nsk.googlevideo.com", &ip);

		status = 3;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32

		__ns_cache_purge ();

		}

	exit(0);
	}
#endif

	/* Start BAGENT */
	if ( !(1 & (status = bagent_start(ctx))) )
		return	$LOG(status, "Error start control thread for '%.*s'", $ASC(&master));


	/* Do nothing  - we watching 'g_exit_flag' only for demonstration purpose !!!... */
	while ( !g_exit_flag )
		{
		status = 3;

		#ifdef WIN32
			Sleep(status * 1000);
		#else
			for (; status = sleep(status); );
		#endif // WIN32
		}

	/* Stop BAGENT's threads ... */
	status = bagent_stop( ctx,  1 /* Let's wait some time to finishing thread correctly*/ );

#ifdef WIN32
	status = __delete_dns_filters();
#endif

	/* Get out !*/
	$LOG(STS$K_INFO, "Exiting with exit_flag=%d!", g_exit_flag);
}

#endif // !__CALLABLE_BAGENT__