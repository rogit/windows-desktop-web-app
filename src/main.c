/*
	https://github.com/rogit/windows-desktop-web-app
*/

#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <shellapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <io.h>

#define RtlGenRandom SystemFunction036
BOOLEAN WINAPI RtlGenRandom ( PVOID, ULONG );

#define BYTES_TO_READ_FROM_WEB_SERVER 1024
#define MAX_BYTES_TO_READ_FROM_WEB_SERVER BYTES_TO_READ_FROM_WEB_SERVER * 10
#define START_BUFFER_MAX 2048
#define ONE_MAX_READ 80
#define TOTAL_MAX_READ 512
#define HTTP_REQUEST_MAX_SIZE 2048

const char * PHP_EXE = "php\\php.exe", * WWW_FOLDER = "www", * DATA_FOLDER = "data", * PORT_FILE = "data\\port";
const char * INSTANCE_FILE_NAME = "\\instance", * INSTANCE_FILE_PATH = "www\\instance";
unsigned int startBufferSize = 0, webLastRequestTime, PORT_WEB = 0, PORT_INTER;
const unsigned int WAIT_FOR_SERVER_START = 3; //seconds
char startBuffer[START_BUFFER_MAX], * SECRET;
BOOL webStarted = FALSE,_logging = FALSE;
CRITICAL_SECTION csLog;

// settings.ini
const char * SETTINGS_FILE = ".\\config\\settings.ini";
#define MAX_INI_STR_LENGTH 128
unsigned int START_PORT_WEB, END_PORT_WEB, LOGGING, DEBUG, MAX_INTERVAL_SEC, MAX_JOBS;
char LOG_FILE[MAX_INI_STR_LENGTH+1], PUT_JOB_URL[MAX_INI_STR_LENGTH+1], TERMINATE[MAX_INI_STR_LENGTH+1];

typedef struct {
	char * text;
	void * next;
} Output;

typedef struct {
	unsigned long dataLength;
	BOOL encode, terminated;
	char * jobCmd, * jsonStart, * jobId;
	unsigned char started, finished;
	DWORD exitCode;
	Output * outFirst, * outLast;
	HANDLE hChildStd_OUT_Rd, hChildStd_OUT_Wr, hChildStd_IN_Rd, hChildStd_IN_Wr;
	PROCESS_INFORMATION procInfo;
	void * sendStatusHandler;
} JobT;

typedef struct {
	JobT ** job;
	JobT * web;
	unsigned int runningJobs, MAX_JOBS;
	BOOL webStopped;
	CRITICAL_SECTION cs;
} JobsT;

JobsT * jobs;

JobT * createJob ( char *, char *, BOOL, void * );
char * jsonEncodeJob ( JobT * );
void removeJob ( JobT * );
char * sendHttpRequest ( const char * , char *, char * );
BOOL startJob ( JobT * );
void freeOutput ( JobT * );
void hSendJobStatus ( JobT * );
void hLogWebServer ( JobT * );
void Debug ( char * );
void Log ( char *, BOOL );
void setWebLastRequestTime ( void );
BOOL pingPort ( unsigned int );
void terminateJob ( JobT * );
void exitAndClean ( int );
char * genRandomString ( unsigned int );

JobsT * initJobs ( unsigned int max_jobs  ) {
	unsigned int i;
	jobs = malloc ( sizeof ( JobsT ));
	InitializeCriticalSection ( &jobs->cs );
	jobs->MAX_JOBS = max_jobs + 1;
	jobs->job = malloc ( sizeof ( JobT * ) * jobs->MAX_JOBS );
	for ( i = 0; i < jobs->MAX_JOBS; i++ ) jobs->job[i] = NULL;
	jobs->runningJobs = 0;
	jobs->webStopped = FALSE;
	return jobs;
}

JobT * addJob ( char * jobId, char * jobCmd, BOOL encode, void (* sendStatusHandler)(JobT *) ) {
	unsigned int i;
	JobT * job;

	if ( jobs->runningJobs >= jobs->MAX_JOBS ) {
		Log ( "Maximum number of jobs is reached", TRUE );
		return NULL;
	}
	EnterCriticalSection ( &jobs->cs );
	job = createJob ( jobId, jobCmd, encode, sendStatusHandler );
	for ( i = 0; i < jobs->MAX_JOBS; i++ ) {
		if ( jobs->job[i] == NULL ) {
			jobs->job[i] = job;
			break;
		}
	}
	jobs->runningJobs++;
	LeaveCriticalSection ( &jobs->cs );
	if ( !startJob ( job )) {
		job->exitCode = 1;
		removeJob ( job );
		return NULL;
	}
	(*sendStatusHandler) ( job );
	return job;
}

void hLogWebServer ( JobT * job ) {
	unsigned int l;
	Output * el = job->outFirst;
	while ( el != NULL ) {
		if (( strstr ( el->text , "GET " ) != NULL ) || ( strstr ( el->text , "HEAD " ) != NULL ) || ( strstr ( el->text , "POST " ) != NULL ) || ( strstr ( el->text , "PUT " ) != NULL ) || ( strstr ( el->text , "DELETE " ) != NULL )) {
			setWebLastRequestTime ();
		}
		if ( !webStarted ) {
			l = strlen ( el->text );
			if ( startBufferSize + l < START_BUFFER_MAX ) {
				memcpy ( startBuffer+startBufferSize, el->text, l );
				startBufferSize += l;
				startBuffer[startBufferSize] = 0;
			}
		}
		Log ( el->text, FALSE );
		el = el->next;
	}
	freeOutput ( job );
}

void hSendJobStatus ( JobT * job ) {
	char * serialized, * response;
	if ( job->terminated ) return;
	serialized = jsonEncodeJob ( job );
	Debug ( "serialized job:" );
	Debug ( serialized );
	response = sendHttpRequest ( "POST", PUT_JOB_URL, serialized );
	free ( serialized );
	if ( response != NULL ) {
		Debug ( "hSendJobStatus response:" );
		Debug ( response );
		if ( strstr ( response, TERMINATE ) != NULL ) {
			job->terminated = TRUE;
			Log ( "Terminating job", TRUE );
			terminateJob ( job );
		}
		free ( response );
	}
	freeOutput ( job );
}

void removeJob ( JobT * job ) {
	unsigned int i;
	void (*sendStatusHandler) ( JobT *) = job->sendStatusHandler;

	job->finished = 1;
	sendStatusHandler ( job );
	EnterCriticalSection ( &jobs->cs );
	for ( i = 0; i < jobs->MAX_JOBS; i++ ) {
		if ( jobs->job[i] == job ) {
			jobs->job[i] = NULL;
			break;
		}
	}
	jobs->runningJobs--;
	LeaveCriticalSection ( &jobs->cs );
	if ( job == jobs->web ) jobs->webStopped = TRUE;
	free ( job->jobCmd );
	free ( job );
}

void waitForJobs ( void ) {
	unsigned int i;
	while (( jobs->runningJobs > 0 ) && ( !jobs->webStopped )) {
		Sleep ( 1000 );
	}
	// terminate all jobs if web server is stopped
	for ( i = 0; i < jobs->MAX_JOBS; i++ ) {
		if ( jobs->job[i] != NULL ) terminateJob ( jobs->job[i] );
	}
}

char * bin2hex ( unsigned char * str, unsigned int l ) {
	unsigned int i = 0;
	char * res = malloc ( l * 2 + 1 );
	for ( i = 0; i < l; i++ ) sprintf ( res + i*2, "%02x",  str[i] );
	return res;
}

void addOutput ( JobT * job, char * text, BOOL sendStatus ) {
	void (*sendStatusHandler) ( JobT *);
	Output * el;
	unsigned int l;

	if ( strlen ( text ) == 0 ) return;
	sendStatusHandler = job->sendStatusHandler;
	el = (Output *) malloc ( sizeof ( Output ));
	l = strlen ( text );
	if ( job->encode ) {
		Debug ( __func__ );
		Debug ( text );
		el->text = bin2hex ( text, l );
	} else {
		el->text = malloc ( l + 1 );
		memcpy ( el->text, text, l + 1 );
	}
	el->next = NULL;
	if ( job->outFirst == NULL ) {
		job->outFirst = el;
		job->outLast = el;
	} else {
		job->outLast->next = el;
		job->outLast = el;
	}
	job->dataLength += strlen ( el->text ) + 3; // "", or ""]
	if ( sendStatus ) sendStatusHandler ( job );
}

void freeOutput ( JobT * job ) {
	Output * el = job->outFirst;
	while ( el != NULL ) {
		job->dataLength -= strlen ( el->text ) + 3; // "", or ""]
		free ( el->text );
		job->outFirst = el->next;
		free ( el );
		el = job->outFirst;
	}
	job->outLast = NULL;
}

char * jsonEncodeJob ( JobT * job ) {
	char * res = malloc ( job->dataLength );
	unsigned int i;
	Output * el;

	sprintf ( res, job->jsonStart, job->jobId, job->started, job->finished, job->exitCode );
	i = strlen ( res );
	el = job->outFirst;
	while ( el != NULL ) {
		if ( el->next == NULL ) {
			sprintf ( res+i, "\"%s\"", el->text );
			i += strlen ( el->text ) + 2;
		} else {
			sprintf ( res+i, "\"%s\",", el->text );
			i += strlen ( el->text ) + 3;
		}
		el = el->next;
	}
	sprintf ( res+i, "]}" );
	return res;
}

void getLines ( JobT * job, char * buffer, unsigned int * dataLength ) {
	char * eol = strstr ( buffer, "\n" );
	if ( eol == NULL ) return;
	(*eol) = 0;
	*dataLength -= (eol-buffer+1);
	addOutput ( job, buffer, TRUE );
	memcpy ( buffer, eol+1, *dataLength );
	buffer[*dataLength] = 0;
	getLines ( job, buffer, dataLength );
}

DWORD WINAPI controlJob ( JobT * job ) {
	unsigned int dataLength = 0;
	DWORD bytesRead;
	char buffer[TOTAL_MAX_READ];
	while ( !job->terminated ) {
		if ( !ReadFile ( job->hChildStd_OUT_Rd, buffer+dataLength, ONE_MAX_READ, &bytesRead, NULL )) break;
		if ( bytesRead == 0 ) break;
		dataLength += bytesRead;
		buffer[dataLength] = 0;
		getLines ( job, buffer, &dataLength );

		if ( dataLength >= TOTAL_MAX_READ - ONE_MAX_READ ) {
			addOutput ( job, buffer, TRUE );
			dataLength = 0;
		}
	}
	buffer[dataLength] = 0;
	if ( dataLength > 0 ) addOutput ( job, buffer, FALSE );
	CloseHandle ( job->hChildStd_OUT_Rd );
	GetExitCodeProcess ( job->procInfo.hProcess, &job->exitCode );
	removeJob ( job );
	return 0;
}

BOOL pingPort ( unsigned int PORT ) {
	WSADATA wsadata;
	SOCKET sck;
	struct sockaddr_in sinRemote;
	struct hostent * HostAddress;
	int ret_val;

	WSAStartup ( 0x101, &wsadata );
	HostAddress = gethostbyname ( "127.0.0.1" );
	if ( HostAddress == NULL ) return FALSE;
	sck = socket ( AF_INET, SOCK_STREAM, 0 );
	sinRemote.sin_family = AF_INET;
	sinRemote.sin_port = htons ( PORT );
	sinRemote.sin_addr.s_addr = *((unsigned long *) HostAddress->h_addr);
	ret_val = connect (sck, (struct sockaddr *) &sinRemote, sizeof (sinRemote) );
	if ( ret_val == SOCKET_ERROR ) {
		closesocket ( sck );
		WSACleanup ();
		return FALSE;
	}
	shutdown ( sck, SD_BOTH );
	closesocket ( sck );
	WSACleanup ();
	return TRUE;
}

BOOL startJob ( JobT * job ) {
	SECURITY_ATTRIBUTES saAttr;
	HANDLE hControlJob = NULL;
	STARTUPINFO siStartInfo;

	ZeroMemory ( &saAttr, sizeof ( SECURITY_ATTRIBUTES ));
	saAttr.nLength = sizeof ( SECURITY_ATTRIBUTES );
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if ( !CreatePipe ( &(job->hChildStd_OUT_Rd), &(job->hChildStd_OUT_Wr), &saAttr, 0 )) {
		Log ( "Failed to create pipe", TRUE );
		return FALSE;
	}
	if ( !CreatePipe ( &(job->hChildStd_IN_Rd), &(job->hChildStd_IN_Wr), &saAttr, 0 )) {
		Log ( "Failed to create pipe", TRUE );
		return FALSE;
	}

	SetHandleInformation ( job->hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0 );
	SetHandleInformation ( job->hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0 );

	ZeroMemory ( &(job->procInfo), sizeof ( PROCESS_INFORMATION ));
	ZeroMemory ( &siStartInfo, sizeof ( STARTUPINFO ));

	siStartInfo.cb = sizeof ( STARTUPINFO );
	siStartInfo.wShowWindow = SW_HIDE;
	siStartInfo.hStdError = job->hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = job->hChildStd_OUT_Wr;
	siStartInfo.hStdInput = job->hChildStd_IN_Rd;
	siStartInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	if ( !CreateProcess (
		NULL,
		job->jobCmd, // command line
		NULL,     // process security attributes
		NULL,     // primary thread security attributes
		TRUE,     // handles are inherited
		CREATE_NO_WINDOW, // creation flags
		NULL,     // use parent's environment
		NULL,     // use parent's current directory
		&siStartInfo,  // STARTUPINFO pointer
		&(job->procInfo))) {
		addOutput ( job, "Failed to create process", FALSE );
		Log ( "Failed to create process", TRUE );
		return FALSE;
	}

	CloseHandle ( job->hChildStd_OUT_Wr );
	CloseHandle ( job->hChildStd_IN_Rd );
	CloseHandle ( job->hChildStd_IN_Wr );

	hControlJob = CreateThread ( 0, 0, (void*) controlJob, (void*) job, 0, NULL );
	if ( hControlJob == NULL ) {
		Log ( "Failed to create thread", TRUE );
		return FALSE;
	}

	job->started = 1;
	return TRUE;
}

JobT * createJob ( char * jobId, char * jobCmd, BOOL encode, void * sendStatusHandler ) {
	JobT * job = malloc ( sizeof ( JobT ));

	job->jobCmd = malloc ( strlen ( jobCmd ) + 1 );
	memcpy ( job->jobCmd, jobCmd, strlen ( jobCmd ) + 1 );

	job->jobId = malloc ( strlen ( jobId ) + 1 );
	memcpy ( job->jobId, jobId, strlen ( jobId ) + 1 );

	job->encode = encode;
	job->terminated = FALSE;
	job->sendStatusHandler = sendStatusHandler;
	job->outFirst = job->outLast = NULL;
	job->started = job->finished = job->exitCode = 0;
	job->hChildStd_OUT_Rd = NULL;
	job->hChildStd_OUT_Wr = NULL;
	job->hChildStd_IN_Rd = NULL;
	job->hChildStd_IN_Wr = NULL;
	job->jsonStart = "data={\"id\":\"%s\",\"started\":%d,\"finished\":%d,\"exitCode\":%d,\"output\":[";
	job->dataLength = strlen ( job->jsonStart ) + strlen ( job->jobId ) + 2; // } + 0x00
	return job;
}

char * sendHttpRequest ( const char * method, char * url, char * post_data ) {
	const char headers[] = "Content-Type: application/x-www-form-urlencoded";
	HINTERNET hConnect, hReq, hInternet;
	unsigned int dwCode, totalRead = 0;
	DWORD dwSize, bytesRead = 1;
	char * HTMLBuffer;

	hInternet = InternetOpen ( "AgentSmith", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 );
	if ( hInternet == NULL ) {
		Log ( "InternetOpen", TRUE );
		return NULL;
	}

	hConnect = InternetConnect ( hInternet, "localhost", PORT_WEB, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0 );
	if ( hConnect == NULL ) {
		Log ( "InternetConnect", TRUE );
		InternetCloseHandle ( hInternet );
		return NULL;
	};

	hReq = HttpOpenRequest ( hConnect, method, url, "HTTP/1.0", NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE, 0 );
	if ( hReq == NULL ) {
		Log ( "HttpOpenRequest", TRUE );
		InternetCloseHandle ( hConnect );
		InternetCloseHandle ( hInternet );
		return NULL;
	};

	if ( !HttpSendRequest ( hReq, headers, strlen(headers), post_data, strlen ( post_data ))) {
		Log ( "HttpSendRequest", TRUE );
		InternetCloseHandle ( hReq );
		InternetCloseHandle ( hConnect );
		InternetCloseHandle ( hInternet );
		return NULL;
	}

	HttpQueryInfo ( hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwCode, &dwSize, NULL );
	HTMLBuffer = malloc ( MAX_BYTES_TO_READ_FROM_WEB_SERVER );
	HTMLBuffer[0] = 0;
	while ( bytesRead ) {
		if ( !InternetReadFile ( hReq, HTMLBuffer+totalRead, BYTES_TO_READ_FROM_WEB_SERVER, &bytesRead )) {
			Log ( "InternetReadFile", TRUE );
			InternetCloseHandle ( hReq );
			InternetCloseHandle ( hConnect );
			InternetCloseHandle ( hInternet );
			HTMLBuffer[totalRead] = 0;
			return HTMLBuffer;
		}
		totalRead += bytesRead;
		if ( totalRead + bytesRead >= MAX_BYTES_TO_READ_FROM_WEB_SERVER ) break;
	};

	HTMLBuffer[totalRead] = 0;
	InternetCloseHandle ( hReq );
	InternetCloseHandle ( hConnect );
	InternetCloseHandle ( hInternet );
	return HTMLBuffer;
}

char * hex2bin ( char * str ) {
	long l, j;
	char * res;

	j = strlen ( str );
	if ( j < 2 ) return NULL;
	if ( j % 2 != 0 ) return NULL;
	l = j >> 1;
	res = malloc ( l + 1 );

	res[l] = 0;
	while ( --l >= 0 ) {
		j = l << 1;
		if (( str[j] >= '0' ) && ( str[j] <= '9' )) res[l] = ( str[j] - '0' ) << 4;
		else {
			if (( str[j] >= 'a' ) && ( str[j] <= 'f' )) res[l] = ( str[j] - 'a' + 10 ) << 4;
			else {
				free ( res );
				return NULL;
			}
		}
		j++;
		if (( str[j] >= '0' ) && ( str[j] <= '9' )) res[l] += ( str[j] - '0' );
		else {
			if (( str[j] >= 'a' ) && ( str[j] <= 'f' )) res[l] += ( str[j] - 'a'+ 10 );
			else {
				free ( res );
				return NULL;
			}
		}
	}
	return res;
}

BOOL FileExists ( const char * FilePath ) {
	struct stat FileInfo;
	return ( stat ( FilePath, &FileInfo ) != -1 );
}

void Debug ( char * text ) {
	if ( DEBUG ) Log ( text, TRUE );
}

void Log ( char * text, BOOL ownLog ) {
	FILE * LogFile;

	if (( !_logging ) || ( !LOGGING )) return;
	EnterCriticalSection ( &csLog );
	LogFile = fopen ( LOG_FILE, "a" );
	if ( LogFile != NULL ) {
		if ( ownLog ) {
			char s[32];
			time_t i = time ( NULL );
			sprintf ( s, "%s", ctime ( &i ));
			s[strlen(s)-1] = 0;
			fprintf ( LogFile, "[%s] exe %s\n", s, text );
		} else {
			fprintf ( LogFile, "%s\n", text );
		}
		fflush ( LogFile );
		fclose ( LogFile );
	}
	LeaveCriticalSection ( &csLog );
}

void setWebLastRequestTime ( void ) {
	webLastRequestTime = time ( 0 );
}

BOOL webIsNotRequested ( void ) {
	return ( time(0) - webLastRequestTime > MAX_INTERVAL_SEC );
}

BOOL openBrowser ( void ) {
	char str[32];
	int ret;
	sprintf ( str, "http://localhost:%d", PORT_WEB );
	ret = (int) ShellExecute ( NULL, "open", str, NULL, NULL, SW_SHOWNORMAL );
	sprintf ( str, "ShellExecute ret %d", ret );
	Debug ( str );
	return ret > 32;
}

BOOL checkRequiredFiles ( void ) {
	char text[512];

	if ( !FileExists ( PHP_EXE )) {
		MessageBox ( NULL, "File 'php/php.exe' does not exist", "Error", MB_ICONSTOP );
		return FALSE;
	}
	if ( !FileExists ( WWW_FOLDER )) {
		sprintf ( text, "Folder '%s' does not exist", WWW_FOLDER );
		MessageBox ( NULL, text, "Error", MB_ICONSTOP );
		return FALSE;
	}
	if ( !FileExists ( DATA_FOLDER )) {
		sprintf ( text, "Folder '%s' does not exist", DATA_FOLDER );
		MessageBox ( NULL, text, "Error", MB_ICONSTOP );
		return FALSE;
	}
	return TRUE;
}

void terminateJob ( JobT * job ) {
	if ( TerminateProcess ( job->procInfo.hProcess, 0 )) Log ( "Terminated", TRUE );
	else Log ( "Failed to terminate job", TRUE );
}

DWORD WINAPI controlWebServer ( JobT * job ) {
	Debug ( __func__ );
	Debug ( "begin" );
	while ( TRUE ) {
		if ( webIsNotRequested ()) {
			Log ( "It seems that web page is closed.", TRUE );
			break;
		}
		Sleep ( 1000 );
	}
	Debug ( "end" );
	Debug ( __func__ );
	Log ( "Terminating web server", TRUE );
	terminateJob ( job );
	return 0;
}

JobT * startWebServer ( void ) {
	char cmd[512];
	JobT * job;

	sprintf ( cmd, "%s -d PORT_INTER=%d -d SECRET_INTER=%s -t %s -S 127.0.0.1:%d", PHP_EXE, PORT_INTER, SECRET, WWW_FOLDER, PORT_WEB );
	job = addJob ( "www", cmd, FALSE, hLogWebServer );
	if ( job == NULL ) return NULL;
	CreateThread ( 0, 0, (void*) controlWebServer, (void *) job, 0, NULL );
	return job;
}

BOOL alreadRunning ( void ) {
	FILE * fp;
	char * response;
	unsigned int instance_present, instance_running;

	if ( !FileExists ( INSTANCE_FILE_PATH )) return FALSE;
	fp = fopen ( INSTANCE_FILE_PATH, "r" );
	fscanf ( fp, "%d", &instance_present );
	fclose ( fp );


	if ( !FileExists ( PORT_FILE )) return FALSE;
	fp = fopen ( PORT_FILE, "r" );
	fscanf ( fp, "%d", &PORT_WEB );
	fclose ( fp );

	if ( PORT_WEB == 0 ) return FALSE;

	response = sendHttpRequest ( "GET", (char *) INSTANCE_FILE_NAME, "" );
	if ( response == NULL ) return FALSE;
	Debug ( "INSTANCE_FILE_NAME response:" );
	Debug ( response );
	instance_running = atoi ( response );
	free ( response );
	if ( instance_running != instance_present ) return FALSE;
	return TRUE;
}

unsigned int findFreePort ( unsigned int start, unsigned int end ) {
	unsigned int port, failures = 0;
	while ( failures <= end - start ) {
		port = ( rand() % (end-start+1)) + start;
		if ( !pingPort ( port )) return port;
		failures++;
	}
	// Failed to find free port
	exitAndClean ( 3 );
	return 0; //to avoid warning
}

void setPortWeb ( void ) {
	FILE * fp;

	PORT_WEB = findFreePort ( START_PORT_WEB, END_PORT_WEB );
	fp = fopen ( INSTANCE_FILE_PATH, "wb" );
	fprintf ( fp, "%d", time ( NULL ) );
	fclose ( fp );
	fp = fopen ( PORT_FILE, "wb" );
	fprintf ( fp, "%d", PORT_WEB );
	fclose ( fp );
}

void setPortInter ( void ) {
	PORT_INTER = findFreePort ( 10000, 60000 );
}

void getConfigParameters ( void ) {
	START_PORT_WEB = GetPrivateProfileInt ( "run", "start_port_web", 10000, SETTINGS_FILE );
	END_PORT_WEB = GetPrivateProfileInt ( "run", "end_port_web", 65000, SETTINGS_FILE );
	LOGGING = GetPrivateProfileInt ( "run", "logging", 1, SETTINGS_FILE );
	DEBUG = GetPrivateProfileInt ( "run", "debug", 0, SETTINGS_FILE );
	MAX_INTERVAL_SEC = GetPrivateProfileInt ( "run", "max_interval_sec", 360, SETTINGS_FILE );
	GetPrivateProfileString ( "run", "log_file", "log.txt", LOG_FILE, MAX_INI_STR_LENGTH, SETTINGS_FILE );

	GetPrivateProfileString ( "job", "put_job_url", "/api/putJob", PUT_JOB_URL, MAX_INI_STR_LENGTH, SETTINGS_FILE );
	GetPrivateProfileString ( "job", "terminate", "terminate", TERMINATE, MAX_INI_STR_LENGTH, SETTINGS_FILE );
	MAX_JOBS = GetPrivateProfileInt ( "job", "max_jobs", 1000, SETTINGS_FILE );
}

void Ret200 ( SOCKET msgsock ) {
	char * answer = "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 0";
	send ( msgsock, answer, strlen ( answer ), 0 );
	shutdown ( msgsock, SD_BOTH );
	closesocket ( msgsock );
}

void Ret400 ( SOCKET msgsock ) {
	char * answer = "HTTP/1.1 400 Bad Request\nContent-Type: text/html\nContent-Length: 0";
	send ( msgsock, answer, strlen ( answer ), 0 );
	shutdown ( msgsock, SD_BOTH );
	closesocket ( msgsock );
}

char * parseQuery ( char * name, char * requestBuffer ) {
	unsigned long i, j;
	char * res;

	res = strstr ( requestBuffer, name );
	if ( res == NULL ) return NULL;
	i = res - requestBuffer + strlen ( name );
	res = malloc ( HTTP_REQUEST_MAX_SIZE );
	j = 0;
	while (( requestBuffer[i] ) && ( requestBuffer[i] != '&' ) && ( requestBuffer[i] != ' ' ) && ( requestBuffer[i] != 13 ) && ( requestBuffer[i] != 10 ) && ( j < HTTP_REQUEST_MAX_SIZE - 1 )) {
		switch ( requestBuffer[i] ) {
		case '+':
			res[j] = ' ';
			break;
		case '%':
			if ((requestBuffer[i+1] >= '0') && (requestBuffer[i+1] <= '9')) res[j] = (requestBuffer[i+1]-'0')<<4;
			else res[j] = (requestBuffer[i+1]-'A'+10)<<4;
			if ((requestBuffer[i+2] >= '0') && (requestBuffer[i+2] <= '9')) res[j] += (requestBuffer[i+2]-'0');
			else res[j] += (requestBuffer[i+2]-'A'+10);
			i+= 2;
			break;
		default:
			res[j] = requestBuffer[i];
		}
		i++;
		j++;
	};
	if ( j == 0 ) {
		free ( res );
		return NULL;
	}
	res[j] = 0;
	return res;
}

void WINAPI handleConnection ( SOCKET msgsock ) {
	char requestBuffer[HTTP_REQUEST_MAX_SIZE+1];
	char * contentStart, * jobId, * jobCmd, * secretRecv;
	unsigned int contentLength = 0;
	int retval, receivedSize = 0;

	memset ( requestBuffer, 0, HTTP_REQUEST_MAX_SIZE+1 );
	retval = recv ( msgsock, requestBuffer, HTTP_REQUEST_MAX_SIZE, 0 );
	if (( retval == SOCKET_ERROR) || ( retval == 0 )) {
		shutdown ( msgsock, SD_BOTH );
		closesocket ( msgsock );
		return;
	}

	if ( strstr ( requestBuffer, "POST" ) != requestBuffer ) {
		shutdown ( msgsock, SD_BOTH );
		closesocket ( msgsock );
		return;
	}

	if ( strstr ( requestBuffer, "Content-Length: " ) == NULL ) {
		shutdown ( msgsock, SD_BOTH );
		closesocket ( msgsock );
		return;
	}

	contentLength = atoi ( strstr ( requestBuffer, "Content-Length: " ) + strlen ( "Content-Length: " ));
	contentStart = strstr ( requestBuffer, "\r\n\r\n" );
	if ( contentStart == NULL ) {
		shutdown ( msgsock, SD_BOTH );
		closesocket ( msgsock );
		return;
	}
	contentStart += 4;
	receivedSize = strlen ( contentStart );
	memcpy ( requestBuffer, contentStart, strlen ( contentStart ) );
	requestBuffer[receivedSize] = 0;

	while ( receivedSize < contentLength ){
			retval = recv ( msgsock, requestBuffer+receivedSize, HTTP_REQUEST_MAX_SIZE-receivedSize, 0 );
			if (( retval == SOCKET_ERROR) || ( retval == 0 )) {
				shutdown ( msgsock, SD_BOTH );
				closesocket ( msgsock );
				return;
			}
			receivedSize += strlen ( requestBuffer+receivedSize );
			requestBuffer[receivedSize] = 0;
			if ( HTTP_REQUEST_MAX_SIZE-receivedSize <= 0 ) break;
	}

	jobId = parseQuery ( "jobId=", requestBuffer );
	if ( jobId == NULL ) {
		Ret400 ( msgsock );
		return;
	}
	jobCmd = parseQuery ( "jobCmd=", requestBuffer );
	if ( jobCmd == NULL ) {
		free ( jobId );
		Ret400 ( msgsock );
		return;
	}
	secretRecv = parseQuery ( "secret=", requestBuffer );
	if ( secretRecv == NULL ) {
		free ( jobId );
		free ( jobCmd );
		Ret400 ( msgsock );
		return;
	}
	if ( strcmp ( SECRET, secretRecv ) != 0 ) {
		free ( jobId );
		free ( jobCmd );
		free ( secretRecv );
		Ret400 ( msgsock );
		return;
	}
	Ret200 ( msgsock );
	free ( secretRecv );
	addJob ( jobId, jobCmd, TRUE, hSendJobStatus );
	free ( jobId );
	free ( jobCmd );
}

void WINAPI listeningThread ( void ) {
	int fromlen, socket_type = SOCK_STREAM;
	struct sockaddr_in local, from;
	WSADATA wsaData;
	SOCKET listen_socket, msgsock;
	HANDLE handle;

	if ( WSAStartup ( 0x202, &wsaData ) == SOCKET_ERROR ) {
		Log ( "WSAStartup failed", TRUE );
		WSACleanup();
		exit ( 1 );
	}

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = inet_addr ( "127.0.0.1" );
	local.sin_port = htons ( PORT_INTER );
	listen_socket = socket ( AF_INET, socket_type, 0 );

	if ( listen_socket == INVALID_SOCKET ) {
		Log ( "socket() failed", TRUE );
		WSACleanup();
		exit ( 1 );
	}

	if ( bind ( listen_socket, (struct sockaddr*)&local, sizeof ( local )) == SOCKET_ERROR ) {
		Log ( "bind() failed", TRUE );
		WSACleanup();
		exit ( 1 );
	}

	if ( listen ( listen_socket, 5 ) == SOCKET_ERROR ) {
		Log ( "listen() failed", TRUE );
		WSACleanup();
		exit ( 1 );
	}

	while ( TRUE ) {
		fromlen = sizeof ( from );
		msgsock = accept ( listen_socket, (struct sockaddr*) &from, &fromlen );

		if ( msgsock == INVALID_SOCKET ) {
			Log ( "accept() failed", TRUE );
			WSACleanup();
			exit ( 1 );
		}

		if (( handle = CreateThread ( 0, 0, (void*) handleConnection, (void*)msgsock, 0, NULL )) == NULL) {
			Log ( "Failed to create new thread", TRUE );
			exit ( 1 );
		}
	}
}

BOOL waitForWebServerStart ( void ) {
	unsigned int start = time ( NULL );
	Debug ( __func__ );
	while (( time ( NULL ) < start + WAIT_FOR_SERVER_START )) {
		if ( pingPort ( PORT_WEB )) {
			Debug ( "ping OK" );
			webStarted = TRUE;
			return TRUE;
		}
		else Debug ( "ping KO" );
		Sleep ( 100 );
	}
	return FALSE;
}

void exitAndClean ( int retCode ) {
	unlink ( INSTANCE_FILE_PATH );
	unlink ( PORT_FILE );
	Log ( "Finished", TRUE );
	DeleteCriticalSection ( &csLog );
	exit ( retCode );
}

char * genRandomString ( unsigned int l ) {
	unsigned char * str, * res;
	str = malloc ( l );
	RtlGenRandom ( str, l );
	res = bin2hex ( str, l );
	free ( str );
	return res;
}

int main ( void ) {
	InitializeCriticalSection ( &csLog );
	srand ( GetTickCount () * time ( NULL ));
	SECRET = genRandomString ( 8 );

	getConfigParameters ();
	if ( !checkRequiredFiles ()) return 1;
	if ( alreadRunning ()) return !openBrowser ();
	setPortWeb ();
	setPortInter ();
	_logging = TRUE;
	Log ( "Started", TRUE );
	jobs = initJobs ( MAX_JOBS );
	setWebLastRequestTime ();
	Debug ( "Starting web server" );
	if (  ( jobs->web = startWebServer ()) == NULL ) {
		Log ( "Failed to start web server", TRUE );
		MessageBox ( NULL, "Failed to start web server", "Error", MB_ICONSTOP );
		exitAndClean ( 1 );
	}
	if ( !waitForWebServerStart ()) {
		Log ( "Error is detected during starting web server", TRUE );
		Log ( "Terminating web server", TRUE );
		terminateJob ( jobs->web );
		if ( startBufferSize > 0 ) {
			Log ( startBuffer, TRUE );
			MessageBox ( NULL, startBuffer, "Error", MB_ICONSTOP );
		}
		exitAndClean ( 2 );
	}
	CreateThread (0, 0, (void *) listeningThread, NULL, 0, NULL );
	Debug ( "Opening default web browser" );
	if ( !openBrowser ()) {
		Log ( "Failed to start default web browser", TRUE );
		MessageBox ( NULL, "Failed to start default web browser", "Error", MB_ICONSTOP );
		exitAndClean ( 3 );
	};
	Debug ( "Starting waitForJobs" );
	waitForJobs ();
	DeleteCriticalSection ( &jobs->cs );
	exitAndClean ( 0 );
	return 0; //to avoid warning
}