
#include "XmlRpcSocket.h"
#include "XmlRpcUtil.h"
#include <QtCore>

#ifndef MAKEDEPEND

#if defined(_WIN32)
# include <stdio.h>
# include <winsock2.h>
//# pragma lib(WS2_32.lib)

#ifdef EINPROGRESS
#undef EINPROGRESS
# define EINPROGRESS	WSAEINPROGRESS
#endif
#ifdef EWOULDBLOCK
#undef EWOULDBLOCK
# define EWOULDBLOCK	WSAEWOULDBLOCK
#endif
#ifdef ETIMEDOUT
#undef ETIMEDOUT
# define ETIMEDOUT	    WSAETIMEDOUT
#endif
#else
extern "C" {
# include <unistd.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netdb.h>
# include <errno.h>
# include <fcntl.h>
}
#endif  // _WIN32

#endif // MAKEDEPEND


using namespace XmlRpc;

#ifdef _OPENSSL_ENABLED
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#endif

#if defined(_WIN32)
  
static void initWinSock()
{
  static bool wsInit = false;
  if (! wsInit)
  {
    WORD wVersionRequested = MAKEWORD( 2, 0 );
    WSADATA wsaData;
    WSAStartup(wVersionRequested, &wsaData);
    wsInit = true;
  }
}

#else

#define initWinSock()

#endif // _WIN32


// These errors are not considered fatal for an IO operation; the operation will be re-tried.
static inline bool
nonFatalError()
{
  int err = XmlRpcSocket::getError();
  return (err == EINPROGRESS || err == EAGAIN || err == EWOULDBLOCK || err == EINTR);
}



int
XmlRpcSocket::socket()
{
  initWinSock();
  return (int) ::socket(AF_INET, SOCK_STREAM, 0);
}


void
XmlRpcSocket::close(int fd)
{
  XmlRpcUtil::log(4, "XmlRpcSocket::close: fd %d.", fd);
#if defined(_WIN32)
  closesocket(fd);
#else
  ::close(fd);
#endif // _WIN32
}




bool
XmlRpcSocket::setNonBlocking(int fd)
{
#if defined(_WIN32)
  unsigned long flag = 1;
  return (ioctlsocket((SOCKET)fd, FIONBIO, &flag) == 0);
#else
  return (fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
#endif // _WIN32
}


bool
XmlRpcSocket::setReuseAddr(int fd)
{
  // Allow this port to be re-bound immediately so server re-starts are not delayed
  int sflag = 1;
  return (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&sflag, sizeof(sflag)) == 0);
}


// Bind to a specified port
bool 
XmlRpcSocket::bind(int fd, int port)
{
  struct sockaddr_in saddr;
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  saddr.sin_port = htons((u_short) port);
  return (::bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) == 0);
}


// Set socket in listen mode
bool 
XmlRpcSocket::listen(int fd, int backlog)
{
  return (::listen(fd, backlog) == 0);
}


int
XmlRpcSocket::accept(int fd)
{
  struct sockaddr_in addr;
#if defined(_WIN32)
  int
#else
  socklen_t
#endif
    addrlen = sizeof(addr);

  return (int) ::accept(fd, (struct sockaddr*)&addr, &addrlen);
}

// Connect a socket to a server (from a client)
bool
XmlRpcSocket::connect(int fd, std::string& host, int port)
{
  struct sockaddr_in saddr;
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;

  struct hostent *hp = gethostbyname(host.c_str());
  if (hp == 0) return false;

  saddr.sin_family = hp->h_addrtype;
  memcpy(&saddr.sin_addr, hp->h_addr, hp->h_length);
  saddr.sin_port = htons((u_short) port);

  // For asynch operation, this will return EWOULDBLOCK (windows) or
  // EINPROGRESS (linux) and we just need to wait for the socket to be writable...
  int result = ::connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
  return result == 0 || nonFatalError();
}

#ifdef _OPENSSL_ENABLED
// Sets SSL on the given socket
void
XmlRpcSocket::enableSSL(int socket, void **sslHandle)
{
    /* Variables */
    SSL_CTX *Ctx;
    SSL *cSSL;

    /* Create the context */
    Ctx = SSL_CTX_new( SSLv23_client_method());
    SSL_CTX_set_options(Ctx, SSL_OP_ALL | SSL_MODE_AUTO_RETRY);

    /* Create the actual SSL handle */
    cSSL = SSL_new(Ctx);

    /* Bind socket */
    SSL_set_fd(cSSL, socket);
    SSL_set_connect_state(cSSL);

    /* Establish secure link */
    while (-1 == SSL_connect(cSSL))
    {
        if (SSL_get_error(cSSL, -1) != SSL_ERROR_WANT_READ
                && SSL_get_error(cSSL, -1) != SSL_ERROR_WANT_WRITE) {
            XmlRpcUtil::error("XmlRpcSocket::enableSSL: accepting ssl socket returned error %i (org %i, errno %s): %s.",
                              SSL_get_error(cSSL, -1), -1, strerror(errno), ERR_error_string(ERR_get_error(), NULL));
            break;
        }
    }

    /* Store */
    *sslHandle = cSSL;

    /* Set non-block */
    setNonBlocking(socket);
}
#endif

// Read available text from the specified socket. Returns false on error.
bool 
#ifdef _OPENSSL_ENABLED
XmlRpcSocket::nbRead(int fd, std::string& s, bool *eof, void *sslHandle)
#else
XmlRpcSocket::nbRead(int fd, std::string& s, bool *eof)
#endif
{
  const int READ_SIZE = 4096;   // Number of bytes to attempt to read at a time
  char readBuf[READ_SIZE];

  bool wouldBlock = false;
  *eof = false;

  while ( ! wouldBlock && ! *eof) {
      int n = 0;
#ifdef _OPENSSL_ENABLED
      if (sslHandle == NULL) {
#endif
#if defined(_WIN32)
          n = recv(fd, readBuf, READ_SIZE-1, 0);
#else
          n = read(fd, readBuf, READ_SIZE-1);
#endif
#ifdef _OPENSSL_ENABLED
      }
      else {
          n = SSL_read((SSL*)sslHandle, readBuf, READ_SIZE-1);
      }
#endif

    XmlRpcUtil::log(5, "XmlRpcSocket::nbRead: read/recv returned %d.", n);

    if (n > 0) {
      readBuf[n] = 0;
      s.append(readBuf, n);
    } else if (n == 0) {
      *eof = true;
    } else if (nonFatalError()) {
      wouldBlock = true;
    } else {
      return false;   // Error
    }
  }
  return true;
}


// Write text to the specified socket. Returns false on error.
bool 
#ifdef _OPENSSL_ENABLED
XmlRpcSocket::nbWrite(int fd, std::string& s, int *bytesSoFar, void *sslHandle)
#else
XmlRpcSocket::nbWrite(int fd, std::string& s, int *bytesSoFar)
#endif
{
  int nToWrite = int(s.length()) - *bytesSoFar;
  char *sp = const_cast<char*>(s.c_str()) + *bytesSoFar;
  bool wouldBlock = false;

  while ( nToWrite > 0 && ! wouldBlock ) {
      int n = 0;
#ifdef _OPENSSL_ENABLED
      if (sslHandle == NULL) {
#endif
#if defined(_WIN32)
        n = send(fd, sp, nToWrite, 0);
#else
        n = write(fd, sp, nToWrite);
#endif
#ifdef _OPENSSL_ENABLED
      }
      else {
        n = SSL_write((SSL*)sslHandle, sp, nToWrite);
      }
#endif

    XmlRpcUtil::log(5, "XmlRpcSocket::nbWrite: send/write returned %d.", n);

    if (n > 0) {
      sp += n;
      *bytesSoFar += n;
      nToWrite -= n;
    } else if (nonFatalError()) {
      wouldBlock = true;
    } else {
      return false;   // Error
    }
  }
  return true;
}


// Returns last errno
int 
XmlRpcSocket::getError()
{
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}


// Returns message corresponding to last errno
std::string 
XmlRpcSocket::getErrorMsg()
{
  return getErrorMsg(getError());
}

// Returns message corresponding to errno... well, it should anyway
std::string 
XmlRpcSocket::getErrorMsg(int error)
{
  char err[60];
  snprintf(err,sizeof(err),"error %d", error);
  return std::string(err);
}


