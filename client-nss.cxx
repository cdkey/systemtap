/*
 Compile server client functions
 Copyright (C) 2010-2018 Red Hat Inc.

 This file is part of systemtap, and is free software.  You can
 redistribute it and/or modify it under the terms of the GNU General
 Public License (GPL); either version 2, or (at your option) any
 later version.
*/

// Completely disable the client if NSS is not available.
#include "config.h"
#if HAVE_NSS
#include "session.h"
#include "cscommon.h"
#include "csclient.h"
#include "client-nss.h"
#include "util.h"
#include "stap-probe.h"

#include <sys/times.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <algorithm>

extern "C" {
#include <unistd.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <glob.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pwd.h>
}

#if HAVE_AVAHI
extern "C" {
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>
}
#endif // HAVE_AVAHI

extern "C" {
#include <ssl.h>
#include <nspr.h>
#include <nss.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>
#include <sslerr.h>
}

#include "nsscommon.h"

using namespace std;

#define STAP_CSC_01 _("WARNING: The domain name, %s, does not match the DNS name(s) on the server certificate:\n")
#define STAP_CSC_02 _("could not find input file %s\n")
#define STAP_CSC_03 _("could not open input file %s\n")
#define STAP_CSC_04 _("Unable to open output file %s\n")
#define STAP_CSC_05 _("could not write to %s\n")

extern "C"
void
nsscommon_error (const char *msg, int logit __attribute ((unused)))
{
  clog << msg << endl << flush;
}

static void
preferred_order (vector<compile_server_info> &servers)
{
  // Sort the given list of servers into the preferred order for contacting.
  // Don't bother if there are less than 2 servers in the list.
  if (servers.size () < 2)
    return;

  // Sort the list using compile_server_info::operator<
  sort (servers.begin (), servers.end ());
}

/* Connection state.  */
typedef struct connectionState_t
{
  const char *hostName;
  PRNetAddr   addr;
  const char *infileName;
  const char *outfileName;
  const char *trustNewServerMode;
} connectionState_t;

/* Called when the server certificate verification fails. This gives us
   the chance to trust the server anyway and add the certificate to the
   local database.  */
static SECStatus
badCertHandler(void *arg, PRFileDesc *sslSocket)
{
  SECStatus secStatus;
  PRErrorCode errorNumber;
  CERTCertificate *serverCert = NULL;
  SECItem subAltName;
  PRArenaPool *tmpArena = NULL;
  CERTGeneralName *nameList, *current;
  char *expected = NULL;
  const connectionState_t *connectionState = (connectionState_t *)arg;

  errorNumber = PR_GetError ();
  switch (errorNumber)
    {
    case SSL_ERROR_BAD_CERT_DOMAIN:
      /* Since we administer our own client-side databases of trustworthy
	 certificates, we don't need the domain name(s) on the certificate to
	 match. If the cert is in our database, then we can trust it.
	 If we know the expected domain name, then issue a warning but,
	 in any case, accept the certificate.  */
      secStatus = SECSuccess;

      expected = SSL_RevealURL (sslSocket);
      if (expected == NULL || *expected == '\0')
	break;

      fprintf (stderr, STAP_CSC_01, expected);

      /* List the DNS names from the server cert as part of the warning.
	 First, find the alt-name extension on the certificate.  */
      subAltName.data = NULL;
      serverCert = SSL_PeerCertificate (sslSocket);
      secStatus = CERT_FindCertExtension (serverCert,
					  SEC_OID_X509_SUBJECT_ALT_NAME,
					  & subAltName);
      if (secStatus != SECSuccess || ! subAltName.data)
	{
	  fprintf (stderr, _("Unable to find alt name extension on the server certificate\n"));
	  secStatus = SECSuccess; /* Not a fatal error */
	  break;
	}

      // Now, decode the extension.
      tmpArena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
      if (! tmpArena) 
	{
	  fprintf (stderr, _("Out of memory\n"));
	  SECITEM_FreeItem(& subAltName, PR_FALSE);
	  secStatus = SECSuccess; /* Not a fatal error here */
	  break;
	}
      nameList = CERT_DecodeAltNameExtension (tmpArena, & subAltName);
      SECITEM_FreeItem(& subAltName, PR_FALSE);
      if (! nameList)
	{
	  fprintf (stderr, _("Unable to decode alt name extension on server certificate\n"));
	  secStatus = SECSuccess; /* Not a fatal error */
	  break;
	}

      /* List the DNS names from the server cert as part of the warning.
	 The names are in a circular list.  */
      current = nameList;
      do
	{
	  /* Make sure this is a DNS name.  */
	  if (current->type == certDNSName)
	    {
	      fprintf (stderr, "  %.*s\n",
		       (int)current->name.other.len, current->name.other.data);
	    }
	  current = CERT_GetNextGeneralName (current);
	}
      while (current != nameList);

      break;

    case SEC_ERROR_CA_CERT_INVALID:
      /* The server's certificate is not trusted. Should we trust it? */
      secStatus = SECFailure; /* Do not trust by default. */
      if (! connectionState->trustNewServerMode)
	break;

      /* Trust it for this session only?  */
      if (strcmp (connectionState->trustNewServerMode, "session") == 0)
	{
	  secStatus = SECSuccess;
	  break;
	}

      /* Trust it permanently?  */
      if (strcmp (connectionState->trustNewServerMode, "permanent") == 0)
	{
	  /* The user wants to trust this server. Get the server's certificate so
	     and add it to our database.  */
	  serverCert = SSL_PeerCertificate (sslSocket);
	  if (serverCert != NULL)
	    {
	      secStatus = nss_trustNewServer (serverCert);
	    }
	}
      break;
    default:
      secStatus = SECFailure; /* Do not trust this server */
      break;
    }

  if (expected)
    PORT_Free (expected);
  if (tmpArena)
    PORT_FreeArena (tmpArena, PR_FALSE);

  if (serverCert != NULL)
    {
      CERT_DestroyCertificate (serverCert);
    }

  return secStatus;
}

static PRFileDesc *
setupSSLSocket (connectionState_t *connectionState)
{
  PRFileDesc         *tcpSocket;
  PRFileDesc         *sslSocket;
  PRSocketOptionData	socketOption;
  PRStatus            prStatus;
  SECStatus           secStatus;

  tcpSocket = PR_OpenTCPSocket(connectionState->addr.raw.family);
  if (tcpSocket == NULL)
    goto loser;

  /* Make the socket blocking. */
  socketOption.option = PR_SockOpt_Nonblocking;
  socketOption.value.non_blocking = PR_FALSE;

  prStatus = PR_SetSocketOption(tcpSocket, &socketOption);
  if (prStatus != PR_SUCCESS)
    goto loser;

  /* Import the socket into the SSL layer. */
  sslSocket = SSL_ImportFD(NULL, tcpSocket);
  if (!sslSocket)
    goto loser;

  /* Set configuration options. */
  secStatus = SSL_OptionSet(sslSocket, SSL_SECURITY, PR_TRUE);
  if (secStatus != SECSuccess)
    goto loser;

  secStatus = SSL_OptionSet(sslSocket, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
  if (secStatus != SECSuccess)
    goto loser;

  /* Set SSL callback routines. */
#if 0 /* no client authentication */
  secStatus = SSL_GetClientAuthDataHook(sslSocket,
					(SSLGetClientAuthData)myGetClientAuthData,
					(void *)certNickname);
  if (secStatus != SECSuccess)
    goto loser;
#endif
#if 0 /* Use the default */
  secStatus = SSL_AuthCertificateHook(sslSocket,
				      (SSLAuthCertificate)myAuthCertificate,
				      (void *)CERT_GetDefaultCertDB());
  if (secStatus != SECSuccess)
    goto loser;
#endif

  secStatus = SSL_BadCertHook(sslSocket, (SSLBadCertHandler)badCertHandler,
			      connectionState);
  if (secStatus != SECSuccess)
    goto loser;

#if 0 /* No handshake callback */
  secStatus = SSL_HandshakeCallback(sslSocket, myHandshakeCallback, NULL);
  if (secStatus != SECSuccess)
    goto loser;
#endif

  return sslSocket;

 loser:
  if (tcpSocket)
    PR_Close(tcpSocket);
  return NULL;
}


static SECStatus
handle_connection (PRFileDesc *sslSocket, connectionState_t *connectionState)
{
  PRInt32     numBytes;
  char       *readBuffer;
  PRFileInfo  info;
  PRFileDesc *local_file_fd;
  PRStatus    prStatus;
  SECStatus   secStatus = SECSuccess;

#define READ_BUFFER_SIZE (60 * 1024)

  /* If we don't have both the input and output file names, then we're
     contacting this server only in order to establish trust. In this case send
     0 as the file size and exit. */
  if (! connectionState->infileName || ! connectionState->outfileName)
    {
      numBytes = htonl ((PRInt32)0);
      numBytes = PR_Write (sslSocket, & numBytes, sizeof (numBytes));
      if (numBytes < 0)
	return SECFailure;
      return SECSuccess;
    }

  /* read and send the data. */
  /* Try to open the local file named.	
   * If successful, then write it to the server
   */
  prStatus = PR_GetFileInfo(connectionState->infileName, &info);
  if (prStatus != PR_SUCCESS ||
      info.type != PR_FILE_FILE ||
      info.size < 0)
    {
      fprintf (stderr, STAP_CSC_02,
	       connectionState->infileName);
      return SECFailure;
    }

  local_file_fd = PR_Open(connectionState->infileName, PR_RDONLY, 0);
  if (local_file_fd == NULL)
    {
      fprintf (stderr, STAP_CSC_03, connectionState->infileName);
      return SECFailure;
    }

  /* Send the file size first, so the server knows when it has the entire file. */
  numBytes = htonl ((PRInt32)info.size);
  numBytes = PR_Write(sslSocket, & numBytes, sizeof (numBytes));
  if (numBytes < 0)
    {
      PR_Close(local_file_fd);
      return SECFailure;
    }

  /* Transmit the local file across the socket.  */
  numBytes = PR_TransmitFile(sslSocket, local_file_fd, 
			     NULL, 0,
			     PR_TRANSMITFILE_KEEP_OPEN,
			     PR_INTERVAL_NO_TIMEOUT);
  if (numBytes < 0)
    {
      PR_Close(local_file_fd);
      return SECFailure;
    }

  PR_Close(local_file_fd);

  /* read until EOF */
  readBuffer = (char *)PORT_Alloc(READ_BUFFER_SIZE);
  if (! readBuffer) {
    fprintf (stderr, _("Out of memory\n"));
    return SECFailure;
  }

  local_file_fd = PR_Open(connectionState->outfileName, PR_WRONLY | PR_CREATE_FILE | PR_TRUNCATE,
			  PR_IRUSR | PR_IWUSR | PR_IRGRP | PR_IWGRP | PR_IROTH);
  if (local_file_fd == NULL)
    {
      fprintf (stderr, STAP_CSC_04, connectionState->outfileName);
      return SECFailure;
    }
  while (PR_TRUE)
    {
      // No need for PR_Read_Complete here, since we're already managing multiple
      // reads to a fixed size buffer.
      numBytes = PR_Read (sslSocket, readBuffer, READ_BUFFER_SIZE);
      if (numBytes == 0)
	break;	/* EOF */

      if (numBytes < 0)
	{
	  secStatus = SECFailure;
	  break;
	}

      /* Write to output file */
      numBytes = PR_Write(local_file_fd, readBuffer, numBytes);
      if (numBytes < 0)
	{
	  fprintf (stderr, STAP_CSC_05, connectionState->outfileName);
	  secStatus = SECFailure;
	  break;
	}
    }

  PR_Free(readBuffer);
  PR_Close(local_file_fd);

  /* Caller closes the socket. */
  return secStatus;
}

/* make the connection.
*/
static SECStatus
do_connect (connectionState_t *connectionState)
{
  PRFileDesc *sslSocket;
  PRStatus    prStatus;
  SECStatus   secStatus;

  secStatus = SECSuccess;

  /* Set up SSL secure socket. */
  sslSocket = setupSSLSocket (connectionState);
  if (sslSocket == NULL)
    return SECFailure;

#if 0 /* no client authentication */
  secStatus = SSL_SetPKCS11PinArg(sslSocket, password);
  if (secStatus != SECSuccess)
    goto done;
#endif

  secStatus = SSL_SetURL(sslSocket, connectionState->hostName);
  if (secStatus != SECSuccess)
    goto done;

  prStatus = PR_Connect(sslSocket, & connectionState->addr, PR_INTERVAL_NO_TIMEOUT);
  if (prStatus != PR_SUCCESS)
    {
      secStatus = SECFailure;
      goto done;
    }

  /* Established SSL connection, ready to send data. */
  secStatus = SSL_ResetHandshake(sslSocket, /* asServer */ PR_FALSE);
  if (secStatus != SECSuccess)
    goto done;

  /* This is normally done automatically on the first I/O operation,
     but doing it here catches any authentication problems early.  */
  secStatus = SSL_ForceHandshake(sslSocket);
  if (secStatus != SECSuccess)
    goto done;

  // Connect to the server and make the request.
  secStatus = handle_connection(sslSocket, connectionState);

 done:
  prStatus = PR_Close(sslSocket);
  return secStatus;
}

static bool
isIPv6LinkLocal (const PRNetAddr &address)
{
  // Link-local addresses are members of the address block fe80::
  if (address.raw.family == PR_AF_INET6 &&
      address.ipv6.ip.pr_s6_addr[0] == 0xfe && address.ipv6.ip.pr_s6_addr[1] == 0x80)
    return true;
  return false;
}

static int
client_connect (const compile_server_info &server,
		const char* infileName, const char* outfileName,
		const char* trustNewServer)
{
  SECStatus   secStatus;
  PRErrorCode errorNumber;
  int         attempt;
  int         errCode = NSS_GENERAL_ERROR;
  struct connectionState_t connectionState;

  // Set up a connection state for use by NSS error callbacks.
  memset (& connectionState, 0, sizeof (connectionState));
  connectionState.hostName = server.host_name.c_str ();
  connectionState.addr = server.address;
  connectionState.infileName = infileName;
  connectionState.outfileName = outfileName;
  connectionState.trustNewServerMode = trustNewServer;

  /* Some errors (see below) represent a situation in which trying again
     should succeed. However, don't try forever.  */
  for (attempt = 0; attempt < 5; ++attempt)
    {
      secStatus = do_connect (& connectionState);
      if (secStatus == SECSuccess)
	return NSS_SUCCESS;

      errorNumber = PR_GetError ();
      switch (errorNumber)
	{
	case PR_CONNECT_RESET_ERROR:
	  /* Server was not ready. */
	  sleep (1);
	  break; /* Try again */
	case SEC_ERROR_EXPIRED_CERTIFICATE:
	  /* The server's certificate has expired. It should
	     generate a new certificate. Return now and we'll try again. */
	  errCode = NSS_SERVER_CERT_EXPIRED_ERROR;
	  return errCode;
	case SEC_ERROR_CA_CERT_INVALID:
	  /* The server's certificate is not trusted. The exit code must
	     reflect this.  */
	  errCode = NSS_CA_CERT_INVALID_ERROR;
	  return errCode;
	default:
	  /* This error is fatal.  */
	  return errCode;
	}
    }

  return errCode;
}

nss_client_backend::nss_client_backend (systemtap_session &s)
  : client_backend(s), argc(0)
{
  server_tmpdir = s.tmpdir + "/server";
}

int
nss_client_backend::initialize ()
{
  // Initialize session state
  argc = 0;
  locale_vars.clear();
  mok_fingerprints.clear();

  // Private location for server certificates.
  private_ssl_dbs.push_back (local_client_cert_db_path ());

  // Additional public location.
  public_ssl_dbs.push_back (global_client_cert_db_path ());
  return 0;
}

int
nss_client_backend::add_protocol_version (const string &version)
{
  // Add the current protocol version.
  return write_to_file (client_tmpdir + "/version", version);
}

int
nss_client_backend::add_sysinfo ()
{
  string sysinfo = "sysinfo: " + s.kernel_release + " " + s.architecture;
  return write_to_file (client_tmpdir + "/sysinfo", sysinfo);
}

// Symbolically link the given file or directory into the client's temp
// directory under the given subdirectory.
int
nss_client_backend::include_file_or_directory (const string &subdir,
					       const string &path,
					       const bool add_arg)
{
  // Must predeclare these because we do use 'goto done' to
  // exit from error situations.
  vector<string> components;
  string name;
  int rc = 0;

  // Canonicalize the given path and remove the leading /.
  string rpath;
  char *cpath = canonicalize_file_name (path.c_str ());
  if (! cpath)
    {
      // It can not be canonicalized. Use the name relative to
      // the current working directory and let the server deal with it.
      char cwd[PATH_MAX];
      if (getcwd (cwd, sizeof (cwd)) == NULL)
	{
	  rpath = path;
	  rc = 1;
	  goto done;
	}
	rpath = string (cwd) + "/" + path;
    }
  else
    {
      // It can be canonicalized. Use the canonicalized name and add this
      // file or directory to the request package.
      rpath = cpath;
      free (cpath);

      // Including / would require special handling in the code below and
      // is a bad idea anyway. Let's not allow it.
      if (rpath == "/")
	{
	  if (rpath != path)
	    clog << _F("%s resolves to %s\n", path.c_str (), rpath.c_str ());
	  clog << _F("Unable to send %s to the server\n", path.c_str ());
	  return 1;
	}

      // First create the requested subdirectory (if there is one).
      if (! subdir.empty())
        {
	  name = client_tmpdir + "/" + subdir;
	  rc = create_dir (name.c_str ());
	  if (rc) goto done;
	}
      else
        {
	  name = client_tmpdir;
	}

      // Now create each component of the path within the sub directory.
      assert (rpath[0] == '/');
      tokenize (rpath.substr (1), components, "/");
      assert (components.size () >= 1);
      unsigned i;
      for (i = 0; i < components.size() - 1; ++i)
	{
	  if (components[i].empty ())
	    continue; // embedded '//'
	  name += "/" + components[i];
	  rc = create_dir (name.c_str ());
	  if (rc) goto done;
	}

      // Now make a symbolic link to the actual file or directory.
      assert (i == components.size () - 1);
      name += "/" + components[i];
      rc = symlink (rpath.c_str (), name.c_str ());
      if (rc) goto done;
    }

  // If the caller asks us, add this file or directory to the arguments.
  if (add_arg)
    rc = add_cmd_arg (subdir + "/" + rpath.substr (1));

 done:
  if (rc != 0)
    {
      const char* e = strerror (errno);
      clog << "ERROR: unable to add "
	   << rpath
	   << " to temp directory as "
	   << name << ": " << e
	   << endl;
    }
  return rc;
}

int
nss_client_backend::add_cmd_arg (const string &cmd_arg)
{
  int rc = 0;
  ostringstream fname;
  fname << client_tmpdir << "/argv" << ++argc;
  write_to_file (fname.str (), cmd_arg); // NB: No terminating newline
  return rc;
}

void
nss_client_backend::add_localization_variable (const std::string &var,
					       const std::string &value)
{
    locale_vars += var + "=" + value + "\n";
}

int
nss_client_backend::finalize_localization_variables ()
{
  string fname = client_tmpdir + "/locale";
  return write_to_file(fname, locale_vars);
}

void
nss_client_backend::add_mok_fingerprint (const std::string &fingerprint)
{
    mok_fingerprints << fingerprint << endl;
}

int
nss_client_backend::finalize_mok_fingerprints ()
{
  string fname = client_tmpdir + "/mok_fingerprints";
  return write_to_file(fname, mok_fingerprints.str());
}

// Package the client's temp directory into a form suitable for sending to the
// server.
int
nss_client_backend::package_request ()
{
  // Package up the temporary directory into a zip file.
  client_zipfile = client_tmpdir + ".zip";
  string cmd = "cd " + cmdstr_quoted(client_tmpdir) + " && zip -qr "
      + cmdstr_quoted(client_zipfile) + " *";
  vector<string> sh_cmd { "sh", "-c", cmd };
  int rc = stap_system (s.verbose, sh_cmd);
  return rc;
}

int
nss_client_backend::find_and_connect_to_server ()
{
  // Accumulate info on the specified servers.
  vector<compile_server_info> specified_servers;
  nss_get_specified_server_info (s, specified_servers);

  // Examine the specified servers to make sure that each has been resolved
  // with a host name, ip address and port. If not, try to obtain this
  // information by examining online servers.
  vector<compile_server_info> server_list;
  for (vector<compile_server_info>::const_iterator i = specified_servers.begin ();
       i != specified_servers.end ();
       ++i)
    {
      // If we have an ip address and were given a port number, then just use the one we've
      // been given. Otherwise, check for matching compatible online servers and try their
      // ip addresses and ports.
      if (i->hasAddress() && i->fully_specified)
	nss_add_server_info (*i, server_list);
      else
	{
	  // Obtain a list of online servers.
	  vector<compile_server_info> online_servers;
	  nss_get_or_keep_online_server_info (s, online_servers, false/*keep*/);

	  // If no specific server (port) has been specified,
	  // then we'll need the servers to be
	  // compatible and possibly trusted as signers as well.
	  if (! i->fully_specified)
	    {
	      nss_get_or_keep_compatible_server_info (s, online_servers,
						      true/*keep*/);
	      if (! pr_contains (s.privilege, pr_stapdev))
		nss_get_or_keep_signing_server_info (s, online_servers,
						     true/*keep*/);
	    }

	  // Keep the ones (if any) which match our server.
	  nss_keep_common_server_info (*i, online_servers);

	  // Add these servers (if any) to the server list.
	  nss_add_server_info (online_servers, server_list);
	}
    }

  // Did we identify any potential servers?
  unsigned limit = server_list.size ();
  if (limit == 0)
    {
      clog << _("Unable to find a suitable compile server.  [man stap-server]") << endl;

      // Try to explain why.
      vector<compile_server_info> online_servers;
      nss_get_or_keep_online_server_info (s, online_servers, false/*keep*/);
      if (online_servers.empty ())
	clog << _("No servers online to select from.") << endl;
      else
	{
	  clog << _("The following servers are online:") << endl;
	  clog << online_servers;
	  if (! specified_servers.empty ())
	    {
	      clog << _("The following servers were requested:") << endl;
	      clog << specified_servers;
	    }
	  else
	    {
	      string criteria = "online,trusted,compatible";
	      if (! pr_contains (s.privilege, pr_stapdev))
		criteria += ",signer";
	      clog << _F("No servers matched the selection criteria of %s.", criteria.c_str())
		   << endl;

	      // PR26665, mention case of local mok key but no matching server 
	      if (s.modules_must_be_signed() && s.mok_fingerprints.size() > 0)
		{
		  clog << _("Consider removing the local MOK to associate with a new server") << endl;
		  clog << _("# sudo mokutil --list-enrolled") << endl;
		  clog << _("# sudo mokutil --export / --delete  OR  --reset") << endl;
		}
	    }
	}
      return 1;
    }

  // Sort the list of servers into a preferred order.
  preferred_order (server_list);

  // Now try each of the identified servers in turn.
  int rc = compile_using_server (server_list);
  if (rc == NSS_SUCCESS)
    return 0; // success!

  // If the error was that a server's cert was expired, try again. This is because the server
  // should generate a new cert which may be automatically trusted by us if it is our server.
  // Give the server a chance to do this before retrying.
  if (rc == NSS_SERVER_CERT_EXPIRED_ERROR)
    {
      if (s.verbose >= 2)
	clog << _("The server's certificate was expired. Trying again") << endl << flush;
      sleep (2);
      rc = compile_using_server (server_list);
      if (rc == NSS_SUCCESS)
	return 0; // success!
    }

  // We were unable to use any available server
  clog << _("Unable to connect to a server.") << endl;
  if (s.verbose == 1)
    {
      // This information is redundant at higher verbosity levels.
      clog << _("The following servers were tried:") << endl;
      clog << server_list;
    }
  return 1; // Failure
}

int 
nss_client_backend::compile_using_server (
  vector<compile_server_info> &servers
)
{
  NSSInitContext *context;

  // Make sure NSPR is initialized. Must be done before NSS is initialized
  s.NSPR_init ();

  // Attempt connection using each of the available client certificate
  // databases. Assume the server certificate is invalid until proven otherwise.
  PR_SetError (SEC_ERROR_CA_CERT_INVALID, 0);
  vector<string> dbs = private_ssl_dbs;
  vector<string>::iterator i = dbs.end();
  dbs.insert (i, public_ssl_dbs.begin (), public_ssl_dbs.end ());
  int rc = NSS_GENERAL_ERROR; // assume failure
  bool serverCertExpired = false;
  for (i = dbs.begin (); i != dbs.end (); ++i)
    {
      // Make sure the database directory exists. It is not an error if it
      // doesn't.
      if (! file_exists (*i))
	continue;

#if 0 // no client authentication for now.
      // Set our password function callback.
      PK11_SetPasswordFunc (myPasswd);
#endif

      // Initialize the NSS libraries.
      const char *cert_dir = i->c_str ();
      context = nssInitContext (cert_dir);
      if (context == NULL)
	{
	  // Message already issued.
	  continue; // try next database
	}

      // Enable all cipher suites.
      // SSL_ClearSessionCache is required for the new settings to take effect.
      /* Some NSS versions don't do this correctly in NSS_SetDomesticPolicy. */
      do {
        const PRUint16 *cipher;
        for (cipher = SSL_GetImplementedCiphers(); *cipher != 0; ++cipher)
          SSL_CipherPolicySet(*cipher, SSL_ALLOWED);
      } while (0);
      SSL_ClearSessionCache ();
  
      server_zipfile = s.tmpdir + "/server.zip";

      // Try each server in turn.
      for (vector<compile_server_info>::iterator j = servers.begin ();
	   j != servers.end ();
	   ++j)
	{
	  // At a minimum we need an ip_address along with a port
	  // number in order to contact the server.
	  if (! j->hasAddress() || j->port == 0)
	    continue;
	  // Set the port within the address.
	  j->setAddressPort (j->port);

	  if (s.verbose >= 2)
           clog << _F("Attempting SSL connection with %s\n"
                "  using certificates from the database in %s\n",
                lex_cast(*j).c_str(), cert_dir);

	  rc = client_connect (*j, client_zipfile.c_str(), server_zipfile.c_str (),
			       NULL/*trustNewServer_p*/);
	  if (rc == NSS_SUCCESS)
	    {
	      s.winning_server = lex_cast(*j);
	      break; // Success!
	    }

	  // Server cert has expired. Try other servers and/or databases, but take note because
	  // server should generate a new certificate. If no other servers succeed, we'll try again
	  // in case the new cert works.
	  if (rc == NSS_SERVER_CERT_EXPIRED_ERROR)
	    {
	      serverCertExpired = true;
	      continue;
	    }

	  if (s.verbose >= 2)
	    {
	      clog << _("  Unable to connect: ");
	      nssError ();
	      // Additional information: if the address is IPv6 and is link-local, then it must
	      // have a scope_id.
	      if (isIPv6LinkLocal (j->address) && j->address.ipv6.scope_id == 0)
		{
		  clog << _("    The address is an IPv6 link-local address with no scope specifier.")
		       << endl;
		}
	    }
	}

      // SSL_ClearSessionCache is required before shutdown for client applications.
      SSL_ClearSessionCache ();
      nssCleanup (cert_dir, context);

      if (rc == SECSuccess)
	break; // Success!
    }

  // Indicate whether a server cert was expired, so we can try again, if desired.
  if (rc != NSS_SUCCESS)
    {
      if (serverCertExpired)
	rc = NSS_SERVER_CERT_EXPIRED_ERROR;
    }

  return rc;
}

int
nss_client_backend::unpack_response ()
{
  // Unzip the response package.
  vector<string> cmd { "unzip", "-qd", server_tmpdir, server_zipfile };
  int rc = stap_system (s.verbose, cmd);
  if (rc != 0)
    {
      clog << _F("Unable to unzip the server response '%s'\n", server_zipfile.c_str());
      return rc;
    }

  // Determine the server protocol version.
  string filename = server_tmpdir + "/version";
  if (file_exists (filename))
    read_from_file (filename, server_version);

  // Warn about the shortcomings of this server, if it is down level.
  show_server_compatibility ();

  // If the server's response contains a systemtap temp directory, move
  // its contents to our temp directory.
  glob_t globbuf;
  string filespec = server_tmpdir + "/stap??????";
  if (s.verbose >= 3)
    clog << _F("Searching \"%s\"\n", filespec.c_str());
  int r = glob(filespec.c_str (), 0, NULL, & globbuf);
  if (r != GLOB_NOSPACE && r != GLOB_ABORTED && r != GLOB_NOMATCH)
    {
      if (globbuf.gl_pathc > 1)
	{
	  clog << _("Incorrect number of files in server response") << endl;
	  rc = 1;
	  goto done;
	}

      assert (globbuf.gl_pathc == 1);
      string dirname = globbuf.gl_pathv[0];
      if (s.verbose >= 3)
	clog << _("  found ") << dirname << endl;

      filespec = dirname + "/*";
      if (s.verbose >= 3)
       clog << _F("Searching \"%s\"\n", filespec.c_str());
      globfree(&globbuf);
      int r = glob(filespec.c_str (), GLOB_PERIOD, NULL, & globbuf);
      if (r != GLOB_NOSPACE && r != GLOB_ABORTED && r != GLOB_NOMATCH)
	{
	  unsigned prefix_len = dirname.size () + 1;
	  for (unsigned i = 0; i < globbuf.gl_pathc; ++i)
	    {
	      string oldname = globbuf.gl_pathv[i];
	      if (oldname.substr (oldname.size () - 2) == "/." ||
		  oldname.substr (oldname.size () - 3) == "/..")
		continue;
	      string newname = s.tmpdir + "/" + oldname.substr (prefix_len);
	      if (s.verbose >= 3)
               clog << _F("  found %s -- linking from %s", oldname.c_str(), newname.c_str());
	      rc = symlink (oldname.c_str (), newname.c_str ());
	      if (rc != 0)
		{
                 clog << _F("Unable to link '%s' to '%s':%s\n",
			    oldname.c_str(), newname.c_str(), strerror(errno));
		  goto done;
		}
	    }
	}
    }

  // If the server version is less that 1.6, remove the output line due to the synthetic
  // server-side -k. Look for a message containing the name of the temporary directory.
  // We can look for the English message since server versions before 1.6 do not support
  // localization.
  if (server_version < "1.6")
    {
      cmd = { "sed", "-i", "/^Keeping temporary directory.*/ d", server_tmpdir + "/stderr" };
      stap_system (s.verbose, cmd);
    }

  // Remove the output line due to the synthetic server-side -p4
  cmd = { "sed", "-i", "/^.*\\.ko$/ d", server_tmpdir + "/stdout" };
  stap_system (s.verbose, cmd);

 done:
  globfree (& globbuf);
  return rc;
}

void
nss_client_backend::show_server_compatibility () const
{
  // Locale sensitivity was added in version 1.6
  if (server_version < "1.6")
    {
      clog << _F("Server protocol version is %s\n", server_version.v);
      clog << _("The server does not use localization information passed by the client\n");
    }
}

int
nss_client_backend::trust_server_info (const compile_server_info &server)
{
  return client_connect (server, NULL, NULL, "permanent");
}

#endif // HAVE_NSS

/* vim: set sw=2 ts=8 cino=>4,n-2,{2,^-2,t0,(0,u0,w1,M1 : */
