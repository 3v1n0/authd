#include <security/_pam_types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <security/pam_appl.h>
#include <sys/socket.h>

# define SSHD_PAM_SERVICE "sshd"

#define sshpam_const	const	/* LinuxPAM, OpenPAM, AIX */

# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)

typedef pid_t sp_pthread_t;
#define pthread_exit    fake_pthread_exit
#define pthread_create  fake_pthread_create
#define pthread_cancel  fake_pthread_cancel
#define pthread_join    fake_pthread_join

typedef int SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1

struct pam_ctxt {
				sp_pthread_t     pam_thread;
				int              pam_psock;
				int              pam_csock;
				SshPamDone       pam_done;
};

typedef int SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1

static struct pam_ctxt *cleanup_ctxt;

static u_int do_pam_account(void);
static int do_pam_putenv(char *name, char *value);

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

static int sshpam_thread_status = -1;
static __sighandler_t sshpam_oldsig;
static const char *service_name = SSHD_PAM_SERVICE;
static const char *service_path = NULL;

static void
sshpam_sigchld_handler(int sig)
{
	signal(SIGCHLD, SIG_DFL);
	if (cleanup_ctxt == NULL)
		return;	/* handler called after PAM cleanup, shouldn't happen */
	if (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
			<= 0) {
		/* PAM thread has not exitted, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		while (waitpid(cleanup_ctxt->pam_thread,
				&sshpam_thread_status, 0) == -1) {
			if (errno == EINTR)
				continue;
			return;
		}
	}
	if (WIFSIGNALED(sshpam_thread_status) &&
			WTERMSIG(sshpam_thread_status) == SIGTERM)
		return;	/* terminated by pthread_cancel */
	if (!WIFEXITED(sshpam_thread_status)) {
		printf("PAM: authentication thread exited unexpectedly\n");
		abort();
	}
	if (WEXITSTATUS(sshpam_thread_status) != 0) {
		printf("PAM: authentication thread exited uncleanly");
		abort();
	}
}

/* ARGSUSED */
static void
pthread_exit(void *value)
{
	_exit(0);
}

#define error(str, ...) printf("ERROR:" str "\n", ##__VA_ARGS__)
#define debug(str, ...) printf("DEBUG:" str "\n", ##__VA_ARGS__)
#define debug1(str, ...) printf("DEBUG1:" str "\n", ##__VA_ARGS__)
#define debug2(str, ...) printf("DEBUG2:" str "\n", ##__VA_ARGS__)
#define debug3(str, ...) printf("DEBUG3:" str "\n", ##__VA_ARGS__)
#define fatal(str, ...) { printf(str "\n", ##__VA_ARGS__); abort(); }

/* ARGSUSED */
static int
pthread_create(sp_pthread_t *thread, const void *attr,
		void *(*thread_start)(void *), void *arg)
{
	pid_t pid;
	struct pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	switch ((pid = fork())) {
	case -1:
		error("fork(): %s", strerror(errno));
		return errno;
	case 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	default:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = signal(SIGCHLD, sshpam_sigchld_handler);
		return (0);
	}
}

static int
pthread_cancel(sp_pthread_t thread)
{
	signal(SIGCHLD, sshpam_oldsig);
	return (kill(thread, SIGTERM));
}

/* ARGSUSED */
static int
pthread_join(sp_pthread_t thread, void **value)
{
	int status;

	if (sshpam_thread_status != -1)
		return (sshpam_thread_status);
	signal(SIGCHLD, sshpam_oldsig);
	while (waitpid(thread, &status, 0) == -1) {
		if (errno == EINTR)
			continue;
		fatal("%s: waitpid: %s", __func__, strerror(errno));
	}
	return (status);
}
#endif


static pam_handle_t *sshpam_handle = NULL;
static int sshpam_err = PAM_SYSTEM_ERR;
static int sshpam_authenticated = 0;
static int sshpam_session_open = 0;
static int sshpam_cred_established = 0;
static int sshpam_account_status = -1;
static char *sshpam_rhost = NULL;
static char *sshpam_laddr = NULL;

/*
 * Conversation function for authentication thread.
 */
static int
sshpam_thread_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	int i;

	debug3("PAM: %s entering, %d messages", __func__, n);
	*resp = NULL;

	if ((reply = calloc(n, sizeof(*reply))) == NULL)
		return PAM_CONV_ERR;

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_OFF:
			debug3("PROMPT OFF: %s", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = getpass(PAM_MSG_MEMBER(msg, i, msg));
			break;
		case PAM_PROMPT_ECHO_ON: {
			debug3("PROMPT ON: %s", PAM_MSG_MEMBER(msg, i, msg));
				char *buffer = NULL;
				size_t len;
				printf("%s: ", PAM_MSG_MEMBER(msg, i, msg));
				if (getline(&buffer, &len, stdin) == -1) {
					free(buffer);
					error("Can't get input");
					goto fail;
				}
				reply[i].resp = buffer;
				printf("Got input");
			}
			break;
		case PAM_ERROR_MSG:
			debug3("ERROR: %s", PAM_MSG_MEMBER(msg, i, msg));
			break;
		case PAM_TEXT_INFO:
			debug3("INFO: %s", PAM_MSG_MEMBER(msg, i, msg));
			break;
		default:
			goto fail;
		}
	}
	*resp = reply;
	return (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	return (PAM_CONV_ERR);
}

static int force_pwchange = 0;

/*
 * Authentication thread.
 */
static void *
sshpam_thread(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;
	struct pam_conv sshpam_conv;
	int flags = 0;
	extern char **environ;
	const char *pam_user;
	const char **ptr_pam_user = &pam_user;
	char *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
			(sshpam_const void **)ptr_pam_user);
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	environ[0] = NULL;
	if (tz != NULL)
		if (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
					strerror(errno));

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
			(const void *)&sshpam_conv);
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	debug3("Starting PAM authentication");
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	debug3("PAM Authenticate, returning %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	if (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		goto auth_fail;
	}
	if (force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
				PAM_CHANGE_EXPIRED_AUTHTOK);
		if (sshpam_err != PAM_SUCCESS)
			goto auth_fail;
	}

 auth_fail:
	debug3("Done with PAM, returning %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));
	pthread_exit(NULL);

	return (NULL); /* Avoid warning for non-pthread case */
}

void
sshpam_thread_cleanup(void)
{
	struct pam_ctxt *ctxt = cleanup_ctxt;

	debug3("PAM: %s entering", __func__);
	if (ctxt != NULL && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, NULL);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, sizeof(*ctxt));
		cleanup_ctxt = NULL;
	}
}

static int
sshpam_null_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	debug3("PAM: %s entering, %d messages", __func__, n);
	return (PAM_CONV_ERR);
}

static struct pam_conv null_conv = { sshpam_null_conv, NULL };

void
sshpam_cleanup(void)
{
	if (sshpam_handle == NULL)
		return;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (const void *)&null_conv);
	if (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	if (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	sshpam_err |= pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = NULL;
}

static int
sshpam_init(const char *user)
{
	const char *pam_user;
	const char **ptr_pam_user = &pam_user;
	int r;

	if (sshpam_handle != NULL) {
		/* We already have a PAM context; check if the user matches */
		sshpam_err = pam_get_item(sshpam_handle,
				PAM_USER, (sshpam_const void **)ptr_pam_user);
		if (sshpam_err == PAM_SUCCESS && strcmp(user, pam_user) == 0)
			return (0);
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
	}
	debug("PAM: initializing \"%s\" for \"%s\"", service_name, user);
	if (service_path != NULL) {
		sshpam_err = pam_start_confdir(service_name, user, &null_conv, service_path, &sshpam_handle);
	} else {
		sshpam_err = pam_start(service_name, user, &null_conv, &sshpam_handle);
	}

	if (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		return (-1);
	}

	sshpam_rhost = "fake-rhost";
	if (sshpam_rhost != NULL) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
				sshpam_rhost);
		if (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = NULL;
			return (-1);
		}
	}
	if (sshpam_laddr != NULL) {
		/* Put SSH_CONNECTION in the PAM environment too */
		if ((r = pam_putenv(sshpam_handle, "SSH_CONNECTION=fake conn 1")) != PAM_SUCCESS)
			debug("pam_putenv: %s", pam_strerror(sshpam_handle, r));
	}

	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	if (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		return (-1);
	}

	return 0;
}

static void
expose_authinfo(const char *caller)
{
	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", "auth-info");
}

static void *
sshpam_init_ctx(const char *user)
{
	struct pam_ctxt *ctxt;
	int result, socks[2];

	debug3("PAM: %s entering", __func__);

	/* Initialize PAM */
	if (sshpam_init(user) == -1) {
		error("PAM: initialization failed");
		return (NULL);
	}

	expose_authinfo(__func__);
	ctxt = calloc(1, sizeof *ctxt);

	/* Start the authentication thread */
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		free(ctxt);
		return (NULL);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, NULL, sshpam_thread, ctxt);
	if (result != 0) {
		error("PAM: failed to start authentication thread: %s",
				strerror(result));
		close(socks[0]);
		close(socks[1]);
		free(ctxt);
		return (NULL);
	}
	cleanup_ctxt = ctxt;
	return (ctxt);
}

static u_int
do_pam_account(void)
{
	debug("%s: called", __func__);
	if (sshpam_account_status != -1)
		return (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
			pam_strerror(sshpam_handle, sshpam_err));

	if (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		return (sshpam_account_status);
	}

	if (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		force_pwchange = 1;

	sshpam_account_status = 1;
	return (sshpam_account_status);
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
static int
do_pam_putenv(char *name, char *value)
{
	int ret = 1;
	char *compound;
	size_t len;

	len = strlen(name) + strlen(value) + 2;
	compound = malloc(len);

	snprintf(compound, len, "%s=%s", name, value);
	ret = pam_putenv(sshpam_handle, compound);
	free(compound);

	return (ret);
}

int main(int argc, char* argv[])
{
	struct pam_ctxt *ctxt;

	if (argc > 1)
		service_name = argv[1];

	if (argc > 2)
		service_path = argv[2];

	ctxt = sshpam_init_ctx(getenv("USER"));
	pthread_join(ctxt->pam_thread, NULL);
	sshpam_cleanup();

	close(ctxt->pam_psock);
	close(ctxt->pam_csock);
	memset(ctxt, 0, sizeof(*ctxt));
	free(ctxt);
	cleanup_ctxt = NULL;

	sshpam_thread_cleanup();

	debug("PAM: Exiting with code %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));

	return sshpam_err;
}
