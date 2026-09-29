/*
 * wolfssl-driver: a small DTLS peer program on libwolfssl, for the interop
 * cases wolfSSL's example client / server cannot express (see
 * ../wolfssl-driver.sh). It speaks DTLS 1.3 or DTLS 1.2, one or two
 * sequential connections, and prints one `key: value` fact per line on
 * stdout for the adapter's `verify`:
 *
 *   == connection N
 *   version: DTLSv1.3
 *   cipher: TLS_AES_128_GCM_SHA256
 *   group: X25519
 *   resumed: yes|no
 *   early data: accepted|rejected|none
 *   early data received: <line>        (server)
 *   received: <line>
 *
 * What it adds over the examples:
 *   - the server calls wolfSSL_dtls13_no_hrr_on_resume() (with
 *     --no-hrr-on-resume; libwolfssl must be built with
 *     WOLFSSL_DTLS13_NO_HRR_ON_RESUME), so a DTLS 1.3 resumption skips the
 *     cookie HelloRetryRequest and 0-RTT can be accepted (RFC 9147 §5.1,
 *     RFC 8446 §4.2.10); early data is read with wolfSSL_read_early_data;
 *   - the server keeps ONE bound UDP socket across connections (the
 *     examples close and rebind it), so a reconnecting client never meets a
 *     closed port;
 *   - the client keeps its session with wolfSSL_get1_session /
 *     wolfSSL_set_session and writes 0-RTT with wolfSSL_write_early_data.
 *
 * Usage:
 *   driver server --port P --cert F --key F [--dtls12] [--accept N]
 *                 [--early-data] [--no-hrr-on-resume] [--cipher LIST]
 *                 [--group x25519|p256] [--reply TEXT]
 *   driver client --port P --ca F --sni NAME [--dtls12] [--resume]
 *                 [--early-data FILE] [--cipher LIST] [--group x25519|p256]
 *                 [--msg TEXT]
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUF 4096

struct opts {
    int server;
    int port;
    int dtls12;
    int accept;
    int early_data;
    int no_hrr_on_resume;
    int resume;
    const char *cert, *key, *ca, *sni, *cipher, *group, *msg, *reply;
    const char *early_file;
};

static void die(const char *what)
{
    fprintf(stderr, "wolfssl-driver: %s\n", what);
    exit(1);
}

static void die_ssl(WOLFSSL *ssl, int ret, const char *what)
{
    char buf[WOLFSSL_MAX_ERROR_SZ];
    int err = wolfSSL_get_error(ssl, ret);
    fprintf(stderr, "wolfssl-driver: %s: %d %s\n", what, err,
            wolfSSL_ERR_error_string((unsigned long)err, buf));
    exit(1);
}

static void set_group(WOLFSSL *ssl, const char *group)
{
    int g;
    if (group == NULL)
        return;
    if (strcmp(group, "x25519") == 0)
        g = WOLFSSL_ECC_X25519;
    else if (strcmp(group, "p256") == 0)
        g = WOLFSSL_ECC_SECP256R1;
    else
        die("unknown --group");
    if (wolfSSL_set_groups(ssl, &g, 1) != WOLFSSL_SUCCESS)
        die("wolfSSL_set_groups");
}

/* Prints the negotiated parameters of a completed handshake. */
static void report(WOLFSSL *ssl, int dtls12, int early_offered)
{
    const char *curve = wolfSSL_get_curve_name(ssl);
    printf("version: %s\n", wolfSSL_get_version(ssl));
    printf("cipher: %s\n",
           wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(ssl)));
    printf("group: %s\n", curve ? curve : "none");
    printf("resumed: %s\n", wolfSSL_session_reused(ssl) ? "yes" : "no");
#ifdef WOLFSSL_EARLY_DATA
    if (dtls12) {
        printf("early data: none\n");
    } else {
        switch (wolfSSL_get_early_data_status(ssl)) {
        case WOLFSSL_EARLY_DATA_ACCEPTED:
            printf("early data: accepted\n");
            break;
        case WOLFSSL_EARLY_DATA_REJECTED:
            printf("early data: rejected\n");
            break;
        default:
            printf("early data: %s\n", early_offered ? "rejected" : "none");
        }
    }
#else
    (void)dtls12;
    (void)early_offered;
    printf("early data: none\n");
#endif
    fflush(stdout);
}

/* Prints each line of `buf[0..n)` as `prefix: line`. */
static void print_lines(const char *prefix, const char *buf, int n)
{
    int start = 0, i;
    for (i = 0; i <= n; i++) {
        if (i == n || buf[i] == '\n') {
            if (i > start)
                printf("%s: %.*s\n", prefix, i - start, buf + start);
            start = i + 1;
        }
    }
    fflush(stdout);
}

static WOLFSSL_CTX *make_ctx(const struct opts *o)
{
    WOLFSSL_METHOD *m;
    WOLFSSL_CTX *ctx;
    if (o->server)
        m = o->dtls12 ? wolfDTLSv1_2_server_method() : wolfDTLSv1_3_server_method();
    else
        m = o->dtls12 ? wolfDTLSv1_2_client_method() : wolfDTLSv1_3_client_method();
    ctx = wolfSSL_CTX_new(m);
    if (ctx == NULL)
        die("wolfSSL_CTX_new");
    if (o->cipher && wolfSSL_CTX_set_cipher_list(ctx, o->cipher) != WOLFSSL_SUCCESS)
        die("wolfSSL_CTX_set_cipher_list");
    if (o->server) {
        if (wolfSSL_CTX_use_certificate_chain_file(ctx, o->cert) != WOLFSSL_SUCCESS)
            die("cannot load --cert");
        if (wolfSSL_CTX_use_PrivateKey_file(ctx, o->key, WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS)
            die("cannot load --key");
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
#ifdef WOLFSSL_EARLY_DATA
        if (o->early_data && !o->dtls12)
            wolfSSL_CTX_set_max_early_data(ctx, 16384);
#endif
    } else {
        if (wolfSSL_CTX_load_verify_locations(ctx, o->ca, NULL) != WOLFSSL_SUCCESS)
            die("cannot load --ca");
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
#ifdef HAVE_SESSION_TICKET
    /* RFC 5077 for DTLS 1.2 (the client asks, the server issues); DTLS 1.3
     * tickets need no opt-in. */
    wolfSSL_CTX_UseSessionTicket(ctx);
#endif
    return ctx;
}

static int udp_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = {30, 0};
    if (fd < 0)
        die("socket");
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static int run_server(const struct opts *o)
{
    WOLFSSL_CTX *ctx = make_ctx(o);
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    int fd = udp_socket(), on = 1, conn;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)o->port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
        die("bind");
    if (getsockname(fd, (struct sockaddr *)&addr, &len) == 0)
        fprintf(stderr, "listening on 127.0.0.1:%d\n", ntohs(addr.sin_port));

    for (conn = 1; conn <= o->accept; conn++) {
        struct sockaddr_in peer;
        socklen_t plen;
        unsigned char b[1500];
        char buf[BUF];
        WOLFSSL *ssl;
        int n, ret, early_seen = 0;

        /* Learn the client from its first handshake datagram, dropping
         * leftovers of the previous connection (its close_notify, an ACK). */
        for (;;) {
            plen = sizeof peer;
            n = (int)recvfrom(fd, b, sizeof b, MSG_PEEK, (struct sockaddr *)&peer, &plen);
            if (n <= 0)
                die("no ClientHello arrived");
            if (b[0] == 0x16 && n > 13 && b[3] == 0 && b[4] == 0)
                break;
            recvfrom(fd, b, sizeof b, 0, (struct sockaddr *)&peer, &plen);
        }
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL)
            die("wolfSSL_new");
        set_group(ssl, o->group);
        wolfSSL_set_fd(ssl, fd);
        wolfSSL_dtls_set_peer(ssl, &peer, plen);
#ifdef WOLFSSL_DTLS13_NO_HRR_ON_RESUME
        if (o->no_hrr_on_resume && !o->dtls12)
            wolfSSL_dtls13_no_hrr_on_resume(ssl, 1);
#else
        if (o->no_hrr_on_resume)
            die("--no-hrr-on-resume: libwolfssl lacks WOLFSSL_DTLS13_NO_HRR_ON_RESUME");
#endif
        printf("== connection %d\n", conn);
#ifdef WOLFSSL_EARLY_DATA
        if (o->early_data && !o->dtls12) {
            /* Drives the handshake as far as the early data allows and
             * returns what the client sent under 0-RTT (RFC 8446 §4.2.10). */
            do {
                int got = 0;
                ret = wolfSSL_read_early_data(ssl, buf, sizeof buf - 1, &got);
                if (ret > 0 && got > 0) {
                    print_lines("early data received", buf, got);
                    early_seen = 1;
                }
            } while (ret > 0);
            if (ret < 0)
                die_ssl(ssl, ret, "wolfSSL_read_early_data");
        }
#endif
        ret = wolfSSL_accept(ssl);
        if (ret != WOLFSSL_SUCCESS)
            die_ssl(ssl, ret, "wolfSSL_accept");
        report(ssl, o->dtls12, early_seen);
        /* One request, answered. */
        n = wolfSSL_read(ssl, buf, sizeof buf - 1);
        if (n > 0) {
            print_lines("received", buf, n);
            if (o->reply)
                wolfSSL_write(ssl, o->reply, (int)strlen(o->reply));
            else
                wolfSSL_write(ssl, buf, n);
        }
        /* Wait for the client's close_notify so the next connection starts
         * on a quiet socket. */
        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    close(fd);
    wolfSSL_CTX_free(ctx);
    return 0;
}

static int run_client(const struct opts *o)
{
    WOLFSSL_CTX *ctx = make_ctx(o);
    WOLFSSL_SESSION *session = NULL;
    struct sockaddr_in addr;
    int conn, conns = o->resume ? 2 : 1;
    char early[BUF];
    int early_len = 0;

    if (o->early_file) {
        FILE *f = fopen(o->early_file, "rb");
        if (f == NULL)
            die("cannot open --early-data file");
        early_len = (int)fread(early, 1, sizeof early, f);
        fclose(f);
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)o->port);

    for (conn = 1; conn <= conns; conn++) {
        WOLFSSL *ssl = wolfSSL_new(ctx);
        int fd = udp_socket(), ret, n, early_offered = 0;
        char buf[BUF];
        const char *msg = o->msg ? o->msg : "ping from wolfssl-driver\n";

        if (ssl == NULL)
            die("wolfSSL_new");
        set_group(ssl, o->group);
        if (o->sni)
            wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, o->sni, (unsigned short)strlen(o->sni));
        /* A fresh socket (and source port) per connection, as wolfSSL's own
         * client does; left unconnected — wolfSSL sends to the peer set
         * below, and sendto() with an address fails on a connected socket
         * on the BSDs. */
        wolfSSL_set_fd(ssl, fd);
        wolfSSL_dtls_set_peer(ssl, &addr, sizeof addr);
        if (session != NULL && wolfSSL_set_session(ssl, session) != WOLFSSL_SUCCESS)
            die("wolfSSL_set_session");
        printf("== connection %d\n", conn);
#ifdef WOLFSSL_EARLY_DATA
        if (session != NULL && early_len > 0 && !o->dtls12) {
            int written = 0;
            ret = wolfSSL_write_early_data(ssl, early, early_len, &written);
            if (ret < 0)
                die_ssl(ssl, ret, "wolfSSL_write_early_data");
            early_offered = 1;
        }
#endif
        ret = wolfSSL_connect(ssl);
        if (ret != WOLFSSL_SUCCESS)
            die_ssl(ssl, ret, "wolfSSL_connect");
        report(ssl, o->dtls12, early_offered);
#ifdef WOLFSSL_EARLY_DATA
        /* Rejected early data was never delivered (RFC 8446 §4.2.10). */
        if (early_offered && wolfSSL_get_early_data_status(ssl) != WOLFSSL_EARLY_DATA_ACCEPTED)
            wolfSSL_write(ssl, early, early_len);
#endif
        if (wolfSSL_write(ssl, msg, (int)strlen(msg)) <= 0)
            die("wolfSSL_write");
        /* Read the answer(s); the reads also process the server's
         * post-handshake NewSessionTicket. Stop after two quiet seconds —
         * by poll(), not a read timeout, which would leave the session in
         * an error state and wolfSSL_shutdown() would send no
         * close_notify. */
        for (;;) {
            if (wolfSSL_pending(ssl) == 0) {
                struct pollfd p = {fd, POLLIN, 0};
                if (poll(&p, 1, 2000) <= 0)
                    break;
            }
            n = wolfSSL_read(ssl, buf, sizeof buf - 1);
            if (n <= 0) {
                int err = wolfSSL_get_error(ssl, n);
                /* A record that carried no application data (a ticket, an
                 * ACK) is not the end. */
                if (err == WOLFSSL_ERROR_WANT_READ)
                    continue;
                break;
            }
            print_lines("received", buf, n);
        }
        if (conn < conns) {
            session = wolfSSL_get1_session(ssl);
            if (session == NULL)
                die("no session to resume");
        }
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(fd);
    }
    if (session != NULL)
        wolfSSL_SESSION_free(session);
    wolfSSL_CTX_free(ctx);
    return 0;
}

int main(int argc, char **argv)
{
    struct opts o;
    int i;

    memset(&o, 0, sizeof o);
    o.accept = 1;
    if (argc < 2)
        die("usage: driver server|client [options]");
    o.server = strcmp(argv[1], "server") == 0;
    for (i = 2; i < argc; i++) {
        const char *a = argv[i];
#define VAL() (i + 1 < argc ? argv[++i] : (die("missing value"), ""))
        if (strcmp(a, "--port") == 0) o.port = atoi(VAL());
        else if (strcmp(a, "--cert") == 0) o.cert = VAL();
        else if (strcmp(a, "--key") == 0) o.key = VAL();
        else if (strcmp(a, "--ca") == 0) o.ca = VAL();
        else if (strcmp(a, "--sni") == 0) o.sni = VAL();
        else if (strcmp(a, "--cipher") == 0) o.cipher = VAL();
        else if (strcmp(a, "--group") == 0) o.group = VAL();
        else if (strcmp(a, "--msg") == 0) o.msg = VAL();
        else if (strcmp(a, "--reply") == 0) o.reply = VAL();
        else if (strcmp(a, "--accept") == 0) o.accept = atoi(VAL());
        else if (strcmp(a, "--dtls12") == 0) o.dtls12 = 1;
        else if (strcmp(a, "--resume") == 0) o.resume = 1;
        else if (strcmp(a, "--no-hrr-on-resume") == 0) o.no_hrr_on_resume = 1;
        else if (strcmp(a, "--early-data") == 0) {
            if (o.server)
                o.early_data = 1;
            else
                o.early_file = VAL();
        } else
            die("unknown option");
#undef VAL
    }
    wolfSSL_Init();
    return o.server ? run_server(&o) : run_client(&o);
}
