/* Linker flags : lcrypto and lssl
 * Openssl is decprecated in mac os x. Ignore
 * such warnings */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#define R_CERT_FILE         "/etc/ssl/certs/"
#define R_HTTP_GET          "GET / HTTP/1.1"
#define R_READ_BUF_LEN      4096
#define R_GET_LEN           100
#define MAXDNSNAMES         10
#define DNSNAMELEN          128
#define R_SUCCESS           0 
#define R_FAILED            1


/* Only printing here. Verifcation done later */
int
handle_certificate_verification (int preverify, X509_STORE_CTX *x509_ctx)
{
    X509 *cert      = NULL;
    BIO *bio_out    = NULL;

    if (NULL == x509_ctx) {
        printf ("Err: Null check failed in handle_certificate_verification\n");
        return preverify;
    }

    cert = X509_STORE_CTX_get_current_cert (x509_ctx);

    if (NULL == cert) {
	printf ("Err: cert is NULL in handle_certificate_verification\n");
        return preverify; 
    }

    bio_out = BIO_new_fp (stdout, BIO_NOCLOSE);
    if (NULL == bio_out) {
        printf ("Err: bio out not allocated\n");
        return preverify;
    }

    printf ("Certificate Issuer\n");
    X509_NAME_print_ex (bio_out, X509_get_issuer_name (cert), 0, XN_FLAG_MULTILINE);
    BIO_printf (bio_out, "\n");
    printf ("Certificate Subject\n");
    X509_NAME_print_ex (bio_out, X509_get_subject_name (cert), 0, XN_FLAG_MULTILINE);
    BIO_printf (bio_out, "\n=======\n");

    BIO_free_all (bio_out);
    return preverify;
}


/* Initialize SSL library and context.
 * Returns SSL_CTX.
 * NULL check on calling. */
SSL_CTX *
ssl_ctx_init ()
{
    SSL_CTX *ctx                            = NULL;
    SSL_METHOD *method                      = NULL;

    /* ignore return value - init always returns 1 
     * and no return for error */
    SSL_library_init (); 
    SSL_load_error_strings();

    method = (SSL_METHOD *)SSLv23_client_method ();
    if (NULL == method) {
        printf ("Err: %s\n", ERR_reason_error_string (ERR_get_error()));
        /* printf ("Err: method failed\n"); */
        return NULL;
    }

    ctx = SSL_CTX_new (method);

    return ctx;
}
 
/* Load CA certificates.
 * Returns Failed/Success */
int
load_ca_certificates (SSL_CTX *ctx)
{
    signed long ret = 0;
    if (NULL == ctx) {
        return R_FAILED;
    }

    /* No diagnostic return values */
    SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                        handle_certificate_verification);

    /* Load CA certificate */
    ret = SSL_CTX_load_verify_locations (ctx, /* R_CERT_FILE */ NULL, /* NULL */ R_CERT_FILE );
    if (ret != 1) {
        printf ("Err: %s, return %lu\n", ERR_reason_error_string (ERR_get_error()), ret);
        /* printf ("Err: Certificates not loaded.\n"); */
        return R_FAILED;
    }

    return R_SUCCESS;
}

/* create TCP socket. Returns R_SUCCESS or 
 * R_FAILED  */
int
create_tcp_socket (int *sock_fd, char *host, int portnumber,
                   struct sockaddr_in *addr)
{
    struct hostent *hostname        = NULL;

    if (NULL == sock_fd || NULL == host || NULL == addr) {
        printf ("Err: NULL checks in create_tcp_socket\n");
        return R_FAILED;
    }

    hostname = gethostbyname (host);
    if (NULL == hostname) {
        printf ("Err: Host name lookup failed.\n");
        return R_FAILED;
    }

    /* Set up TCP/IP socket */
    *sock_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*sock_fd < 0) {
        printf ("Err: Socket failed\n");
        return R_FAILED;
    }

    memset (addr, 0, sizeof (struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons (portnumber);
    memcpy (&addr->sin_addr, hostname->h_addr, hostname->h_length);

    return R_SUCCESS;    
}


/* Initiate the handshake */
int
initiate_handshake (SSL *ssl)
{
    signed long ret = 0;

    if (NULL == ssl) {
        printf ("Err: null check in initiate_handshake failed\n");
        return R_FAILED;
    }

    ret = SSL_connect (ssl);
    if (ret != 1) {
        printf ("Err: %s\n", ERR_error_string (SSL_get_error (ssl, ret), NULL));
        return R_FAILED;
    }

    return R_SUCCESS;
}

/* Compare dnsname and hostname, including '*' */
int
compare_dns_host (char *dnsname, char *hostname)
{
    char *str       = NULL;

    if (NULL == dnsname || NULL == hostname) {
        printf ("Err: Null check failed in compare_dns_host\n");
        return R_FAILED;
    }

    if (strcmp (dnsname, hostname) == 0) {
        return R_SUCCESS;
    }
    /* Checking for *. Compares only right side of * and
     * checks if the string is found anywhere in hostname */
    else { 
        str = strtok (dnsname, "*");
        while (str != NULL) {
            if (strstr (hostname, str) == NULL)
                return R_FAILED;
            str = strtok (NULL, "*");
        }
        return R_SUCCESS;
    }

    return R_FAILED;
}

/* host name validation */
int
verify_hostname (X509 *cert, char *hostname)
{
    STACK_OF (GENERAL_NAME) *names              = NULL;   
    GENERAL_NAME *name                          = NULL;
    char dnsname[MAXDNSNAMES][DNSNAMELEN]       = {0};
    int num_names                               = 0;
    int i                                       = 0;
    int j                                       = 0;
    int max_name_checks                         = 0;

    if (NULL == cert) {
        printf ("Err: Null check failed in verify_hostname\n");
        return R_FAILED;
    }

    /* Extranct subject Alt names */
    names = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);

    if (NULL == names) {
        printf ("Err: Subject Alt Name not found\n");
        return R_FAILED;
    }

    num_names = sk_GENERAL_NAME_num (names);

    max_name_checks = num_names > MAXDNSNAMES ? MAXDNSNAMES : num_names;

    /* Compare all names with hostname */
    for (i = 0; i < max_name_checks; i++) { 
        name = sk_GENERAL_NAME_value (names, i);
        if (name->type != GEN_DNS) {
            printf ("Err: Name type not DNS\n");
            goto EXIT;
        }

        if (ASN1_STRING_type (name->d.ia5) != V_ASN1_IA5STRING) {
            printf ("Err: Malformed Certificate. Not AS1 string.\n");
            goto EXIT;
        }

        /* Copying to display later if validation fails */
        strncpy (dnsname[i], (char *) ASN1_STRING_data (name->d.dNSName), DNSNAMELEN);

        if (compare_dns_host (dnsname[i], hostname) != R_SUCCESS) {
        //if (strcmp (dnsname[i], hostname) != 0) {
            continue;
        }
        else {
            sk_GENERAL_NAME_pop_free (names, GENERAL_NAME_free);
            return R_SUCCESS;
        }
    }

    printf ("Exiting due to error: Peer certificate SAN does not match Host name. "
            "Expected %s, Found DNS: ", hostname);
    for (j = 0; j <= i; j++) {
        printf ("%s ", dnsname[j]);
    }
    printf ("\n");

EXIT:
    sk_GENERAL_NAME_pop_free (names, GENERAL_NAME_free);
    return R_FAILED;
}


int
send_http_request (SSL *ssl, char *send_buf)
{
    signed long ret = 0;

    if (NULL == ssl || NULL == send_buf) {
        printf ("Err: null checks in send_http_request\n");
        return R_FAILED;
    }

    ret = SSL_write (ssl, send_buf, strlen (send_buf));
    if (ret != strlen (send_buf)) {
        printf ("Err: SSL_write returns %lu\n", ret);
        return R_FAILED;
    }

    return R_SUCCESS;
}


int
read_http_response (SSL *ssl, char *read_buf)
{
    if (NULL == ssl || NULL == read_buf) {
        printf ("Err: Null checks failed read_http_response\n");
        return R_FAILED;
    }

    if  (SSL_read (ssl, read_buf, R_READ_BUF_LEN-1) <= 0) {
        printf ("Err: %s\n", ERR_reason_error_string (ERR_get_error()));
        return R_FAILED;
    }

    /* Dump the response - HTML code */
    printf ("%s\n", read_buf);

    return R_SUCCESS;
}

/* Returns nothing - best effort */
void
ssl_cleanup (SSL_CTX *ctx, SSL *ssl)
{
    if (ctx != NULL) {
        SSL_CTX_free (ctx);
    }

    if (ssl != NULL) {
        SSL_shutdown (ssl);
        /* SSL_free frees BIO as well */
        SSL_free (ssl);
    }
}

int
main (int argc, char *argv[])
{
    SSL_CTX *ctx                            = NULL;
    SSL *ssl                                = NULL;
    BIO *bio                                = NULL;
    X509 *cert                              = NULL;
    char http_get_request[R_GET_LEN]        = {0};
    char read_buf[R_READ_BUF_LEN]           = {0};
    struct sockaddr_in addr                 = {0};
    int sock_fd                             = 0;

    /* Check on the arguments passed */
    if (argc < 3) {
        printf ("Err: Two arguments needed - url and port\n");
        goto EXIT;
    }

    ctx = ssl_ctx_init ();
    if (NULL == ctx) {
        printf ("Err: %s\n", ERR_reason_error_string (ERR_get_error()));
        /* printf ("Err: new CTX failed\n"); */
        goto EXIT;
    }

    /* load certificate */
    if (load_ca_certificates (ctx) != R_SUCCESS) {
        goto EXIT;
    }

    ssl = SSL_new (ctx);
    if (NULL == ssl) {
        printf ("Err: ssl failed\n");
        goto EXIT;
    }

    if (create_tcp_socket (&sock_fd, argv[1], atoi(argv[2]), &addr) != R_SUCCESS) {
        goto EXIT;
    }

    if (connect (sock_fd, (struct sockaddr *) &addr, sizeof (struct sockaddr_in)) < 0) {
        printf ("Err: Connection failed\n");
        goto EXIT;
    }

    /* Use BIO to link ssl to the socket */
    bio = BIO_new_socket (sock_fd, BIO_NOCLOSE);
    SSL_set_bio (ssl, bio, bio);

    /* Handshake */
    if (initiate_handshake (ssl) != R_SUCCESS) {
        goto EXIT;
    }

    /* Get result */
    if (SSL_get_verify_result (ssl) != X509_V_OK) {
        printf ("Exiting due to error: %s\n", ERR_reason_error_string (ERR_get_error()));
        goto EXIT;
    }

    cert = SSL_get_peer_certificate (ssl);
    if (NULL == cert) {
        printf ("Exiting due to error: Peer certificate not found\n");
        goto EXIT;
    }

    if (verify_hostname (cert, argv[1]) != R_SUCCESS) {
        goto EXIT;
    }

    /* '\r\n' is not working. replaced with ASCII values. */
    sprintf (http_get_request, "%s\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A",
             R_HTTP_GET, argv[1]);

    if (send_http_request (ssl, http_get_request) != R_SUCCESS) {
        goto EXIT;
    }

    printf ("----------Dumping HTTP response--------\n");

    /* Memset the read buffer */
    memset (read_buf, 0, R_READ_BUF_LEN);
    read_http_response (ssl, read_buf);
        
    ssl_cleanup (ctx, ssl);
    return R_SUCCESS;

EXIT:
    ssl_cleanup (ctx, ssl);
    return R_FAILED;
}
