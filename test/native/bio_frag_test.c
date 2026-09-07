/* Compile the production sources with allocation/callback wrappers confined to
 * this test translation unit. Every invocation starts with a fresh once flag. */
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#define THREADS 16
static int fail_method_step;
static int fail_context;
static int test_first_use;
static atomic_int method_allocations;
static int method_frees;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static int entered;

static BIO_METHOD *test_method_new(int type, const char *name) {
  atomic_fetch_add(&method_allocations, 1);
  return fail_method_step == 1 ? NULL : BIO_meth_new(type, name);
}
static void test_method_free(BIO_METHOD *method) {
  method_frees++;
  BIO_meth_free(method);
}
static int test_set_read(BIO_METHOD *method, int (*cb)(BIO *, char *, int)) {
  if (test_first_use) {
    /* Hold publication until all competing callers have started. No sleep or
     * probability of a lucky thread schedule is needed to check single setup. */
    pthread_mutex_lock(&gate);
    while (entered != THREADS)
      pthread_cond_wait(&ready, &gate);
    pthread_mutex_unlock(&gate);
  }
  return fail_method_step == 2 ? 0 : BIO_meth_set_read(method, cb);
}
static int test_set_write(BIO_METHOD *method,
                          int (*cb)(BIO *, const char *, int)) {
  return fail_method_step == 3 ? 0 : BIO_meth_set_write(method, cb);
}
static int test_set_ctrl(BIO_METHOD *method,
                         long (*cb)(BIO *, int, long, void *)) {
  return fail_method_step == 4 ? 0 : BIO_meth_set_ctrl(method, cb);
}
static int test_set_create(BIO_METHOD *method, int (*cb)(BIO *)) {
  return fail_method_step == 5 ? 0 : BIO_meth_set_create(method, cb);
}
static int test_set_destroy(BIO_METHOD *method, int (*cb)(BIO *)) {
  return fail_method_step == 6 ? 0 : BIO_meth_set_destroy(method, cb);
}
static int test_set_callback_ctrl(BIO_METHOD *method,
                                  long (*cb)(BIO *, int, BIO_info_cb *)) {
  return fail_method_step == 7 ? 0 : BIO_meth_set_callback_ctrl(method, cb);
}
static void *test_context_calloc(size_t count, size_t size) {
  return fail_context ? NULL : calloc(count, size);
}

#define BIO_meth_new test_method_new
#define BIO_meth_free test_method_free
#define BIO_meth_set_read test_set_read
#define BIO_meth_set_write test_set_write
#define BIO_meth_set_ctrl test_set_ctrl
#define BIO_meth_set_create test_set_create
#define BIO_meth_set_destroy test_set_destroy
#define BIO_meth_set_callback_ctrl test_set_callback_ctrl
#define calloc test_context_calloc
#include "../../c_src/ex_dtls/bio_frag.c"
#undef BIO_meth_new
#undef BIO_meth_free
#undef BIO_meth_set_read
#undef BIO_meth_set_write
#undef BIO_meth_set_ctrl
#undef BIO_meth_set_create
#undef BIO_meth_set_destroy
#undef BIO_meth_set_callback_ctrl
#undef calloc

static int fail_ssl;
static int fail_bio_number;
static int fail_srtp;
static int bios_created;
static int bios_live;
static int ssl_live;
static int ctx_live;
static SSL *test_ssl_new(SSL_CTX *ctx) {
  SSL *ssl = fail_ssl ? NULL : SSL_new(ctx);
  if (ssl != NULL)
    ssl_live++;
  return ssl;
}
static int chain_size(BIO *bio) {
  int n = 0;
  for (; bio != NULL; bio = BIO_next(bio))
    n++;
  return n;
}
static void test_ssl_free(SSL *ssl) {
  if (ssl != NULL) {
    ssl_live--;
    bios_live -= chain_size(SSL_get_rbio(ssl));
    if (SSL_get_rbio(ssl) != SSL_get_wbio(ssl))
      bios_live -= chain_size(SSL_get_wbio(ssl));
  }
  SSL_free(ssl);
}
static BIO *test_bio_new(const BIO_METHOD *method) {
  bios_created++;
  BIO *bio = bios_created == fail_bio_number ? NULL : BIO_new(method);
  if (bio != NULL)
    bios_live++;
  return bio;
}
static int test_bio_free(BIO *bio) {
  if (bio != NULL)
    bios_live--;
  return BIO_free(bio);
}
static void test_bio_free_all(BIO *bio) {
  bios_live -= chain_size(bio);
  BIO_free_all(bio);
}
static SSL_CTX *test_ctx_new(const SSL_METHOD *method) {
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (ctx != NULL)
    ctx_live++;
  return ctx;
}
static void test_ctx_free(SSL_CTX *ctx) {
  if (ctx != NULL)
    ctx_live--;
  SSL_CTX_free(ctx);
}
static int test_set_srtp(SSL_CTX *ctx, const char *profiles) {
  return fail_srtp ? 1 : SSL_CTX_set_tlsext_use_srtp(ctx, profiles);
}
#define SSL_new test_ssl_new
#define SSL_free test_ssl_free
#define BIO_new test_bio_new
#define BIO_free test_bio_free
#define BIO_free_all test_bio_free_all
#define SSL_CTX_new test_ctx_new
#define SSL_CTX_free test_ctx_free
#define SSL_CTX_set_tlsext_use_srtp test_set_srtp
#include "../../c_src/ex_dtls/dtls.c"
#undef SSL_new
#undef SSL_free
#undef BIO_new
#undef BIO_free
#undef BIO_free_all
#undef SSL_CTX_new
#undef SSL_CTX_free
#undef SSL_CTX_set_tlsext_use_srtp

struct Worker {
  const BIO_METHOD *method;
  BIO *bio;
};
static void *initialize(void *arg) {
  struct Worker *worker = arg;
  pthread_mutex_lock(&gate);
  entered++;
  pthread_cond_broadcast(&ready);
  pthread_mutex_unlock(&gate);
  worker->method = BIO_f_frag();
  CHECK(worker->method != NULL);
  worker->bio = BIO_new(worker->method);
  CHECK(worker->bio != NULL);
  CHECK(BIO_get_data(worker->bio) != NULL);
  BIO *memory = BIO_new(BIO_s_mem());
  CHECK(memory != NULL);
  BIO_push(worker->bio, memory);
  char byte = 'x';
  CHECK(BIO_write(worker->bio, &byte, 1) == 1);
  CHECK(BIO_ctrl_pending(worker->bio) == 1);
  CHECK(BIO_read(worker->bio, &byte, 1) == 1 && byte == 'x');
  CHECK(BIO_ctrl_pending(worker->bio) == 0);
  return NULL;
}
static void concurrent_first_use(void) {
  pthread_t threads[THREADS];
  struct Worker workers[THREADS];
  test_first_use = 1;
  for (int i = 0; i < THREADS; i++)
    CHECK(pthread_create(&threads[i], NULL, initialize, &workers[i]) == 0);
  for (int i = 0; i < THREADS; i++)
    CHECK(pthread_join(threads[i], NULL) == 0);
  CHECK(atomic_load(&method_allocations) == 1);
  for (int i = 0; i < THREADS; i++) {
    CHECK(workers[i].method == workers[0].method);
    for (int j = 0; j < i; j++)
      CHECK(BIO_get_data(workers[i].bio) != BIO_get_data(workers[j].bio));
  }
  for (int i = 0; i < THREADS; i++)
    BIO_free_all(workers[i].bio);
}
static void method_failure(int step) {
  fail_method_step = step;
  CHECK(BIO_f_frag() == NULL);
  CHECK(BIO_f_frag() == NULL); /* A failed once initializer is never retried. */
  CHECK(atomic_load(&method_allocations) == 1);
  CHECK(method_frees == (step == 1 ? 0 : 1));
  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  CHECK(ctx != NULL);
  CHECK(create_ssl(ctx, MODE_CLIENT) == NULL);
  CHECK(ssl_live == 0 && bios_live == 0);
  SSL_CTX_free(ctx);
}
static void context_failure(void) {
  const BIO_METHOD *method = BIO_f_frag();
  CHECK(method != NULL);
  fail_context = 1;
  CHECK(BIO_new(method) == NULL);
  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  CHECK(ctx != NULL);
  CHECK(create_ssl(ctx, MODE_CLIENT) == NULL);
  CHECK(ssl_live == 0 && bios_live == 0);
  SSL_CTX_free(ctx);
  fail_context = 0;
  BIO *bio = BIO_new(method);
  CHECK(bio != NULL && BIO_get_data(bio) != NULL);
  BIO_free(bio);
}
static void ssl_failure(int step) {
  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  CHECK(ctx != NULL);
  fail_ssl = step == 0;
  fail_bio_number = step;
  CHECK(create_ssl(ctx, step == 4 ? -1 : MODE_CLIENT) == NULL);
  CHECK(ssl_live == 0 && bios_live == 0);
  fail_ssl = 0;
  fail_bio_number = 0;
  SSL *ssl = create_ssl(ctx, MODE_CLIENT);
  CHECK(ssl != NULL);
  test_ssl_free(ssl);
  CHECK(ssl_live == 0 && bios_live == 0);
  SSL_CTX_free(ctx);
}
static void fragment_boundaries(void) {
  BIO *bio = BIO_new(BIO_f_frag());
  BIO *memory = BIO_new(BIO_s_mem());
  CHECK(bio != NULL && memory != NULL);
  BIO_push(bio, memory);
  for (int count = 99; count <= 101; count++) {
    int accepted = count > MAX_FRAGS ? MAX_FRAGS : count;
    CHECK(BIO_ctrl_pending(bio) == 0);
    for (int i = 0; i < count; i++) {
      unsigned char packet[3] = {(unsigned char)i, 42, 99};
      CHECK(BIO_write(bio, packet, sizeof(packet)) ==
            (i < MAX_FRAGS ? (int)sizeof(packet) : 0));
    }
    for (int i = 0; i < accepted; i++) {
      unsigned char packet[3];
      CHECK(BIO_ctrl_pending(bio) == sizeof(packet));
      CHECK(BIO_read(bio, packet, sizeof(packet)) == sizeof(packet));
      CHECK(packet[0] == i && packet[1] == 42 && packet[2] == 99);
    }
    CHECK(BIO_ctrl_pending(bio) == 0);
    CHECK(BIO_ctrl_pending(memory) == 0);
    char byte = 'x';
    CHECK(BIO_read(bio, &byte, 1) == 0);
    CHECK(BIO_write(bio, &byte, 1) == 1);
    CHECK(BIO_read(bio, &byte, 1) == 1 && byte == 'x');
  }
  /* Missing context must remain a signed error, not an unsigned byte count. */
  void *ctx = BIO_get_data(bio);
  BIO_set_data(bio, NULL);
  char byte = 'x';
  CHECK(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL) == -1);
  CHECK(BIO_read(bio, &byte, 1) == -1);
  CHECK(BIO_write(bio, &byte, 1) == -1);
  BIO_set_data(bio, ctx);
  BIO_free_all(bio);
}
int main(int argc, char **argv) {
  CHECK(argc >= 2);
  if (strcmp(argv[1], "concurrent") == 0)
    concurrent_first_use();
  else if (strcmp(argv[1], "method-failure") == 0) {
    CHECK(argc == 3);
    method_failure(atoi(argv[2]));
  } else if (strcmp(argv[1], "context-failure") == 0)
    context_failure();
  else if (strcmp(argv[1], "ssl-failure") == 0) {
    CHECK(argc == 3);
    ssl_failure(atoi(argv[2]));
  } else if (strcmp(argv[1], "srtp-failure") == 0) {
    fail_srtp = 1;
    CHECK(create_ctx(1) == NULL);
    CHECK(ctx_live == 0);
  } else if (strcmp(argv[1], "boundaries") == 0)
    fragment_boundaries();
  else
    CHECK(0);
  puts("PASS");
  return 0;
}
