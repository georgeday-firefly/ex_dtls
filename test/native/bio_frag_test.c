#include <assert.h>
#include <openssl/bio.h>
#include "../../c_src/ex_dtls/bio_frag.h"

int main(void) {
  BIO *bio = BIO_new(BIO_f_frag());
  BIO *memory = BIO_new(BIO_s_mem());
  assert(bio != NULL && memory != NULL);
  BIO_push(bio, memory);

  // Reject the 101st fragment, then drain and reuse the same queue.
  for (int count = 99; count <= 101; count++) {
    int accepted = count > 100 ? 100 : count;
    for (int i = 0; i < count; i++) {
      unsigned char byte = (unsigned char)i;
      assert(BIO_write(bio, &byte, 1) == (i < 100 ? 1 : 0));
    }
    for (int i = 0; i < accepted; i++) {
      unsigned char byte;
      assert(BIO_ctrl_pending(bio) == 1);
      assert(BIO_read(bio, &byte, 1) == 1);
      assert(byte == i);
    }
    assert(BIO_ctrl_pending(bio) == 0);
    assert(BIO_ctrl_pending(memory) == 0);
  }

  BIO_free_all(bio);
  return 0;
}
