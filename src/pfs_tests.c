#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "pfs.h"
#include "logger.h"

static void test_pfs_interaction(void) {
  assert(fs_init(&my_fs, 1000));
  set_log_level(LOG_DEBUG);

  assert(create_file(&my_fs, "testfile", ROOT, (const uint8_t *)"test", 4));

  struct stat stbuf;
  assert(pfs_getattr("/testfile", &stbuf) == 0);
  assert(stbuf.st_size == 4);

  char read_buf[10];
  assert(pfs_read("/testfile", read_buf, 4, 0, NULL) == 4);
  assert(memcmp(read_buf, "test", 4) == 0);

  fs_free(&my_fs);
  log_msg(LOG_INFO, "test_pfs_interaction passed.\n");
}

int main(void) {
  test_pfs_interaction();
  log_msg(LOG_INFO, "All PFS tests passed.\n");
  return 0;
}

