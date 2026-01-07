#include "fs.h"
#include "logger.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_init(void) {
  fs fs;
  assert(fs_init(&fs, 16));
  assert(fs.meta.total_node_count == 16);
  assert(fs.table[0].status == NODE_DIR_ENTRY);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_init passed.\n");
}

static void test_create_and_read(void) {
  fs fs;
  assert(fs_init(&fs, 32));

  const char *name = "hello";
  const char *msg = "world";
  assert(create_file(&fs, name, ROOT, (const uint8_t *)msg, strlen(msg)));

  uint64_t size = 0;
  uint8_t *buf = read_file(&fs, name, ROOT, false, &size);
  assert(buf != NULL);
  assert(size == strlen(msg));
  assert(memcmp(buf, msg, size) == 0);
  free(buf);

  fs_free(&fs);
  log_msg(LOG_INFO, "test_create_and_read passed.\n");
}

static void test_write_overwrite(void) {
  fs fs;
  assert(fs_init(&fs, 64));

  const char *name = "sample";
  const char *msg1 = "short";
  const char *msg2 = "this is a longer overwrite string";

  assert(write_file(&fs, name, ROOT, (const uint8_t *)msg1, strlen(msg1)));
  assert(write_file(&fs, name, ROOT, (const uint8_t *)msg2, strlen(msg2)));

  uint64_t size = 0;
  uint8_t *buf = read_file(&fs, name, ROOT, 0, &size);
  assert(size == strlen(msg2));
  assert(memcmp(buf, msg2, size) == 0);
  free(buf);

  fs_free(&fs);
  log_msg(LOG_INFO, "test_write_overwrite passed.\n");
}

static void test_delete(void) {
  fs fs;
  assert(fs_init(&fs, 32));

  const char *name = "deleteme";
  const char *msg = "bye";
  assert(create_file(&fs, name, ROOT, (const uint8_t *)msg, strlen(msg)));
  assert(delete_file(&fs, name, ROOT));

  uint64_t size = 0;
  uint8_t *buf = read_file(&fs, name, ROOT, 0, &size);
  assert(buf == NULL); /* should not exist */
  fs_free(&fs);
  log_msg(LOG_INFO, "test_delete passed.\n");
}

static uint8_t *make_buffer(size_t n, uint8_t seed) {
  uint8_t *buf = malloc(n);
  for (size_t i = 0; i < n; i++)
    buf[i] = (uint8_t)(seed + (i % 251));
  return buf;
}

static void test_multi_node_file(void) {
  fs fs;
  assert(fs_init(&fs, 128));

  size_t big_size = DATA_BYTES_PER_NODE * 3 + 100; /* spans 4 nodes */
  uint8_t *buf = make_buffer(big_size, 42);

  assert(create_file(&fs, "bigfile", ROOT, buf, big_size));

  uint64_t size = 0;
  uint8_t *out = read_file(&fs, "bigfile", ROOT, 0, &size);
  assert(out != NULL);
  assert(size == big_size);
  assert(memcmp(out, buf, big_size) == 0);

  free(buf);
  free(out);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_multi_node_file passed.\n");
}

static void test_overwrite_shrink_and_grow(void) {
  fs fs;
  assert(fs_init(&fs, 128));

  const char *name = "resize";
  uint8_t *buf1 = make_buffer(DATA_BYTES_PER_NODE * 2, 11);
  uint8_t *buf2 = make_buffer(10, 99);
  uint8_t *buf3 = make_buffer(DATA_BYTES_PER_NODE * 5, 77);

  /* grow */
  assert(write_file(&fs, name, ROOT, buf1, DATA_BYTES_PER_NODE * 2));
  uint64_t size = 0;
  uint8_t *out = read_file(&fs, name, ROOT, 0, &size);
  assert(size == DATA_BYTES_PER_NODE * 2);
  assert(memcmp(out, buf1, size) == 0);
  free(out);

  /* shrink */
  assert(write_file(&fs, name, ROOT, buf2, 10));
  out = read_file(&fs, name, ROOT, 0, &size);
  assert(size == 10);
  assert(memcmp(out, buf2, 10) == 0);
  free(out);

  /* grow again */
  assert(write_file(&fs, name, ROOT, buf3, DATA_BYTES_PER_NODE * 5));
  out = read_file(&fs, name, ROOT, 0, &size);
  assert(size == DATA_BYTES_PER_NODE * 5);
  free(out);

  free(buf1);
  free(buf2);
  free(buf3);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_overwrite_shrink_and_grow passed.\n");
}

static void test_allocator_reuse(void) {
  fs fs;
  assert(fs_init(&fs, 32));

  for (int i = 0; i < 5; i++) {
    char name[32];
    sprintf(name, "f%d", i);
    assert(create_file(&fs, name, ROOT, (const uint8_t *)"abc", 3));
    assert(delete_file(&fs, name, ROOT));
  }

  uint32_t id = fs_allocate_node(&fs);
  assert(id != NULL_NODE_ID);
  assert(id <= fs.meta.largest_id_allocated_node);

  fs_free(&fs);
  log_msg(LOG_INFO, "test_allocator_reuse passed.\n");
}

static void test_delete_chain(void) {
  fs fs;
  assert(fs_init(&fs, 64));

  size_t big_size = DATA_BYTES_PER_NODE * 2 + 50;
  uint8_t *buf = make_buffer(big_size, 5);
  assert(create_file(&fs, "chain", ROOT, buf, big_size));
  assert(delete_file(&fs, "chain", ROOT));

  uint64_t size = 0;
  uint8_t *out = read_file(&fs, "chain", ROOT, false, &size);
  assert(out == NULL);

  free(buf);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_delete_chain passed.\n");
}

int main(void) {
  test_init();
  test_create_and_read();
  test_write_overwrite();
  test_delete();
  test_multi_node_file();
  test_overwrite_shrink_and_grow();
  test_allocator_reuse();
  test_delete_chain();
  log_msg(LOG_INFO, "All tests passed.\n");
  return 0;
}
