#include "dir.h"
#include "fs.h"
#include "logger.h"
#include "pfs.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static uint8_t *make_buffer(size_t n, uint8_t seed) {
  uint8_t *buf = malloc(n);
  for (size_t i = 0; i < n; i++)
    buf[i] = (uint8_t)(seed + (i % 251));
  return buf;
}

static char mount_point[100];
static pid_t fuse_child_pid = -1;

static const char *create_temp_mount_point() {
  strcpy(mount_point, "/tmp/pfs_test_XXXXXX");
  if (mkdtemp(mount_point) == NULL) {
    perror("mkdtemp failed");
    return NULL;
  }
  log_msg(LOG_INFO, "Created temporary mount point: %s", mount_point);
  return mount_point;
}

static void cleanup_temp_mount_point() {
  if (mount_point[0] != '\0') {
    char command[256];
    snprintf(command, sizeof(command), "fusermount -u %s 2>/dev/null",
             mount_point);
    system(command);

    if (rmdir(mount_point) == -1) {
      perror("rmdir failed");
    }
    log_msg(LOG_INFO, "Cleaned up temporary mount point: %s", mount_point);
    mount_point[0] = '\0';
  }
}

static int start_pfs_fuse(const char *mount_point) {
  fuse_child_pid = fork();
  if (fuse_child_pid == -1) {
    perror("fork failed");
    return -1;
  }

  if (fuse_child_pid == 0) {
    int fd = open("/dev/null", O_WRONLY);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);

    char *args[] = {"./bin/pfs", "-f", "-s", (char *)mount_point, NULL};
    execvp(args[0], args);
    perror("execvp failed");
    _exit(1);
  } else {
    // Wait for FUSE to mount
    int retries = 10;
    char mount_check_cmd[256];
    snprintf(mount_check_cmd, sizeof(mount_check_cmd),
             "grep -qs '%s' /proc/mounts", mount_point);

    while (retries > 0) {
      if (system(mount_check_cmd) == 0) {
        log_msg(LOG_INFO, "FUSE filesystem mounted at %s", mount_point);
        break;
      }
      sleep(1);
      retries--;
    }

    if (retries == 0) {
      log_msg(LOG_ERROR,
              "FUSE filesystem failed to mount at %s within timeout.",
              mount_point);
      kill(fuse_child_pid, SIGTERM);
      return -1;
    }
    log_msg(LOG_INFO, "pfs FUSE daemon started with PID: %d", fuse_child_pid);
  }
  return 0;
}

static void stop_pfs_fuse(const char *mount_point) {
  if (mount_point[0] != '\0') {
    char command[256];
    snprintf(command, sizeof(command), "fusermount -u %s", mount_point);
    if (system(command) == -1) {
      perror("fusermount -u failed");
    }
    log_msg(LOG_INFO, "Unmounted FUSE filesystem from %s", mount_point);
  }

  if (fuse_child_pid != -1) {
    kill(fuse_child_pid, SIGTERM);
    int status;
    waitpid(fuse_child_pid, &status, 0);
    log_msg(LOG_INFO, "pfs FUSE daemon (PID: %d) stopped.", fuse_child_pid);
    fuse_child_pid = -1;
  }
}

static void test_init(void) {
  fs fs;
  assert(fs_init(&fs, 16) == 0);
  assert(fs.meta.total_node_count == 16);
  assert(fs.table[0].status == NODE_DIR_ENTRY);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_init passed.\n");
}

static void test_create_and_read(void) {
  fs fs;
  assert(fs_init(&fs, 32) == 0);

  const char *name = "hello";
  const char *msg = "world";
  assert(create_file(&fs, name, ROOT, (const uint8_t *)msg, strlen(msg)) == 0);

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
  assert(fs_init(&fs, 64) == 0);

  const char *name = "sample";
  const char *msg1 = "short";
  const char *msg2 = "this is a longer overwrite string";

  assert(write_file(&fs, name, ROOT, (const uint8_t *)msg1, strlen(msg1)) == 0);
  assert(write_file(&fs, name, ROOT, (const uint8_t *)msg2, strlen(msg2)) == 0);

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
  assert(fs_init(&fs, 32) == 0);

  const char *name = "deleteme";
  const char *msg = "bye";
  assert(create_file(&fs, name, ROOT, (const uint8_t *)msg, strlen(msg)) == 0);
  assert(delete_file(&fs, name, ROOT) == 0);

  uint64_t size = 0;
  uint8_t *buf = read_file(&fs, name, ROOT, 0, &size);
  assert(buf == NULL);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_delete passed.\n");
}

static void test_multi_node_file(void) {
  fs fs;
  assert(fs_init(&fs, 128) == 0);

  size_t big_size = DATA_BYTES_PER_NODE * 3 + 100;
  uint8_t *buf = make_buffer(big_size, 42);

  assert(create_file(&fs, "bigfile", ROOT, buf, big_size) == 0);

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
  assert(fs_init(&fs, 128) == 0);

  const char *name = "resize";
  uint8_t *buf1 = make_buffer(DATA_BYTES_PER_NODE * 2, 11);
  uint8_t *buf2 = make_buffer(10, 99);
  uint8_t *buf3 = make_buffer(DATA_BYTES_PER_NODE * 5, 77);

  assert(write_file(&fs, name, ROOT, buf1, DATA_BYTES_PER_NODE * 2) == 0);
  uint64_t size = 0;
  uint8_t *out = read_file(&fs, name, ROOT, 0, &size);
  assert(size == DATA_BYTES_PER_NODE * 2);
  assert(memcmp(out, buf1, size) == 0);
  free(out);

  assert(write_file(&fs, name, ROOT, buf2, 10) == 0);
  out = read_file(&fs, name, ROOT, 0, &size);
  assert(size == 10);
  assert(memcmp(out, buf2, 10) == 0);
  free(out);

  assert(write_file(&fs, name, ROOT, buf3, DATA_BYTES_PER_NODE * 5) == 0);
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
  assert(fs_init(&fs, 32) == 0);

  for (int i = 0; i < 5; i++) {
    char name[32];
    sprintf(name, "f%d", i);
    assert(create_file(&fs, name, ROOT, (const uint8_t *)"abc", 3) == 0);
    assert(delete_file(&fs, name, ROOT) == 0);
  }

  uint32_t id = fs_allocate_node(&fs);
  assert(id != NULL_NODE_ID);
  assert(id <= fs.meta.largest_id_allocated_node);

  fs_free(&fs);
  log_msg(LOG_INFO, "test_allocator_reuse passed.\n");
}

static void test_delete_chain(void) {
  fs fs;
  assert(fs_init(&fs, 64) == 0);

  size_t big_size = DATA_BYTES_PER_NODE * 2 + 50;
  uint8_t *buf = make_buffer(big_size, 5);
  assert(create_file(&fs, "chain", ROOT, buf, big_size) == 0);
  assert(delete_file(&fs, "chain", ROOT) == 0);

  uint64_t size = 0;
  uint8_t *out = read_file(&fs, "chain", ROOT, false, &size);
  assert(out == NULL);

  free(buf);
  fs_free(&fs);
  log_msg(LOG_INFO, "test_delete_chain passed.\n");
}

static void test_symlinks(void) {
  fs fs;
  assert(fs_init(&fs, 64) == 0);

  const char *file_name = "original_file";
  const char *file_content = "This is the original content.";
  assert(create_file(&fs, file_name, ROOT, (const uint8_t *)file_content,
                     strlen(file_content)) == 0);

  const char *symlink_name = "link_to_file";
  assert(fs_symlink(&fs, file_name, symlink_name) == 0);

  uint64_t size = 0;
  uint8_t *read_symlink_content =
      read_file(&fs, symlink_name, ROOT, false, &size);
  assert(read_symlink_content != NULL);
  assert(size == strlen(file_content));
  assert(memcmp(read_symlink_content, file_content, size) == 0);
  free(read_symlink_content);

  char target_buf[FILE_NAME_SIZE];
  assert(fs_readlink(&fs, symlink_name, target_buf, FILE_NAME_SIZE) == 0);
  assert(strcmp(target_buf, file_name) == 0);

  struct stat st;
  uint32_t symlink_node_id = get_node_from_path(&fs, symlink_name, false);
  assert(symlink_node_id != NULL_NODE_ID);
  memcpy(&st, &fs.table[symlink_node_id].st, sizeof(struct stat));
  assert(S_ISLNK(st.st_mode));
  assert(st.st_size == (off_t)strlen(file_name));

  fs_free(&fs);
  log_msg(LOG_INFO, "test_symlinks passed.\n");
}

static void test_pfs_interaction(void) {
  fs my_fs;
  assert(fs_init(&my_fs, 1000) == 0);
  set_log_level(LOG_DEBUG);

  assert(create_file(&my_fs, "testfile", ROOT, (const uint8_t *)"test", 4) ==
         0);

  struct stat stbuf;
  uint32_t testfile_node_id = find_node(&my_fs, "testfile", ROOT, true);
  assert(testfile_node_id != NULL_NODE_ID);
  memcpy(&stbuf, &my_fs.table[testfile_node_id].st, sizeof(struct stat));
  assert(stbuf.st_size == 4);

  uint64_t size = 0;
  uint8_t *read_buf = read_file(&my_fs, "testfile", ROOT, false, &size);
  assert(read_buf != NULL);
  assert(size == 4);
  assert(memcmp(read_buf, "test", 4) == 0);
  free(read_buf);

  fs_free(&my_fs);
  log_msg(LOG_INFO, "test_pfs_interaction passed.\n");
}

static void test_fuse_file_operations(void) {
  log_msg(LOG_INFO, "Starting FUSE integration tests...");
  const char *mount_point_path = create_temp_mount_point();
  assert(mount_point_path != NULL);
  assert(!start_pfs_fuse(mount_point_path));
  char filepath[256];

  snprintf(filepath, sizeof(filepath), "%s/testfile.txt", mount_point_path);
  const char *test_content = "Hello, FUSE!";
  size_t test_content_len = strlen(test_content);
  log_msg(LOG_INFO, "Test 1: Creating and writing to %s", filepath);

  int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd != -1);
  assert(write(fd, test_content, test_content_len) ==
         (ssize_t)test_content_len);
  close(fd);
  log_msg(LOG_INFO, "Test 1 Passed: File created and content written.");
  log_msg(LOG_INFO, "Test 2: Reading from %s", filepath);

  char read_buf[256] = {0};
  fd = open(filepath, O_RDONLY);
  assert(fd != -1);
  assert(read(fd, read_buf, test_content_len) == (ssize_t)test_content_len);
  assert(strcmp(read_buf, test_content) == 0);
  close(fd);
  log_msg(LOG_INFO, "Test 2 Passed: Content read matches written content.");

  log_msg(LOG_INFO, "Test 3: Stat-ing %s", filepath);
  struct stat st;
  assert(stat(filepath, &st) == 0);
  assert(st.st_size == (off_t)test_content_len);
  assert(S_ISREG(st.st_mode));
  log_msg(LOG_INFO, "Test 3 Passed: File size and mode are correct.");

  char dirpath[256];
  snprintf(dirpath, sizeof(dirpath), "%s/testdir", mount_point_path);
  log_msg(LOG_INFO, "Test 4: Creating directory %s", dirpath);
  assert(mkdir(dirpath, 0755) == 0);
  log_msg(LOG_INFO, "Test 4 Passed: Directory created.");

  log_msg(LOG_INFO, "Test 5: Listing directory %s", mount_point_path);
  DIR *dp = opendir(mount_point_path);
  assert(dp != NULL);
  struct dirent *de;
  int found_testfile = 0;
  int found_testdir = 0;
  while ((de = readdir(dp)) != NULL) {
    if (strcmp(de->d_name, "testfile.txt") == 0) {
      found_testfile = 1;
      if (strcmp(de->d_name, "testdir") == 0) {
        found_testdir = 1;
      }
    }
  }

  closedir(dp);
  assert(found_testfile == 1);
  assert(found_testdir == 1);
  log_msg(LOG_INFO, "Test 5 Passed: Listed files and directories correctly.");

  char symlink_path[256];
  snprintf(symlink_path, sizeof(symlink_path), "%s/symlink_to_file",
           mount_point_path);
  assert(symlink("testfile.txt", symlink_path) == 0);
  char readlink_buf[256];
  ssize_t link_len =
      readlink(symlink_path, readlink_buf, sizeof(readlink_buf) - 1);
  assert(link_len > 0);
  readlink_buf[link_len] = '\0';
  assert(strcmp(readlink_buf, "testfile.txt") == 0);

  log_msg(LOG_INFO, "Test 6: Deleting file %s", filepath);
  assert(unlink(filepath) == 0);
  assert(access(filepath, F_OK) == -1 && errno == ENOENT);
  log_msg(LOG_INFO, "Test 6 Passed: File deleted.");

  snprintf(dirpath, sizeof(dirpath), "%s/testdir", mount_point_path);
  log_msg(LOG_INFO, "Test 7: Deleting directory %s", dirpath);
  int res = rmdir(dirpath);
  if (res != 0) {
    log_msg(LOG_ERROR, "rmdir failed with errno: %d (%s)", errno,
            strerror(errno));
  }
  assert(res == 0);
  assert(access(dirpath, F_OK) == -1 && errno == ENOENT);
  log_msg(LOG_INFO, "Test 7 Passed: Directory deleted.");
  log_msg(LOG_INFO, "All FUSE integration tests passed.");
  stop_pfs_fuse(mount_point_path);
  cleanup_temp_mount_point();
}

int main(void) {
  set_log_level(LOG_DEBUG);
  test_init();
  test_create_and_read();
  test_write_overwrite();
  test_delete();
  test_multi_node_file();
  test_overwrite_shrink_and_grow();
  test_allocator_reuse();
  test_delete_chain();
  test_symlinks();
  test_pfs_interaction();
  test_fuse_file_operations();
  log_msg(LOG_INFO, "All tests passed.\n");
  return 0;
}
