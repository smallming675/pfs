#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     // fork, execvp, sleep
#include <sys/wait.h>   // waitpid
#include <fcntl.h>      // open, O_RDWR, O_CREAT, O_TRUNC
#include <errno.h>      // errno
#include <dirent.h>     // opendir, readdir, closedir

#include "pfs.h"
#include "logger.h"

static char mount_point_path[100];
static pid_t fuse_child_pid = -1;

// Helper to create a temporary mount point
static const char *create_temp_mount_point() {
    strcpy(mount_point_path, "/tmp/pfs_test_XXXXXX");
    if (mkdtemp(mount_point_path) == NULL) {
        perror("mkdtemp failed");
        return NULL;
    }
    log_msg(LOG_INFO, "Created temporary mount point: %s", mount_point_path);
    return mount_point_path;
}

// Helper to clean up the temporary mount point
static void cleanup_temp_mount_point() {
    if (mount_point_path[0] != '\0') {
        if (rmdir(mount_point_path) == -1) {
            perror("rmdir failed");
        }
        log_msg(LOG_INFO, "Cleaned up temporary mount point: %s", mount_point_path);
        mount_point_path[0] = '\0'; // Clear the path
    }
}

// Helper to start the pfs FUSE process
static int start_pfs_fuse(const char *mount_point) {
    fuse_child_pid = fork();
    if (fuse_child_pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (fuse_child_pid == 0) {
        // Child process
        char *args[] = {"./bin/pfs", "-f", "-s", (char *)mount_point, NULL};
        execvp(args[0], args);
        perror("execvp failed"); // Should not reach here
        _exit(1);
    } else {
        // Parent process
        // Robustly wait for FUSE to mount
        int retries = 10; // Max 10 retries
        char mount_check_cmd[256];
        snprintf(mount_check_cmd, sizeof(mount_check_cmd), "grep -qs '%s' /proc/mounts", mount_point);

        while (retries > 0) {
            if (system(mount_check_cmd) == 0) {
                log_msg(LOG_INFO, "FUSE filesystem mounted at %s", mount_point);
                break;
            }
            sleep(1);
            retries--;
        }

        if (retries == 0) {
            log_msg(LOG_ERROR, "FUSE filesystem failed to mount at %s within timeout.", mount_point);
            kill(fuse_child_pid, SIGTERM);
            return -1;
        }
        log_msg(LOG_INFO, "pfs FUSE daemon started with PID: %d", fuse_child_pid);
    }
    return 0;
}

// Helper to stop the pfs FUSE process
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


static void test_fuse_file_operations(void) {
    log_msg(LOG_INFO, "Starting FUSE integration tests...");

    const char *mount_point = create_temp_mount_point();
    assert(mount_point != NULL);

    assert(start_pfs_fuse(mount_point) == 0);

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/testfile.txt", mount_point);
    const char *test_content = "Hello, FUSE!";
    size_t test_content_len = strlen(test_content);

    // Test 1: Create and Write to a file
    log_msg(LOG_INFO, "Test 1: Creating and writing to %s", filepath);
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd != -1);
    assert(write(fd, test_content, test_content_len) == (ssize_t)test_content_len);
    close(fd);
    log_msg(LOG_INFO, "Test 1 Passed: File created and content written.");

    // Test 2: Read from the file
    log_msg(LOG_INFO, "Test 2: Reading from %s", filepath);
    char read_buf[256] = {0};
    fd = open(filepath, O_RDONLY);
    assert(fd != -1);
    assert(read(fd, read_buf, test_content_len) == (ssize_t)test_content_len);
    assert(strcmp(read_buf, test_content) == 0);
    close(fd);
    log_msg(LOG_INFO, "Test 2 Passed: Content read matches written content.");

    // Test 3: Stat the file
    log_msg(LOG_INFO, "Test 3: Stat-ing %s", filepath);
    struct stat st;
    assert(stat(filepath, &st) == 0);
    assert(st.st_size == (off_t)test_content_len);
    assert(S_ISREG(st.st_mode));
    log_msg(LOG_INFO, "Test 3 Passed: File size and mode are correct.");

    // Test 4: Create a directory
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "%s/testdir", mount_point);
    log_msg(LOG_INFO, "Test 4: Creating directory %s", dirpath);
    assert(mkdir(dirpath, 0755) == 0);
    log_msg(LOG_INFO, "Test 4 Passed: Directory created.");

    // Test 5: List directory contents
    log_msg(LOG_INFO, "Test 5: Listing directory %s", mount_point);
    DIR *dp = opendir(mount_point);
    assert(dp != NULL);
    struct dirent *de;
    int found_testfile = 0;
    int found_testdir = 0;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, "testfile.txt") == 0) {
            found_testfile = 1;
        }
        if (strcmp(de->d_name, "testdir") == 0) {
            found_testdir = 1;
        }
    }
    closedir(dp);
    assert(found_testfile == 1);
    assert(found_testdir == 1);
    log_msg(LOG_INFO, "Test 5 Passed: Listed files and directories correctly.");

    // Test 6: Delete the file
    log_msg(LOG_INFO, "Test 6: Deleting file %s", filepath);
    assert(unlink(filepath) == 0);
    assert(access(filepath, F_OK) == -1 && errno == ENOENT); // Verify file is gone
    log_msg(LOG_INFO, "Test 6 Passed: File deleted.");

    snprintf(dirpath, sizeof(dirpath), "%s/testdir", mount_point); 
    log_msg(LOG_INFO, "Test 7: Deleting directory %s", dirpath);
    int res = rmdir(dirpath);
    if (res != 0) {
        log_msg(LOG_ERROR, "rmdir failed with errno: %d (%s)", errno, strerror(errno));
    }
    assert(res == 0);
    assert(access(dirpath, F_OK) == -1 && errno == ENOENT); 
    log_msg(LOG_INFO, "Test 7 Passed: Directory deleted.");
    
    log_msg(LOG_INFO, "All FUSE integration tests passed.");

    stop_pfs_fuse(mount_point);
    cleanup_temp_mount_point();
}



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
  test_fuse_file_operations();
  log_msg(LOG_INFO, "All PFS tests passed.\n");
  return 0;
}
