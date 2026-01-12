#define FUSE_USE_VERSION 26
#include "pfs.h"
#include "dir.h"
#include "fs.h"
#include "logger.h"
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

fs file_system;

#ifndef TEST_BUILD
char *mount_point = NULL;
struct fuse_chan *g_ch = NULL;
struct fuse *g_fuse = NULL;

void unmount_fs(void) {
  if (mount_point && g_ch) {
    fuse_unmount(mount_point, g_ch);
    mount_point = NULL;
    g_ch = NULL;
  }
}

static void unmount_handler(int sig) {
  (void)sig;
  unmount_fs();
  signal(sig, SIG_DFL);
  raise(sig);
}
#endif


int pfs_getattr(const char *path, struct stat *stbuf) {
  log_msg(LOG_DEBUG, "pfs_getattr: path='%s'", path);
  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) {
    memcpy(stbuf, &file_system.table[ROOT].st, sizeof(struct stat));
    log_msg(LOG_INFO, "pfs_getattr: Retrieved attributes for root directory.");
    return 0;
  }

  uint32_t node_id = get_node_from_path(&file_system, path, false);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_getattr: Path not found: %s", path);
    return -ENOENT;
  }

  fs_node *node = &file_system.table[node_id];
  memcpy(stbuf, &node->st, sizeof(struct stat));

  if (node->status == NODE_SYMLINK) {
    stbuf->st_mode = S_IFLNK | 0777;
    stbuf->st_size = strlen(node->data.symlink.target_path);
  }

  log_msg(LOG_INFO, "pfs_getattr: Retrieved attributes for %s (node_id: %u).",
          path, node_id);

  return 0;
}

int pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                off_t offset, struct fuse_file_info *fi) {
  (void)offset;
  (void)fi;
  uint32_t node_id = get_node_from_path(&file_system, path, true);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_readdir: Path not found: %s", path);
    return -ENOENT;
  }

  if (file_system.table[node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "pfs_readdir: Not a directory: %s", path);
    return -ENOTDIR;
  }

  filler(buf, ".", &file_system.table[node_id].st, 0);
  filler(buf, "..", &file_system.table[ROOT].st, 0);

  log_msg(LOG_DEBUG, "pfs_readdir: Directory %s (node_id: %u) has %u entries.",
          path, node_id, file_system.table[node_id].data.dir_entry.entry_count);

  for (uint32_t i = 0; i < file_system.table[node_id].data.dir_entry.entry_count;
       ++i) {
    uint32_t entry_id = file_system.table[node_id].data.dir_entry.entries[i];
    if (entry_id == NULL_NODE_ID) {
      continue;
    }

    fs_node *entry_node = &file_system.table[entry_id];
    const char *entry_name = NULL;
    if (entry_node->status == NODE_DIR_ENTRY) {
      entry_name = entry_node->data.dir_entry.dir_name;
    } else if (entry_node->status == NODE_SINGLE_NODE_FILE ||
               entry_node->status == NODE_FILE_START) {
      entry_name = entry_node->data.header_file.file_name;
    } else if (entry_node->status == NODE_SYMLINK) {
      entry_name = entry_node->data.symlink.link_name;
    }
    if (entry_name) {
      filler(buf, entry_name, &entry_node->st, 0);
      log_msg(LOG_DEBUG, "pfs_readdir: Added entry '%s' to buffer.",
              entry_name);
    }
  }
  log_msg(LOG_INFO, "pfs_readdir: Successfully listed directory: %s", path);
  return 0;
}

int pfs_read(const char *path, char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi) {
  (void)fi;
  uint32_t node_id = get_node_from_path(&file_system, path, true);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_read: File not found: %s", path);
    return -ENOENT;
  }

  if (file_system.table[node_id].status == NODE_SYMLINK) {
    log_msg(LOG_ERROR, "pfs_read: Cannot read from a symlink directly: %s",
            path);
    return -EINVAL;
  }

  if (!S_ISREG(file_system.table[node_id].st.st_mode)) {
    log_msg(LOG_ERROR, "pfs_read: Not a regular file: %s", path);
    return -EISDIR;
  }

  uint64_t file_size;
  uint8_t *file_content = read_from_path(&file_system, path, false, &file_size);
  if (!file_content) {
    log_msg(LOG_ERROR, "pfs_read: Error reading file: %s", path);
    return -EIO;
  }

  uint64_t bytes_to_read = size;
  if ((uint64_t)offset < file_size) {
    if ((uint64_t)offset + bytes_to_read > file_size) {
      bytes_to_read = file_size - offset;
    }
    memcpy(buf, file_content + offset, bytes_to_read);
  } else {
    bytes_to_read = 0;
  }
  free(file_content);
  log_msg(LOG_INFO, "pfs_read: Successfully read %zu bytes from %s",
          bytes_to_read, path);

  return bytes_to_read;
}

int pfs_write(const char *path, const char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi) {
  (void)fi;
  log_msg(LOG_DEBUG, "pfs_write: path='%s', size=%zu, offset=%lld", path, size,
          offset);
  uint32_t node_id = get_node_from_path(&file_system, path, true);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_write: File not found: %s", path);
    return -ENOENT;
  }

  if (!S_ISREG(file_system.table[node_id].st.st_mode)) {
    log_msg(LOG_ERROR, "pfs_write: Not a regular file: %s", path);
    return -EISDIR;
  }

  uint64_t old_size;
  uint8_t *old_content = read_from_path(&file_system, path, false, &old_size);
  if (!old_content && old_size > 0) {
    log_msg(LOG_ERROR, "pfs_write: Error reading existing file: %s", path);
    return -EIO;
  }
  uint64_t new_size = offset + size;
  if (new_size < old_size) {
    new_size = old_size;
  }

  uint8_t *new_content = (uint8_t *)realloc(old_content, new_size);
  if (!new_content) {
    log_msg(LOG_ERROR, "pfs_write: Failed to allocate memory for new content.");
    if (old_content)
      free(old_content);
    return -ENOMEM;
  }

  memcpy(new_content + offset, buf, size);
  if (write_from_path(&file_system, path, new_content, new_size) != 0) {
    log_msg(LOG_ERROR, "pfs_write: Failed to write to file: %s", path);
    free(new_content);
    return -EIO;
  }

  free(new_content);
  log_msg(LOG_INFO, "pfs_write: Successfully wrote %zu bytes to %s", size,
          path);
  return size;
}

int pfs_mknod(const char *path, mode_t mode, dev_t rdev) {
  log_msg(LOG_DEBUG, "pfs_mknod: path='%s', mode=%o", path, mode);
  (void)rdev;

  if (!S_ISREG(mode)) {
    log_msg(LOG_ERROR,
            "pfs_mknod: Only regular files can be created. Invalid mode: %o",
            mode);
    return -EACCES;
  }
  char parent_path[256];
  char new_file_name[256];
  char *last_slash = strrchr(path, '/');
  if (last_slash == NULL || last_slash == path) {
    strcpy(parent_path, "/");
  } else {
    strncpy(parent_path, path, last_slash - path);
    parent_path[last_slash - path] = '\0';
  }

  strcpy(new_file_name, last_slash + 1);
  uint32_t parent_id = get_node_from_path(&file_system, parent_path, true);
  if (parent_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_mknod: Parent directory not found: %s",
            parent_path);
    return -ENOENT;
  }

  if (create_file(&file_system, new_file_name, parent_id, NULL, 0) != 0) {
    log_msg(LOG_ERROR, "pfs_mknod: Failed to create file: %s", new_file_name);
    return -EIO;
  }

  log_msg(LOG_INFO, "pfs_mknod: Successfully created file: %s", path);
  return 0;
}

int pfs_unlink(const char *path) {
  log_msg(LOG_DEBUG, "pfs_unlink: path='%s'", path);
  if (delete_from_path(&file_system, path) != 0) {
    log_msg(LOG_ERROR, "pfs_unlink: Failed to delete file: %s", path);
    return -EIO;
  }
  log_msg(LOG_INFO, "pfs_unlink: Successfully deleted file: %s", path);
  return 0;
}

int pfs_utimens(const char *path, const struct timespec tv[2]) {
  uint32_t node_id = get_node_from_path(&file_system, path, true);
  if (node_id == NULL_NODE_ID) {
    return -ENOENT;
  }
  file_system.table[node_id].st.st_atime = tv[0].tv_sec;
  file_system.table[node_id].st.st_mtime = tv[1].tv_sec;
  return 0;
}

int pfs_mkdir(const char *path, mode_t mode) {
  log_msg(LOG_DEBUG, "pfs_mkdir: path='%s', mode=%o", path, mode);
  char parent_path[256];
  char new_dir_name[256];
  char *last_slash = strrchr(path, '/');
  if (last_slash == NULL) {
    return -EINVAL;
  }
  if (last_slash == path) {
    strcpy(parent_path, "/");
  } else {
    strncpy(parent_path, path, last_slash - path);
    parent_path[last_slash - path] = '\0';
  }
  strcpy(new_dir_name, last_slash + 1);
  uint32_t parent_id = get_node_from_path(&file_system, parent_path, true);
  if (parent_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_mkdir: Parent directory not found: %s",
            parent_path);
    return -ENOENT;
  }
  if (create_dir(&file_system, parent_id, new_dir_name) != 0) {
    log_msg(LOG_ERROR,
            "pfs_mkdir: Failed to create directory: %s, create_dir returned 0",
            new_dir_name);
    return -EIO;
  }
  uint32_t new_dir_node_id = get_node_from_path(&file_system, path, true);
  if (new_dir_node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "pfs_mkdir: Failed to get new dir node ID after creation: %s",
            path);
    return -EIO;
  }
  log_msg(LOG_INFO,
          "pfs_mkdir: Successfully created directory: %s (node id: %u)", path,
          new_dir_node_id);
  return 0;
}

int pfs_rmdir(const char *path) {
  log_msg(LOG_DEBUG, "pfs_rmdir: path='%s'", path);
  if (strcmp(path, "/") == 0) {
    log_msg(LOG_ERROR, "pfs_rmdir: Cannot remove root directory.");
    return -EPERM;
  }

  uint32_t node_id = get_node_from_path(&file_system, path, true);
  log_msg(LOG_DEBUG,
          "pfs_rmdir: get_node_from_path for '%s' returned node_id: %u", path,
          node_id);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "pfs_rmdir: Directory not found: %s", path);
    return -ENOENT;
  }
  if (file_system.table[node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "pfs_rmdir: Not a directory: %s", path);
    return -ENOTDIR;
  }
  if (file_system.table[node_id].data.dir_entry.entry_count > 0) {
    log_msg(LOG_ERROR, "pfs_rmdir: Directory not empty: %s", path);
    return -ENOTEMPTY;
  }
  if (delete_from_path(&file_system, path) != 0) {
    log_msg(LOG_ERROR, "pfs_rmdir: Failed to delete directory: %s", path);
    return -EIO;
  }
  log_msg(LOG_INFO, "pfs_rmdir: Successfully deleted directory: %s", path);
  return 0;
}

int pfs_symlink(const char *target, const char *newpath) {
  log_msg(LOG_DEBUG, "pfs_symlink: target='%s', newpath='%s'", target, newpath);
  return fs_symlink(&file_system, target, newpath);
}

int pfs_readlink(const char *path, char *buf, size_t size) {
  return fs_readlink(&file_system, path, buf, size);
}

#ifndef TEST_BUILD
int pfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  (void)fi;
  log_msg(LOG_DEBUG, "pfs_create: path='%s', mode=%o", path, mode);
  char parent_path[256];
  char new_file_name[256];
  char *last_slash = strrchr(path, '/');
  if (last_slash == NULL || last_slash == path) {
    strcpy(parent_path, "/");
  } else {
    strncpy(parent_path, path, last_slash - path);
    parent_path[last_slash - path] = '\0';
  }
  strcpy(new_file_name, last_slash + 1);
  uint32_t parent_id = get_node_from_path(&file_system, parent_path, true);
  if (parent_id == NULL_NODE_ID) {
    return -ENOENT;
  }
  if (create_file(&file_system, new_file_name, parent_id, NULL, 0) != 0) {
    return -EIO;
  }
  return 0;
}
int pfs_open(const char *path, struct fuse_file_info *fi) {
  log_msg(LOG_DEBUG, "pfs_open: path='%s'", path);
  uint32_t node_id = get_node_from_path(&file_system, path, true);
  if (node_id == NULL_NODE_ID) {
    return -ENOENT;
  }
  fi->direct_io = 1;
  fi->fh = node_id;
  return 0;
}
int pfs_fallocate(const char *path, int mode, off_t offset, off_t length,
                  struct fuse_file_info *fi) {
  (void)path;
  (void)mode;
  (void)offset;
  (void)length;
  (void)fi;
  return 0;
}

int pfs_flush(const char *path, struct fuse_file_info *fi) {
  (void)path;
  (void)fi;
  return 0;
}

static void *pfs_init(struct fuse_conn_info *conn) {
  (void)conn;
  return NULL;
}

static void pfs_destroy(void *private_data) { (void)private_data; }

static struct fuse_operations pfs_oper = {
    .getattr = pfs_getattr,
    .readlink = pfs_readlink,
    .mknod = pfs_mknod,
    .mkdir = pfs_mkdir,
    .unlink = pfs_unlink,
    .rmdir = pfs_rmdir,
    .symlink = pfs_symlink,
    .rename = NULL,
    .link = NULL,
    .chmod = NULL,
    .chown = NULL,
    .truncate = NULL,
    .utimens = pfs_utimens,
    .open = pfs_open,
    .read = pfs_read,
    .write = pfs_write,
    .statfs = NULL,
    .flush = pfs_flush,
    .release = NULL,
    .fsync = NULL,
    .setxattr = NULL,
    .getxattr = NULL,
    .listxattr = NULL,
    .removexattr = NULL,
    .opendir = NULL,
    .readdir = pfs_readdir,
    .releasedir = NULL,
    .fsyncdir = NULL,
    .init = pfs_init,
    .destroy = pfs_destroy,
    .access = NULL,
    .create = pfs_create,
    .lock = NULL,
    .bmap = NULL,
    .ioctl = NULL,
    .poll = NULL,
    .write_buf = NULL,
    .read_buf = NULL,
    .flock = NULL,
    .fallocate = pfs_fallocate,
};

int main(int argc, char *argv[]) {
  struct fuse_args args = {0};
  char *temp_mountpoint = NULL; 
  const char *disk_image_path = "disk.img";
  int res;
  
  char **new_argv = malloc(sizeof(char *) * argc);
  int new_argc = 0;
  new_argv[new_argc++] = argv[0];

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--log-level") == 0) {
      if (i + 1 < argc) {
        set_log_level(log_level_from_str(argv[i + 1]));
        i++;
      } else {
        fprintf(stderr, "Missing log level\n");
        free(new_argv);
        return 1;
      }
    } else if (strcmp(argv[i], "--disk-image") == 0) {
      if (i + 1 < argc) {
        disk_image_path = argv[i + 1];
        i++;
      } else {
        fprintf(stderr, "Missing disk image path\n");
        free(new_argv);
        return 1;
      }
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [FUSE options] [--log-level <level>] [--disk-image <path>]\n", argv[0]);
      printf("Log levels: INFO, WARN, ERROR, DEBUG\n");
      new_argv[new_argc++] = argv[i];
    } else {
      new_argv[new_argc++] = argv[i];
    }
  }

  args.argc = new_argc;
  args.argv = new_argv;
  args.allocated = 0;

  res = fuse_parse_cmdline(&args, &temp_mountpoint, NULL, NULL);
  if (res == -1) {
    free(new_argv);
    fuse_opt_free_args(&args);
    return 1;
  }
  mount_point = temp_mountpoint; 

  g_ch = fuse_mount(mount_point, &args);
  if (!g_ch) {
    free(new_argv);
    free(mount_point);
    fuse_opt_free_args(&args);
    return 1;
  }

  g_fuse = fuse_new(g_ch, &args, &pfs_oper, sizeof(pfs_oper), NULL);
  if (!g_fuse) {
    free(new_argv);
    fuse_unmount(mount_point, g_ch);
    free(mount_point);
    fuse_opt_free_args(&args);
    return 1;
  }

  if (fs_load(&file_system, disk_image_path) != 0) {
    log_msg(LOG_WARN,
            "main: Failed to load %s. Initializing a new file system.", disk_image_path);
    fs_free(&file_system);
    if (fs_init(&file_system, 1000) != 0) {
      log_msg(LOG_ERROR, "main: Failed to initialize new file system.");
      fuse_destroy(g_fuse);
      fuse_unmount(mount_point, g_ch);
      free(mount_point);
      free(new_argv);
      fuse_opt_free_args(&args);
      return 1;
    }
  }

  signal(SIGINT, unmount_handler);
  signal(SIGTERM, unmount_handler);
  signal(SIGABRT, unmount_handler);
  signal(SIGSEGV, unmount_handler);

  log_msg(LOG_INFO, "main: FUSE file system initialized/loaded. Mounting at %s", mount_point);
  res = fuse_loop(g_fuse);

  fuse_unmount(mount_point, g_ch);
  fuse_destroy(g_fuse);
  free(mount_point);
  free(new_argv);
  fuse_opt_free_args(&args);

  return res;
}
#endif

