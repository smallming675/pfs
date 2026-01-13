#include "fs.h"
#include "dir.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

size_t fs_get_file_size(const char *filename) {
  struct stat st;
  if (stat(filename, &st) != 0) {
    log_msg(LOG_ERROR, "fs_get_file_size: Failed to stat file %s: %s", filename,
            strerror(errno));
    return (size_t)-errno;
  }
  return (size_t)st.st_size;
}

uint8_t *fs_read_os_file(const char *filename, size_t *out_bytes) {
  *out_bytes = 0;
  FILE *f = fopen(filename, "rb");
  if (!f) {
    log_msg(LOG_ERROR, "fs_read_os_file: Failed to open file %s: %s", filename,
            strerror(errno));
    return NULL;
  }

  uint8_t *buf = NULL;
  size_t cap = CHUNK_SIZE;
  size_t len = 0;
  buf = (uint8_t *)malloc(cap);
  if (!buf) {
    log_msg(LOG_ERROR,
            "fs_read_os_file: Failed to allocate initial buffer for file %s",
            filename);
    fclose(f);
    return NULL;
  }

  uint8_t chunk[CHUNK_SIZE];
  size_t n;
  while ((n = fread(chunk, 1, CHUNK_SIZE, f)) > 0) {
    if (len + n > cap) {
      size_t new_cap = (len + n) * 2;
      uint8_t *nb = (uint8_t *)realloc(buf, new_cap);
      if (!nb) {
        log_msg(LOG_ERROR,
                "fs_read_os_file: Failed to reallocate buffer for file %s",
                filename);
        free(buf);
        fclose(f);
        return NULL;
      }
      buf = nb;
      cap = new_cap;
    }
    memcpy(buf + len, chunk, n);
    len += n;
  }
  if (ferror(f)) {
    log_msg(LOG_ERROR, "fs_read_os_file: Error reading from file %s: %s",
            filename, strerror(errno));
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *out_bytes = len;
  return buf;
}

int fs_write_os_file(const char *filename, const uint8_t *data, size_t bytes) {
  int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    log_msg(LOG_ERROR, "fs_write_os_file: Failed to open file %s: %s", filename,
            strerror(errno));
    return -errno;
  }
  ssize_t w = write(fd, data, bytes);
  if (w < 0 || (size_t)w != bytes) {
    log_msg(LOG_ERROR, "fs_write_os_file: Failed to write to file %s: %s",
            filename, strerror(errno));
    close(fd);
    return -errno;
  }
  close(fd);
  return 0;
}

static void cleanup_chain(fs *fs, uint32_t start_id) {
  log_msg(LOG_DEBUG, "cleanup_chain: Cleaning up node chain starting at %u...",
          start_id);
  if (!start_id)
    return;
  uint32_t cur = start_id;
  while (cur != NULL_NODE_ID) {
    uint32_t next = fs->table[cur].data.data_file.next_id;
    if (fs->table[cur].status == NODE_FILE_END) {
      fs_deallocate_node(fs, cur);
      log_msg(LOG_DEBUG,
              "cleanup_chain: Deallocated node chain starting at %u.",
              start_id);
      break;
    }
    fs_deallocate_node(fs, cur);
    cur = next;
  }
}

int fs_init(fs *fs, uint32_t nodes) {
  log_msg(LOG_DEBUG, "fs_init: Initializing file system with %u nodes (sizeof(fs_info)=%zu, sizeof(fs_node)=%zu)...",
          nodes, sizeof(fs_info), sizeof(fs_node));
  if (!fs) {
    log_msg(LOG_ERROR, "fs_init: No file system provided");
    errno = EINVAL;
    return -EINVAL;
  }
  // memset(fs, 0, sizeof(*fs));
  if (nodes == 0) {
    log_msg(LOG_ERROR, "fs_init: No nodes provided.");
    errno = EINVAL;
    return -EINVAL;
  }

  fs->table = (fs_node *)calloc(nodes, sizeof(fs_node));
  if (!fs->table) {
    log_msg(LOG_ERROR, "fs_init: Failed to allocate node table: %s",
            strerror(errno));
    return -errno;
  }
  fs->meta.total_node_count = nodes;
  fs->meta.smallest_id_deallocated_node = NULL_NODE_ID;
  fs->meta.largest_id_allocated_node = 0;
  fs->table[0].status = NODE_DIR_ENTRY;
  memset(fs->table[0].data.dir_entry.dir_name, 0, FILE_NAME_SIZE);
  strncpy(fs->table[0].data.dir_entry.dir_name, "root", FILE_NAME_SIZE - 1);
  fs->table[0].st.st_mode = S_IFDIR | 0755;
  fs->table[0].st.st_nlink = 2;
  fs->table[0].st.st_uid = getuid();
  fs->table[0].st.st_gid = getgid();
  fs->table[0].st.st_atime = time(NULL);
  fs->table[0].st.st_mtime = time(NULL);
  fs->table[0].st.st_ctime = time(NULL);
  fs->table[0].st.st_size = 0;
  return 0;
}

int fs_from_image(fs *fs, void *buffer, size_t bytes) {
  log_msg(LOG_INFO,
          "fs_from_image: Recreating file system from a buffer of %zu bytes (sizeof(fs_info)=%zu, sizeof(fs_node)=%zu)...",
          bytes, sizeof(fs_info), sizeof(fs_node));

  if (!fs || !buffer) {
    log_msg(LOG_ERROR, "fs_from_image: Invalid arguments to fs_from_image.");
    errno = EINVAL;
    return -EINVAL;
  }
  if (bytes < sizeof(fs_info)) {
    log_msg(LOG_ERROR, "fs_from_image: Image too small.");
    errno = EINVAL;
    return -EINVAL;
  }

  fs_info *meta = (fs_info *)buffer;
  size_t nodes = meta->total_node_count;
  size_t expected = sizeof(fs_info) + nodes * sizeof(fs_node);
  if (bytes < expected) {
    log_msg(LOG_ERROR,
            "fs_from_image: Corrupt image: expected %zu bytes, got %zu.",
            expected, bytes);
    errno = EILSEQ;
    return -EILSEQ;
  }

  fs->meta = *meta;
  if (fs->table) {
    free(fs->table);
    fs->table = NULL;
  }
  fs->table = (fs_node *)malloc(nodes * sizeof(fs_node));
  if (!fs->table) {
    log_msg(LOG_ERROR, "fs_from_image: Failed to allocate node table: %s",
            strerror(errno));
    return -errno;
  }

  uint8_t *node_base = (uint8_t *)buffer + sizeof(fs_info);
  memcpy(fs->table, node_base, nodes * sizeof(fs_node));

  log_msg(LOG_INFO, "fs_from_image: Filesystem image loaded: %u nodes.",
          (uint32_t)nodes);

  for (uint32_t i = 0; i < nodes; i++) {
    fs_node *n = &fs->table[i];
    switch (n->status) {
    case NODE_DIR_ENTRY:
      log_msg(LOG_DEBUG,
              "fs_from_image: Reconstructed directory node %u ('%s') with %u "
              "entries.",
              i, n->data.dir_entry.dir_name, n->data.dir_entry.entry_count);
      break;
    case NODE_SINGLE_NODE_FILE:
    case NODE_FILE_START:
      log_msg(LOG_DEBUG, "fs_from_image: Reconstructed file node %u ('%s').", i,
              n->data.header_file.file_name);
      break;
    case NODE_FREE:
      break;
    default:
      log_msg(LOG_ERROR, "fs_from_image: Unknown node status %d at index %u.",
              n->status, i);
      break;
    }
  }

  if (fs->table[0].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR,
            "fs_from_image: Invalid filesystem image: root directory missing.");
    errno = EILSEQ;
    return -EILSEQ;
  }
  return 0;
}

int fs_load(fs *fs, const char *image_path) {
  log_msg(LOG_INFO, "fs_load: Loading file system from image: %s", image_path);

  FILE *fp = fopen(image_path, "rb");
  if (!fp) {
    log_msg(LOG_ERROR, "fs_load: Failed to open image file %s: %s", image_path,
            strerror(errno));
    return -errno;
  }

  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (file_size == -1) {
    log_msg(LOG_ERROR, "fs_load: Failed to get file size for %s: %s",
            image_path, strerror(errno));
    fclose(fp);
    return -errno;
  }

  void *buffer = malloc(file_size);
  if (!buffer) {
    log_msg(LOG_ERROR,
            "fs_load: Failed to allocate buffer for image file %s: %s",
            image_path, strerror(errno));
    fclose(fp);
    return -errno;
  }

  if (fread(buffer, 1, file_size, fp) != (size_t)file_size) {
    log_msg(LOG_ERROR, "fs_load: Failed to read entire image file %s: %s",
            image_path, strerror(errno));
    free(buffer);
    fclose(fp);
    return -errno;
  }
  if (ferror(fp)) {
    log_msg(LOG_ERROR, "fs_load: Error after reading image file %s: %s",
            image_path, strerror(errno));
    free(buffer);
    fclose(fp);
    return -errno;
  }

  fclose(fp);

  int result = fs_from_image(fs, buffer, file_size);
  free(buffer);

  if (result != 0) {
    log_msg(LOG_ERROR,
            "fs_load: Failed to initialize file system from image buffer: %s",
            strerror(-result));
    return result;
  }

  log_msg(LOG_INFO, "fs_load: File system successfully loaded from %s.",
          image_path);
  return 0;
}

int fs_symlink(fs *fs, const char *target, const char *newpath) {
  log_msg(LOG_DEBUG, "fs_symlink: target='%s', newpath='%s'", target, newpath);

  char parent_path[256];
  char symlink[256];
  char *last_slash = strrchr(newpath, '/');
  if (last_slash == NULL) {
    strcpy(parent_path, ".");
    strncpy(symlink, newpath, sizeof(symlink) - 1);
    symlink[sizeof(symlink) - 1] = '\0';
  } else if (last_slash == newpath) {
    strcpy(parent_path, "/");
    strncpy(symlink, last_slash + 1, sizeof(symlink) - 1);
    symlink[sizeof(symlink) - 1] = '\0';
  } else {
    strncpy(parent_path, newpath, last_slash - newpath);
    parent_path[last_slash - newpath] = '\0';
    strncpy(symlink, last_slash + 1, sizeof(symlink) - 1);
    symlink[sizeof(symlink) - 1] = '\0';
  }

  uint32_t parent_id = get_node_from_path(fs, parent_path, true);
  if (parent_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "fs_symlink: Parent directory not found: %s",
            parent_path);
    return -ENOENT;
  }

  if (has_name_conflict(fs, parent_id, symlink)) {
    log_msg(LOG_ERROR, "fs_symlink: Name conflict: %s already exists in %s",
            symlink, parent_path);
    return -EEXIST;
  }

  uint32_t symlink_id = fs_allocate_node(fs);
  if (symlink_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "fs_symlink: No free nodes to create symlink.");
    return -ENOSPC;
  }

  fs_node *symlink_node = &fs->table[symlink_id];
  symlink_node->status = NODE_SYMLINK;
  size_t target_len = strlen(target);
  size_t link_name_len = strlen(symlink);

  if (target_len >= FILE_NAME_SIZE || link_name_len >= FILE_NAME_SIZE) {
    log_msg(LOG_ERROR, "fs_symlink: Target or link name is too long.");
    return -ENAMETOOLONG;
  }

  strcpy(symlink_node->data.symlink.target_path, target);
  strcpy(symlink_node->data.symlink.link_name, symlink);
  symlink_node->st.st_mode = S_IFLNK | 0777;
  symlink_node->st.st_nlink = 1;
  symlink_node->st.st_uid = getuid();
  symlink_node->st.st_gid = getgid();
  symlink_node->st.st_atime = time(NULL);
  symlink_node->st.st_mtime = time(NULL);
  symlink_node->st.st_ctime = time(NULL);
  symlink_node->st.st_size = strlen(target);
  if (insert_node_to_dir(fs, parent_id, symlink_id) != 0) {
    log_msg(LOG_ERROR,
            "fs_symlink: Failed to insert symlink node %u into directory %u.",
            symlink_id, parent_id);
    fs_deallocate_node(fs, symlink_id);
    return -EIO;
  }

  log_msg(
      LOG_INFO,
      "fs_symlink: Successfully created symlink '%s' to '%s' (node id: %u).",
      newpath, target, symlink_id);

  return 0;
}

int fs_readlink(fs *fs, const char *path, char *buf, size_t size) {
  uint32_t node_id = get_node_from_path(fs, path, false);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "fs_readlink: Path not found: %s", path);
    return -ENOENT;
  }

  fs_node *node = &fs->table[node_id];
  if (node->status != NODE_SYMLINK) {
    log_msg(LOG_ERROR, "fs_readlink: Not a symbolic link: %s", path);
    return -EINVAL;
  }

  const char *target_path = node->data.symlink.target_path;
  strncpy(buf, target_path, size);
  if (size > 0) {
    buf[size - 1] = '\0';
  }

  log_msg(LOG_INFO, "fs_readlink: Read symlink '%s' target '%s'.", path,
          target_path);
  return 0;
}

int fs_rename(fs *fs, const char *from, const char *to) {
  log_msg(LOG_INFO, "fs_rename: Renaming '%s' to '%s'.", from, to);
  if (!fs || !from || !to) {
    return -EINVAL;
  }

  resolved_path from_rp = resolve_path(fs, from, ROOT);
  if (from_rp.dir_id == NULL_NODE_ID || !from_rp.filename) {
    free_resolved_path(&from_rp);
    return -ENOENT;
  }

  uint32_t from_node_id = find_node(fs, from_rp.filename, from_rp.dir_id, false);
  if (from_node_id == NULL_NODE_ID) {
    free_resolved_path(&from_rp);
    return -ENOENT;
  }

  resolved_path to_rp = resolve_path(fs, to, ROOT);
  if (to_rp.dir_id == NULL_NODE_ID || !to_rp.filename) {
    free_resolved_path(&from_rp);
    free_resolved_path(&to_rp);
    return -ENOENT;
  }

  if (has_name_conflict(fs, to_rp.dir_id, to_rp.filename)) {
    free_resolved_path(&from_rp);
    free_resolved_path(&to_rp);
    return -EEXIST;
  }

  // Update the name in the node itself
  fs_node *node = &fs->table[from_node_id];
  if (node->status == NODE_DIR_ENTRY) {
    strncpy(node->data.dir_entry.dir_name, to_rp.filename, FILE_NAME_SIZE - 1);
    node->data.dir_entry.dir_name[FILE_NAME_SIZE - 1] = '\0';
  } else if (node->status == NODE_SINGLE_NODE_FILE ||
             node->status == NODE_FILE_START) {
    strncpy(node->data.header_file.file_name, to_rp.filename,
            FILE_NAME_SIZE - 1);
    node->data.header_file.file_name[FILE_NAME_SIZE - 1] = '\0';
  } else if (node->status == NODE_SYMLINK) {
    strncpy(node->data.symlink.link_name, to_rp.filename, FILE_NAME_SIZE - 1);
    node->data.symlink.link_name[FILE_NAME_SIZE - 1] = '\0';
  }

  // Move the node to the new directory
  if (from_rp.dir_id != to_rp.dir_id) {
    if (remove_file_from_dir(fs, from_rp.dir_id, from_node_id) != 0) {
      // This should not happen
      free_resolved_path(&from_rp);
      free_resolved_path(&to_rp);
      return -EIO;
    }
    if (insert_node_to_dir(fs, to_rp.dir_id, from_node_id) != 0) {
      // Try to roll back
      insert_node_to_dir(fs, from_rp.dir_id, from_node_id);
      free_resolved_path(&from_rp);
      free_resolved_path(&to_rp);
      return -EIO;
    }
  }

  free_resolved_path(&from_rp);
  free_resolved_path(&to_rp);
  return 0;
}

int fs_truncate(fs *fs, const char *path, off_t size) {
  log_msg(LOG_INFO, "fs_truncate: Truncating '%s' to %zu bytes.", path, size);
  if (!fs || !path) {
    return -EINVAL;
  }

  uint32_t node_id = get_node_from_path(fs, path, true);
  if (node_id == NULL_NODE_ID) {
    return -ENOENT;
  }

  fs_node *node = &fs->table[node_id];
  if (node->status != NODE_SINGLE_NODE_FILE && node->status != NODE_FILE_START) {
    return -EISDIR;
  }

  uint64_t old_size = node->data.header_file.file_size;
  if ((uint64_t)size == old_size) {
    return 0; // No change
  }

  uint8_t *content = read_from_path(fs, path, false, &old_size);
  uint8_t *new_content = realloc(content, size);
  if (size > 0 && !new_content) {
    free(content);
    return -ENOMEM;
  }

  if ((uint64_t)size > old_size) {
    memset(new_content + old_size, 0, size - old_size);
  }

  int res = write_from_path(fs, path, new_content, size);
  free(new_content);
  return res;
}

int fs_chmod(fs *fs, const char *path, mode_t mode) {
    log_msg(LOG_INFO, "fs_chmod: Changing mode of '%s' to %o.", path, mode);
    if (!fs || !path) {
        return -EINVAL;
    }

    uint32_t node_id = get_node_from_path(fs, path, true);
    if (node_id == NULL_NODE_ID) {
        return -ENOENT;
    }

    fs->table[node_id].st.st_mode = mode;
    fs->table[node_id].st.st_ctime = time(NULL);

    return 0;
}

int fs_chown(fs *fs, const char *path, uid_t uid, gid_t gid) {
    log_msg(LOG_INFO, "fs_chown: Changing owner of '%s' to uid=%u, gid=%u.", path, uid, gid);
    if (!fs || !path) {
        return -EINVAL;
    }

    uint32_t node_id = get_node_from_path(fs, path, true);
    if (node_id == NULL_NODE_ID) {
        return -ENOENT;
    }

    fs->table[node_id].st.st_uid = uid;
    fs->table[node_id].st.st_gid = gid;
    fs->table[node_id].st.st_ctime = time(NULL);

    return 0;
}




int fs_to_image(const fs *fs, uint8_t **out_buf, size_t *out_bytes) {
  if (!fs || !out_buf || !out_bytes) {
    log_msg(LOG_ERROR, "fs_to_image: Invalid arguments to fs_to_image.");
    errno = EINVAL;
    return -EINVAL;
  }

  size_t total = sizeof(fs_info) + fs->meta.total_node_count * sizeof(fs_node);
  uint8_t *out = (uint8_t *)malloc(total);
  if (!out) {
    log_msg(LOG_ERROR, "fs_to_image: Failed to allocate output buffer: %s",
            strerror(errno));
    return -errno;
  }

  memcpy(out, &fs->meta, sizeof(fs_info));
  memcpy(out + sizeof(fs_info), fs->table,
         fs->meta.total_node_count * sizeof(fs_node));

  *out_buf = out;
  *out_bytes = total;

  log_msg(LOG_INFO, "fs_to_image: Filesystem serialized to image (%zu bytes, sizeof(fs_info)=%zu, sizeof(fs_node)=%zu).",
          total, sizeof(fs_info), sizeof(fs_node));
  return 0;
}

void fs_free(fs *fs) {
  if (!fs)
    return;
  free(fs->table);
  fs->table = NULL;
  fs->meta.total_node_count = 0;
  memset(&fs->meta, 0, sizeof(fs->meta));
}

uint32_t fs_allocate_node(fs *fs) {
  if (!fs) {
    errno = EINVAL;
    return NULL_NODE_ID;
  }

  if (fs->meta.smallest_id_deallocated_node != NULL_NODE_ID) {
    uint32_t id = fs->meta.smallest_id_deallocated_node;
    fs->table[id].status = NODE_USED;
    /* advance smallest free */
    uint32_t next = NULL_NODE_ID;
    for (uint32_t i = id + 1; i <= fs->meta.largest_id_allocated_node; ++i) {
      if (fs->table[i].status == NODE_FREE) {
        next = i;
        break;
      }
    }
    if (fs->meta.smallest_id_deallocated_node >=
        fs->meta.largest_id_allocated_node) {
      fs->meta.largest_id_allocated_node++;
    }

    fs->meta.smallest_id_deallocated_node = next;
    log_msg(LOG_DEBUG, "fs_allocate_node: Reallocated node %u.", id);
    return id;
  }

  if (fs->meta.largest_id_allocated_node + 1 >= fs->meta.total_node_count) {
    return NULL_NODE_ID;
  }

  uint32_t id = ++fs->meta.largest_id_allocated_node;
  fs->table[id].status = NODE_USED;
  fs->table[id].data.data_file.next_id = NULL_NODE_ID;
  log_msg(LOG_DEBUG, "fs_allocate_node: Allocated node %u.", id);
  return id;
}

void fs_deallocate_node(fs *fs, uint32_t id) {
  if (!fs)
    return;
  if (id >= fs->meta.total_node_count)
    return;
  fs_node *node = &fs->table[id];
  if (node->status == NODE_FREE)
    return;
  node->status = NODE_FREE;

  if (fs->meta.smallest_id_deallocated_node == NULL_NODE_ID ||
      id < fs->meta.smallest_id_deallocated_node) {
    fs->meta.smallest_id_deallocated_node = id;
  }
  if (id == fs->meta.largest_id_allocated_node &&
      fs->meta.largest_id_allocated_node > 0) {
    fs->meta.largest_id_allocated_node--;
  }
  log_msg(LOG_DEBUG, "fs_deallocate_node: Freed node %u.", id);
}

uint32_t find_node(const fs *fs, const char *name, uint32_t dir_node_id,
                   bool follow_symlinks) {
  log_msg(LOG_INFO,
          "find_node: Finding node id of '%s' at directory id %u "
          "(follow_symlinks: %s)...",
          name, dir_node_id, follow_symlinks ? "true" : "false");

  if (!fs || !name) {
    errno = EINVAL;
    return NULL_NODE_ID;
  }
  if (dir_node_id == NULL_NODE_ID ||
      fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    errno = ENOENT;
    return NULL_NODE_ID;
  }

  uint32_t node_id_found = NULL_NODE_ID;
  int count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (int i = 0; i < count; i++) {
    uint32_t id = fs->table[dir_node_id].data.dir_entry.entries[i];
    if (id == NULL_NODE_ID)
      continue;

    fs_node *entry_node = &fs->table[id];
    const char *entry_name = NULL;

    if (entry_node->status == NODE_DIR_ENTRY) {
      entry_name = entry_node->data.dir_entry.dir_name;
    } else if (entry_node->status == NODE_SINGLE_NODE_FILE ||
               entry_node->status == NODE_FILE_START) {
      entry_name = entry_node->data.header_file.file_name;
    } else if (entry_node->status == NODE_SYMLINK) {
      entry_name = entry_node->data.symlink.link_name;
    }

    if (entry_name && strcmp(entry_name, name) == 0) {
      node_id_found = id;
      break;
    }
  }

  if (node_id_found == NULL_NODE_ID) {
    log_msg(LOG_INFO, "find_node: Node '%s' not found at directory id %u.",
            name, dir_node_id);
    errno = ENOENT;
    return NULL_NODE_ID;
  }

  if (follow_symlinks && fs->table[node_id_found].status == NODE_SYMLINK) {
    const char *symlink_target_path =
        fs->table[node_id_found].data.symlink.target_path;
    log_msg(LOG_INFO,
            "find_node: Found symlink '%s' (node id: %u) to '%s'. Resolving "
            "target...",
            name, node_id_found, symlink_target_path);

    uint32_t resolved_target_id =
        get_node_from_path(fs, symlink_target_path, follow_symlinks);
    if (resolved_target_id == NULL_NODE_ID) {
      log_msg(LOG_ERROR,
              "find_node: Symlink target '%s' for symlink '%s' not found.",
              symlink_target_path, name);
      return NULL_NODE_ID;
    }
    log_msg(LOG_INFO, "find_node: Symlink '%s' resolved to node %u.", name,
            resolved_target_id);
    return resolved_target_id;
  }

  log_msg(LOG_INFO, "find_node: Found id %u of '%s' at directory id %u.",
          node_id_found, name, dir_node_id);
  return node_id_found;
}

int create_file(fs *fs, const char *name, uint32_t dir_node_id,
                const uint8_t *data, uint64_t size) {
  if (!fs || !name)
    return 1;
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return 1;

  log_msg(LOG_INFO, "create_file: Creating file '%s'...", name);

  uint32_t head_id = fs_allocate_node(fs);
  if (insert_node_to_dir(fs, dir_node_id, head_id)) {
    log_msg(LOG_ERROR, "create_file: Unable to insert '%s' into directory %u.",
            name, dir_node_id);
    return 1;
  }
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "create_file: No free nodes.");
    return 1;
  }

  fs_node *head = &fs->table[head_id];
  head->status = NODE_SINGLE_NODE_FILE;
  memset(head->data.header_file.file_name, 0, FILE_NAME_SIZE);
  strncpy(head->data.header_file.file_name, name, FILE_NAME_SIZE - 1);
  head->data.header_file.file_size = size;
  head->data.header_file.next_id = NULL_NODE_ID;

  head->st.st_mode = S_IFREG | 0644; // rw-r--r--
  head->st.st_nlink = 1;
  head->st.st_uid = getuid();
  head->st.st_gid = getgid();
  head->st.st_atime = time(NULL);
  head->st.st_mtime = time(NULL);
  head->st.st_ctime = time(NULL);
  head->st.st_size = size;

  if (size <= DATA_BYTES_PER_NODE) {
    if (data && size > 0)
      memcpy(head->data.header_file.data, data, (size_t)size);
    log_msg(
        LOG_INFO,
        "create_file: New file '%s' created at directory id %u, node id %u.",
        name, dir_node_id, head_id);
    return 0;
  }

  head->status = NODE_FILE_START;
  uint64_t bytes_written = 0;
  uint64_t first_chunk =
      (size < DATA_BYTES_PER_NODE) ? size : DATA_BYTES_PER_NODE;
  if (data && first_chunk > 0)
    memcpy(head->data.header_file.data, data, (size_t)first_chunk);
  bytes_written += first_chunk;
  size_t node_count = 1;
  uint32_t cur_id = fs_allocate_node(fs);
  if (cur_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "create_file: No free nodes.");
    return 1;
  }

  head->data.header_file.next_id = cur_id;

  while (bytes_written < size) {
    fs_node *cur = &fs->table[cur_id];
    uint64_t chunk = (size - bytes_written < DATA_BYTES_PER_NODE)
                         ? (size - bytes_written)
                         : DATA_BYTES_PER_NODE;
    if (data && chunk > 0)
      memcpy(cur->data.data_file.data, data + bytes_written, (size_t)chunk);
    bytes_written += chunk;
    node_count++;

    if (bytes_written >= size) {
      cur->status = NODE_FILE_END;
      cur->data.data_file.next_id = NULL_NODE_ID;
      break;
    } else {
      cur->status = NODE_FILE_DATA;
      uint32_t next_id = fs_allocate_node(fs);
      if (next_id == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "create_file: No free node.");
        return 1;
      }
      cur->data.data_file.next_id = next_id;
      cur_id = next_id;
    }
  }

  log_msg(
      LOG_INFO,
      "create_file: New file '%s' created at %u, head: %u, node count: %zu. ",
      name, dir_node_id, head_id, node_count);
  return 0;
}

int write_file(fs *fs, const char *name, uint32_t dir_node_id,
               const uint8_t *data, uint64_t size) {
  if (!fs || !name)
    return 0;
  log_msg(LOG_INFO, "write_file: Writing file '%s'...", name);

  uint32_t head_id = find_node(fs, name, dir_node_id, true);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_INFO, "write_file: File '%s' not found, creating a new file...",
            name);
    return create_file(fs, name, dir_node_id, data, size);
  }

  if (!(fs->table[head_id].status == NODE_FILE_START ||
        fs->table[head_id].status == NODE_SINGLE_NODE_FILE)) {
    log_msg(LOG_ERROR,
            "write_file: Non-file node type found with name '%s' at directory "
            "id %u.",
            name, dir_node_id);
    return 0;
  }

  fs_node *head = &fs->table[head_id];
  memset(head->data.header_file.file_name, 0, FILE_NAME_SIZE);
  strncpy(head->data.header_file.file_name, name, FILE_NAME_SIZE - 1);
  size_t original_size = head->data.header_file.file_size;
  head->data.header_file.file_size = size;
  // Update mtime and ctime on write
  head->st.st_mtime = time(NULL);
  head->st.st_ctime = time(NULL);
  head->st.st_size = size;

  uint64_t bytes_written = 0;

  if (size <= DATA_BYTES_PER_NODE) {
    head->status = NODE_SINGLE_NODE_FILE;
    if (data && size > 0)
      memcpy(head->data.header_file.data, data, (size_t)size);
    cleanup_chain(fs, head->data.header_file.next_id);
    head->data.header_file.next_id = NULL_NODE_ID;
    log_msg(LOG_INFO, "write_file: Written %llu bytes to node %u.",
            (unsigned long long)size, head_id);
    return 0;
  }

  if (head->status == NODE_SINGLE_NODE_FILE ||
      head->data.header_file.next_id == NULL_NODE_ID) {

    uint32_t first = fs_allocate_node(fs);
    if (first == NULL_NODE_ID) {
      log_msg(LOG_ERROR, "write_file: No free nodes.");
      return 1;
    }

    head->data.header_file.next_id = first;
    fs->table[first].status = NODE_FILE_END;
  }

  head->status = NODE_FILE_START;
  uint64_t first_chunk =
      (size < DATA_BYTES_PER_NODE) ? size : DATA_BYTES_PER_NODE;
  if (data && first_chunk > 0)
    memcpy(head->data.header_file.data, data, (size_t)first_chunk);
  bytes_written += first_chunk;

  uint32_t cur_id = head->data.header_file.next_id;
  size_t node_count = 1;

  while (bytes_written < size) {
    fs_node *cur = &fs->table[cur_id];
    uint64_t chunk = (size - bytes_written < DATA_BYTES_PER_NODE)
                         ? (size - bytes_written)
                         : DATA_BYTES_PER_NODE;
    if (data && chunk > 0)
      memcpy(cur->data.data_file.data, data + bytes_written, (size_t)chunk);

    log_msg(LOG_INFO, "write_file: Written chunk with size %llu into node %u.",
            (unsigned long long)chunk, cur_id);
    bytes_written += chunk;
    node_count++;

    if (bytes_written >= size) {
      cur->status = NODE_FILE_END;
      if (original_size - size >= DATA_BYTES_PER_NODE) {
        cleanup_chain(fs, cur->data.data_file.next_id);
      }
      cur->data.data_file.next_id = NULL_NODE_ID;
      break;
    }

    if (cur->status == NODE_FILE_END) {
      uint32_t next = fs_allocate_node(fs);
      if (next == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "write_file: No free nodes.");
        return 1;
      }
      cur->data.data_file.next_id = next;
      cur->status = NODE_FILE_DATA;
      fs->table[next].status = NODE_FILE_END;
    }
    cur_id = cur->data.data_file.next_id;
  }

  log_msg(
      LOG_INFO,
      "write_file: Written %llu bytes starting at node %u, node count: %zu.",
      (unsigned long long)size, head_id, node_count);
  return 0;
}

uint8_t *read_file(const fs *fs, const char *name, uint32_t dir_node_id,
                   bool meta_only, uint64_t *out_size) {
  log_msg(LOG_INFO, "read_file: Reading '%s' at directory id %u...", name,
          dir_node_id);
  if (out_size)
    *out_size = 0;
  if (!fs || !name)
    return NULL;

  uint32_t head_id = find_node(fs, name, dir_node_id, true);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_INFO, "read_file: File '%s' not found.", name);
    return NULL;
  }

  if (!(fs->table[head_id].status == NODE_SINGLE_NODE_FILE ||
        fs->table[head_id].status == NODE_FILE_START)) {
    log_msg(LOG_INFO, "read_file: Non-file node type found with name '%s'.",
            name);
    return NULL;
  }
  const fs_node *node = &fs->table[head_id];
  uint64_t size = node->data.header_file.file_size;
  if (out_size)
    *out_size = size;

  uint8_t *buf = NULL;
  if (!meta_only) {
    buf = (uint8_t *)malloc((size_t)size);
    if (!buf && size > 0)
      return NULL;
  }

  uint64_t bytes_read = 0;
  uint64_t chunk = (size < DATA_BYTES_PER_NODE) ? size : DATA_BYTES_PER_NODE;
  if (!meta_only && chunk > 0)
    memcpy(buf, node->data.header_file.data, (size_t)chunk);
  bytes_read += chunk;

  if (node->status == NODE_SINGLE_NODE_FILE || bytes_read >= size) {
    if (meta_only) {
      log_msg(LOG_INFO, "read_file: File size: %llu, node count: 1.",
              (unsigned long long)size);
      return NULL;
    }
    return buf;
  }

  uint32_t cur = node->data.header_file.next_id;
  size_t node_count = 1;
  while (cur != NULL_NODE_ID && bytes_read < size) {
    const fs_node *d = &fs->table[cur];
    uint64_t chunk2 = (size - bytes_read < DATA_BYTES_PER_NODE)
                          ? (size - bytes_read)
                          : DATA_BYTES_PER_NODE;
    if (!meta_only && chunk2 > 0)
      memcpy(buf + bytes_read, d->data.data_file.data, (size_t)chunk2);
    bytes_read += chunk2;
    node_count++;
    if (d->status == NODE_FILE_END || bytes_read >= size)
      break;
    cur = d->data.data_file.next_id;
  }

  if (meta_only) {
    log_msg(LOG_INFO, "read_file: File size: %llu, node count: %zu",
            (unsigned long long)size, node_count);
    return NULL;
  }
  return buf;
}

int delete_file(fs *fs, const char *name, uint32_t dir_node_id) {
  log_msg(LOG_INFO, "delete_file: Deleting file '%s'...", name);
  if (!fs || !name)
    return 1;
  uint32_t head_id = find_node(fs, name, dir_node_id, true);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "delete_file: file '%s' not found at directory id %u.", name,
            dir_node_id);
    return 1;
  }

  remove_file_from_dir(fs, dir_node_id, head_id);
  fs->table[dir_node_id].st.st_mtime = time(NULL);
  fs->table[dir_node_id].st.st_ctime = time(NULL);
  fs_node *head = &fs->table[head_id];
  if (head->status == NODE_SINGLE_NODE_FILE) {
    fs_deallocate_node(fs, head_id);
    log_msg(LOG_INFO, "delete_file: Deleted file '%s', node_count: 1.", name);
    return 0;
  }
  if (head->status == NODE_DIR_ENTRY) {
    fs_deallocate_node(fs, head_id);
    log_msg(LOG_INFO, "delete_file: Deleted directory '%s'", name);
    return 0;
  }

  uint32_t cur = head->data.header_file.next_id;
  fs_deallocate_node(fs, head_id);
  size_t node_count = 1;
  while (cur != NULL_NODE_ID) {
    uint32_t next = fs->table[cur].data.data_file.next_id;
    fs_deallocate_node(fs, cur);
    node_count++;
    cur = next;
  }
  log_msg(LOG_INFO, "delete_file: Deleted file '%s', node_count: %zu.", name,
          node_count);
  return 0;
}

int fs_write_image(const fs *fs, const char *filename) {
  uint8_t *buf = NULL;
  size_t bytes = 0;
  if (fs_to_image(fs, &buf, &bytes))
    return 0;
  int ok = fs_write_os_file(filename, buf, bytes);
  free(buf);
  return ok;
}

int fs_read_image(fs *fs, const char *filename) {
  size_t bytes = 0;
  uint8_t *buf = fs_read_os_file(filename, &bytes);
  if (!buf || bytes == 0) {
    return 1;
  }
  int ok = fs_from_image(fs, buf, bytes);
  free(buf);
  return ok;
}

const fs_info *fs_meta(const fs *fs) { return fs ? &fs->meta : NULL; }
const fs_node *fs_table(const fs *fs) { return fs ? fs->table : NULL; }
size_t fs_table_size(const fs *fs) {
  return fs ? fs->meta.total_node_count : 0;
}

static uint32_t _get_node_from_path(const fs *fs, const char *path,
                                    uint32_t start_dir, uint32_t depth,
                                    bool follow_symlinks);

uint32_t get_node_from_path(const fs *fs, const char *path,
                            bool follow_symlinks) {
  return _get_node_from_path(fs, path, ROOT, 0, follow_symlinks);
}

static uint32_t _get_node_from_path(const fs *fs, const char *path,
                                    uint32_t start_dir, uint32_t depth,
                                    bool follow_symlinks) {
  log_msg(LOG_DEBUG, "get_node_from_path: path='%s', start_dir=%u, depth=%u, follow_symlinks=%d", path, start_dir, depth, follow_symlinks);
  if (strcmp(path, "/") == 0) {
    return ROOT;
  }

  if (strcmp(path, ".") == 0) {
    return start_dir;
  }

  file_path fp = file_path_split(path);
  uint32_t node_id;

  if (path[0] == '/') {
    node_id = ROOT;
  } else {
    node_id = start_dir;
  }

  for (size_t i = 0; i < fp.count; ++i) {


    if (fs->table[node_id].status != NODE_DIR_ENTRY) {
      log_msg(LOG_WARN,
              "get_node_from_path: Path component '%s' is not a directory.",
              fp.parts[i]);
      file_path_free(&fp);
      return NULL_NODE_ID;
    }

    uint32_t next_node_id = find_node(fs, fp.parts[i], node_id, false);
    if (next_node_id == NULL_NODE_ID) {
      log_msg(LOG_WARN, "get_node_from_path: Path component '%s' not found: %s",
              fp.parts[i], strerror(errno));
      file_path_free(&fp);
      return NULL_NODE_ID;
    }
    if (!follow_symlinks && i == fp.count - 1 &&
        fs->table[next_node_id].status == NODE_SYMLINK) {
      file_path_free(&fp);
      log_msg(LOG_DEBUG,
              "get_node_from_path: Returning symlink node %u without following "
              "for path '%s'.",
              next_node_id, path);
      return next_node_id;
    }

    if (fs->table[next_node_id].status == NODE_SYMLINK) {
      if (depth >= MAX_SYMLINK_DEPTH) {
        log_msg(LOG_ERROR,
                "get_node_from_path: Too many symlinks encountered for '%s'.",
                path);
        file_path_free(&fp);
        return NULL_NODE_ID;
      }

      const char *symlink_target =
          fs->table[next_node_id].data.symlink.target_path;
      uint32_t resolved_symlink_target;

      char temp_full_path[FILE_NAME_SIZE * MAX_SYMLINK_DEPTH +
                          MAX_SYMLINK_DEPTH]; 
      temp_full_path[0] = '\0';

      if (symlink_target[0] == '/') {
        strncpy(temp_full_path, symlink_target, sizeof(temp_full_path) - 1);
        temp_full_path[sizeof(temp_full_path) - 1] = '\0';
      } else {
        strncpy(temp_full_path, symlink_target, sizeof(temp_full_path) - 1);
        temp_full_path[sizeof(temp_full_path) - 1] = '\0';

        for (size_t j = i + 1; j < fp.count; ++j) {
          strncat(temp_full_path, "/",
                  sizeof(temp_full_path) - strlen(temp_full_path) - 1);
          strncat(temp_full_path, fp.parts[j],
                  sizeof(temp_full_path) - strlen(temp_full_path) - 1);
          temp_full_path[sizeof(temp_full_path) - 1] = '\0';
        }
      }
      resolved_symlink_target = _get_node_from_path(fs, temp_full_path, node_id,
                                                    depth + 1, follow_symlinks);
      file_path_free(&fp);
      return resolved_symlink_target;
    }

    node_id = next_node_id;
  }

  file_path_free(&fp);
  log_msg(LOG_DEBUG, "get_node_from_path: Path '%s' resolved to node %u", path,
          node_id);
  return node_id;
}