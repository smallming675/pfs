#include "fs.h"
#include "dir.h"
#include "logger.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h> // Include for time functions
#include <unistd.h>

uint32_t hash_str(const char *s) {
  /* Fowler–Noll–Vo hash variant */
  const uint32_t FNV_OFFSET = 2166136261u;
  const uint32_t FNV_PRIME = 16777619u;
  uint32_t h = FNV_OFFSET;
  for (; *s; ++s) {
    h ^= (uint8_t)(*s);
    h *= FNV_PRIME;
  }
  return h;
}

size_t fs_get_file_size(const char *filename) {
  struct stat st;
  if (stat(filename, &st) != 0) {
    perror("stat");
    return (size_t)-1;
  }
  return (size_t)st.st_size;
}

uint8_t *fs_read_os_file(const char *filename, size_t *out_bytes) {
  *out_bytes = 0;
  FILE *f = fopen(filename, "rb");
  if (!f) {
    perror("fopen");
    return NULL;
  }

  uint8_t *buf = NULL;
  size_t cap = CHUNK_SIZE;
  size_t len = 0;
  buf = (uint8_t *)malloc(cap);
  if (!buf) {
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
    perror("fread");
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
    perror("open");
    return 0;
  }
  ssize_t w = write(fd, data, bytes);
  if (w < 0 || (size_t)w != bytes) {
    perror("write");
    close(fd);
    return 0;
  }
  close(fd);
  return 1;
}

static void cleanup_chain(fs *fs, uint32_t start_id) {
  log_msg(LOG_DEBUG, "cleanup_chain: Cleaning up node chain starting at %i...", start_id);
  // nothing can point to 0 (root node)
  if (!start_id)
    return;
  uint32_t cur = start_id;
  while (cur != NULL_NODE_ID) {
    uint32_t next = fs->table[cur].data.data_file.next_id;
    if (fs->table[cur].status == NODE_FILE_END) {
      fs_deallocate_node(fs, cur);
      log_msg(LOG_DEBUG, "cleanup_chain: Deallocated node chain starting at %i.", start_id);
      break;
    }
    fs_deallocate_node(fs, cur);
    cur = next;
  }
}

int fs_init(fs *fs, uint32_t nodes) {
  log_msg(LOG_DEBUG, "fs_init: Initializing file system with %i nodes...", nodes);
  if (!fs)
    return 0;
  memset(fs, 0, sizeof(*fs));
  if (nodes == 0) {
    log_msg(LOG_ERROR, "fs_init: No nodes provided.");
    return 0;
  }
  fs->table = (fs_node *)calloc(nodes, sizeof(fs_node));
  if (!fs->table)
    return 0;

  fs->meta.total_node_count = nodes;
  fs->meta.smallest_id_deallocated_node = NULL_NODE_ID;
  fs->meta.largest_id_allocated_node = 0;

  /* root dir at node 0 */
  fs->table[0].status = NODE_DIR_ENTRY;
  memset(fs->table[0].data.dir_entry.dir_name, 0, FILE_NAME_SIZE);
  strncpy(fs->table[0].data.dir_entry.dir_name, "root", FILE_NAME_SIZE - 1);

  fs->table[0].st.st_mode = S_IFDIR | 0755;
  fs->table[0].st.st_nlink = 2; // For '.' and '..'
  fs->table[0].st.st_uid = getuid();
  fs->table[0].st.st_gid = getgid();
  fs->table[0].st.st_atime = time(NULL);
  fs->table[0].st.st_mtime = time(NULL);
  fs->table[0].st.st_ctime = time(NULL);
  fs->table[0].st.st_size = 0;

  for (uint32_t i = 1; i < nodes; ++i) {
    fs->table[i].status = NODE_FREE;
  }
  return 1;
}

int fs_from_image(fs *fs, void *buffer, size_t bytes) {
  log_msg(LOG_INFO, "fs_from_image: Recreating file system from a buffer of %zu bytes...",
          bytes);

  if (!fs || !buffer) {
    log_msg(LOG_ERROR, "fs_from_image: Invalid arguments to fs_from_image.");
    return 1;
  }
  if (bytes < sizeof(fs_info)) {
    log_msg(LOG_ERROR, "fs_from_image: Image too small.");
    return 1;
  }

  fs_info *meta = (fs_info *)buffer;
  size_t nodes = meta->total_node_count;
  size_t expected = sizeof(fs_info) + nodes * sizeof(fs_node);
  if (bytes < expected) {
    log_msg(LOG_ERROR, "fs_from_image: Corrupt image: expected %zu bytes, got %zu.", expected,
            bytes);
    return 1;
  }

  /* copy metadata */
  fs->meta = *meta;

  /* allocate table if not already allocated */
  if (!fs->table) {
    fs->table = (fs_node *)malloc(nodes * sizeof(fs_node));
    if (!fs->table) {
      log_msg(LOG_ERROR, "fs_from_image: Failed to allocate node table.");
      return 1;
    }
  }

  /* copy node table */
  uint8_t *node_base = (uint8_t *)buffer + sizeof(fs_info);
  memcpy(fs->table, node_base, nodes * sizeof(fs_node));

  log_msg(LOG_INFO, "fs_from_image: Filesystem image loaded: %u nodes.", (uint32_t)nodes);

  /* reconstruct / verify nodes */
  for (uint32_t i = 0; i < nodes; i++) {
    fs_node *n = &fs->table[i];
    switch (n->status) {
    case NODE_DIR_ENTRY:
      log_msg(LOG_DEBUG,
              "fs_from_image: Reconstructed directory node %u ('%s') with %u entries.", i,
              n->data.dir_entry.dir_name, n->data.dir_entry.entry_count);
      break;
    case NODE_SINGLE_NODE_FILE:
    case NODE_FILE_START:
      log_msg(LOG_DEBUG, "fs_from_image: Reconstructed file node %u ('%s').", i,
              n->data.header_file.file_name);
      break;
    case NODE_FREE:
      break;
    default:
      log_msg(LOG_ERROR, "fs_from_image: Unknown node status %d at index %u.", n->status, i);
      break;
    }
  }

  /* sanity check: root directory must exist */
  if (fs->table[0].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "fs_from_image: Invalid filesystem image: root directory missing.");
    return 1;
  }

  log_msg(LOG_INFO, "fs_from_image: Filesystem reconstruction complete.");
  return 0;
}

int fs_to_image(const fs *fs, uint8_t **out_buf, size_t *out_bytes) {
  if (!fs || !out_buf || !out_bytes) {
    log_msg(LOG_ERROR, "fs_to_image: Invalid arguments to fs_to_image.");
    return 1;
  }

  size_t total = sizeof(fs_info) + fs->meta.total_node_count * sizeof(fs_node);
  uint8_t *out = (uint8_t *)malloc(total);
  if (!out) {
    log_msg(LOG_ERROR, "fs_to_image: Failed to allocate output buffer.");
    return 1;
  }

  memcpy(out, &fs->meta, sizeof(fs_info));
  memcpy(out + sizeof(fs_info), fs->table,
         fs->meta.total_node_count * sizeof(fs_node));

  *out_buf = out;
  *out_bytes = total;

  log_msg(LOG_INFO, "fs_to_image: Filesystem serialized to image (%zu bytes).", total);
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
  if (!fs)
    return NULL_NODE_ID;

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
    log_msg(LOG_DEBUG, "fs_allocate_node: Allocated node %i.", next);
    return id;
  }

  if (fs->meta.largest_id_allocated_node + 1 >= fs->meta.total_node_count) {
    return NULL_NODE_ID;
  }

  uint32_t id = ++fs->meta.largest_id_allocated_node;
  fs->table[id].status = NODE_USED;
  fs->table[id].data.data_file.next_id = NULL_NODE_ID;
  log_msg(LOG_DEBUG, "fs_allocate_node: Allocated node %i.", id);
  return id;
}

void fs_deallocate_node(fs *fs, uint32_t id) {
  log_msg(LOG_DEBUG, "fs_deallocate_node: Freeing node %i.", id);
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
  log_msg(LOG_DEBUG, "fs_deallocate_node: Freed node %i.", id);
}

uint32_t find_dir_node(const fs *fs, const char *dir_name,
                       uint32_t dir_node_id) {

  log_msg(LOG_DEBUG, "find_dir_node: Finding node id of '%s' in directory %i...", dir_name,
          dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return NULL_NODE_ID;
  int count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (int i = 0; i < count; i++) {
    uint32_t id = fs->table[dir_node_id].data.dir_entry.entries[i];
    if (id != NULL_NODE_ID && strcmp(fs->table[id].data.dir_entry.dir_name, dir_name) == 0) {
      log_msg(LOG_DEBUG, "find_dir_node: Found node id %i in directory %i.", id, dir_node_id);
      return id;
    };
  }
  return NULL_NODE_ID;
}

uint32_t find_file_node(const fs *fs, const char *name, uint32_t dir_node_id) {
  log_msg(LOG_INFO, "find_file_node: Finding node id of '%s' at directory id %i...", name,
          dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return NULL_NODE_ID;

  int count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (int i = 0; i < count; i++) {
    uint32_t id = fs->table[dir_node_id].data.dir_entry.entries[i];
    if (id != NULL_NODE_ID && strcmp(fs->table[id].data.header_file.file_name, name) == 0) {
      log_msg(LOG_INFO, "find_file_node: Found id %i of '%s' at directory id %i.", id, name,
              dir_node_id);
      return id;
    };
  }
  return NULL_NODE_ID;
}

int create_file(fs *fs, const char *name, uint32_t dir_node_id,
                const uint8_t *data, uint64_t size) {
  if (!fs || !name)
    return 0;
  log_msg(LOG_INFO, "create_file: Creating file '%s'...", name);

  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return 0;

  uint32_t head_id = fs_allocate_node(fs);
  if (insert_file_to_dir(fs, dir_node_id, head_id)) {
    log_msg(LOG_ERROR, "create_file: Unable to insert '%s' into directory %i.", name,
            dir_node_id);
    return 0;
  }
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "create_file: No free nodes.");
    return 0;
  }

  fs_node *head = &fs->table[head_id];
  head->status = NODE_SINGLE_NODE_FILE;
  memset(head->data.header_file.file_name, 0, FILE_NAME_SIZE);
  strncpy(head->data.header_file.file_name, name, FILE_NAME_SIZE - 1);
  head->data.header_file.file_size = size;
  head->data.header_file.next_id = NULL_NODE_ID;

  // Initialize stat for the new file
  head->st.st_mode = S_IFREG | 0644; // Regular file with rw-r--r-- permissions
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
    log_msg(LOG_INFO, "create_file: New file '%s' created at directory id %i, node id %i.",
            name, dir_node_id, head_id);
    return 1;
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
    return 0;
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
        return 0;
      }
      cur->data.data_file.next_id = next_id;
      cur_id = next_id;
    }
  }

  log_msg(LOG_INFO, "create_file: New file '%s' created at %i, head: %zi, node count: %zi. ",
          name, dir_node_id, head_id, node_count);
  return 1;
}

int write_file(fs *fs, const char *name, uint32_t dir_node_id,
               const uint8_t *data, uint64_t size) {
  if (!fs || !name)
    return 0;
  log_msg(LOG_INFO, "write_file: Writing file '%s'...", name);

  uint32_t head_id = find_file_node(fs, name, dir_node_id);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_INFO, "write_file: File '%s' not found, creating a new file...", name);
    return create_file(fs, name, dir_node_id, data, size);
  }

  if (!(fs->table[head_id].status == NODE_FILE_START ||
        fs->table[head_id].status == NODE_SINGLE_NODE_FILE)) {
    log_msg(LOG_ERROR,
            "write_file: Non-file node type found with name '%s' at directory id %i.", name,
            dir_node_id);
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
    log_msg(LOG_INFO, "write_file: Written %llu bytes to node %i.",
            (unsigned long long)size, head_id);
    return 1;
  }

  if (head->status == NODE_SINGLE_NODE_FILE ||
      head->data.header_file.next_id == NULL_NODE_ID) {

    uint32_t first = fs_allocate_node(fs);
    if (first == NULL_NODE_ID) {
      log_msg(LOG_ERROR, "write_file: No free nodes.");
      return 0;
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

    log_msg(LOG_INFO, "write_file: Written chunk with size %llu into node %u.", (unsigned long long)chunk, cur_id);
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
        return 0;
      }
      cur->data.data_file.next_id = next;
      cur->status = NODE_FILE_DATA;
      fs->table[next].status = NODE_FILE_END;
    }
    cur_id = cur->data.data_file.next_id;
  }

  log_msg(LOG_INFO, "write_file: Written %llu bytes starting at node %i, node count: %zu.",
          (unsigned long long)size, head_id, node_count);
  return 1;
}

uint8_t *read_file(const fs *fs, const char *name, uint32_t dir_node_id,
                   bool meta_only, uint64_t *out_size) {
  log_msg(LOG_INFO, "read_file: Reading '%s' at directory id %i...", name, dir_node_id);
  if (out_size)
    *out_size = 0;
  if (!fs || !name)
    return NULL;

  uint32_t head_id = find_file_node(fs, name, dir_node_id);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_INFO, "read_file: File '%s' not found.", name);
    return NULL;
  }

  if (!(fs->table[head_id].status == NODE_SINGLE_NODE_FILE ||
        fs->table[head_id].status == NODE_FILE_START)) {
    log_msg(LOG_INFO, "read_file: Non-file node type found with name '%s'.", name);
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
    return 0;
  uint32_t head_id = find_file_node(fs, name, dir_node_id);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "delete_file: file '%s' not found at directory id '%i'.",
            dir_node_id);
    return 0;
  }

  remove_file_from_dir(fs, dir_node_id, head_id);
  // Update parent directory's modification times
  fs->table[dir_node_id].st.st_mtime = time(NULL);
  fs->table[dir_node_id].st.st_ctime = time(NULL);
  fs_node *head = &fs->table[head_id];
  if (head->status == NODE_SINGLE_NODE_FILE) {
    fs_deallocate_node(fs, head_id);
    log_msg(LOG_INFO, "delete_file: Deleted file '%s', node_count: 1.", name);
    return 1;
  }
  if (head->status == NODE_DIR_ENTRY) {
    fs_deallocate_node(fs, head_id);
    log_msg(LOG_INFO, "delete_file: Deleted directory '%s'", name);
    return 1;
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
  log_msg(LOG_INFO, "delete_file: Deleted file '%s', node_count: %zu.", name, node_count);
  return 1;
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

uint32_t get_node_from_path(const fs *fs, const char *path) {
  log_msg(LOG_DEBUG, "get_node_from_path: Resolving path: %s", path);
  if (strcmp(path, "/") == 0) {
    return ROOT;
  }

  file_path fp = file_path_split(path);
  uint32_t current_node_id = ROOT;

  for (size_t i = 0; i < fp.count; ++i) {
    if (strcmp(fp.parts[i], "") == 0) {
      continue;
    }
            if (fs->table[current_node_id].status != NODE_DIR_ENTRY) {
              log_msg(LOG_WARN, "get_node_from_path: Path component '%s' is not a directory.", fp.parts[i]);
              file_path_free(&fp);
              return NULL_NODE_ID;
            }
            bool found_next_node = false;
    // Iterate through directory entries to find the next path component
    uint32_t entry_count = fs->table[current_node_id].data.dir_entry.entry_count;
    for (uint32_t j = 0; j < entry_count; ++j) {
      uint32_t entry_id = fs->table[current_node_id].data.dir_entry.entries[j];
      if (entry_id == NULL_NODE_ID) continue;

      fs_node *entry_node = &fs->table[entry_id];
      const char *entry_name = NULL;

      if (entry_node->status == NODE_DIR_ENTRY) {
        entry_name = entry_node->data.dir_entry.dir_name;
      } else if (entry_node->status == NODE_SINGLE_NODE_FILE ||
                 entry_node->status == NODE_FILE_START) {
        entry_name = entry_node->data.header_file.file_name;
      }

      if (entry_name && strcmp(entry_name, fp.parts[i]) == 0) {
        current_node_id = entry_id;
        found_next_node = true;
        break;
      }
    }

    if (!found_next_node) {
      log_msg(LOG_WARN, "get_node_from_path: Path component '%s' not found.", fp.parts[i]);
      file_path_free(&fp);
      return NULL_NODE_ID;
    }
  }

  file_path_free(&fp);
  log_msg(LOG_DEBUG, "get_node_from_path: Path '%s' resolved to node %u", path, current_node_id);
  return current_node_id;
}

