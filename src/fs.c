#include "fs.h"
#include "logger.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------- Utility ---------- */

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

/* ---------- OS helpers ---------- */

size_t fs_get_file_size(const char *filename) {
  struct stat st;
  if (stat(filename, &st) != 0) {
    perror("stat");
    return (size_t)-1;
  }
#ifdef __APPLE__
  return (size_t)st.st_size;
#else
  return (size_t)st.st_size;
#endif
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

/* ---------- Internal helpers ---------- */

static void cleanup_chain(FileSystem *fs, uint32_t start_id) {
  uint32_t cur = start_id;
  while (cur != NULL_NODE_ID) {
    uint32_t next = fs->table[cur].data.data_file.next_id;
    fs_deallocate_node(fs, cur);
    cur = next;
  }
}

/* ---------- Constructors/serializers ---------- */

int fs_init(FileSystem *fs, uint32_t nodes) {
  if (!fs)
    return 0;
  memset(fs, 0, sizeof(*fs));
  if (nodes == 0) {
    log_msg(LOG_ERROR, "No nodes");
    return 0;
  }
  fs->table = (FsNode *)calloc(nodes, sizeof(FsNode));
  if (!fs->table)
    return 0;
  fs->table_count = nodes;

  fs->meta.total_node_count = nodes;
  fs->meta.smallest_id_deallocated_node = NULL_NODE_ID;
  fs->meta.largest_id_allocated_node = 0;
  memset(fs->meta.file_table, 0, sizeof(fs->meta.file_table));

  /* root dir at node 0 */
  fs->table[0].status = NODE_DIR_ENTRY;
  memset(fs->table[0].data.dir_entry.dir_name, 0, FILE_NAME_SIZE);
  strncpy(fs->table[0].data.dir_entry.dir_name, "root", FILE_NAME_SIZE - 1);

  for (uint32_t i = 1; i < nodes; ++i) {
    fs->table[i].status = NODE_FREE;
  }
  return 1;
}

int fs_from_image(FileSystem *fs, void *buffer, size_t bytes) {
  if (!fs || !buffer)
    return 0;
  if (bytes < sizeof(FsMeta)) {
    log_msg(LOG_ERROR, "Image too small");
    return 0;
  }
  FsMeta *meta = (FsMeta *)buffer;
  size_t nodes = meta->total_node_count;
  size_t expected = sizeof(FsMeta) + nodes * sizeof(FsNode);
  if (bytes < expected) {
    log_msg(LOG_ERROR, "Corrupt image");
    return 0;
  }
  if (!fs_init(fs, (uint32_t)nodes))
    return 0;

  fs->meta = *meta;
  uint8_t *node_base = (uint8_t *)buffer + sizeof(FsMeta);
  memcpy(fs->table, node_base, nodes * sizeof(FsNode));
  return 1;
}

int fs_to_image(const FileSystem *fs, uint8_t **out_buf, size_t *out_bytes) {
  if (!fs || !out_buf || !out_bytes)
    return 0;
  size_t total = sizeof(FsMeta) + fs->table_count * sizeof(FsNode);
  uint8_t *out = (uint8_t *)malloc(total);
  if (!out)
    return 0;

  memcpy(out, &fs->meta, sizeof(FsMeta));
  memcpy(out + sizeof(FsMeta), fs->table, fs->table_count * sizeof(FsNode));
  *out_buf = out;
  *out_bytes = total;
  return 1;
}

void fs_free(FileSystem *fs) {
  if (!fs)
    return;
  free(fs->table);
  fs->table = NULL;
  fs->table_count = 0;
  memset(&fs->meta, 0, sizeof(fs->meta));
}

/* ---------- Allocation ---------- */

uint32_t fs_allocate_node(FileSystem *fs) {
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
    fs->meta.smallest_id_deallocated_node = next;
    return id;
  }
  if (fs->meta.largest_id_allocated_node + 1 >= fs->meta.total_node_count) {
    return NULL_NODE_ID;
  }
  uint32_t id = ++fs->meta.largest_id_allocated_node;
  fs->table[id].status = NODE_USED;
  return id;
}

void fs_deallocate_node(FileSystem *fs, uint32_t id) {
  if (!fs)
    return;
  if (id >= fs->table_count)
    return;
  FsNode *node = &fs->table[id];
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
}

/* ---------- File table ---------- */

uint32_t fs_find_file_node(const FileSystem *fs, const char *name) {
  if (!fs || !name)
    return NULL_NODE_ID;
  uint32_t idx = hash_str(name) % HASH_TABLE_SIZE;
  uint32_t stored = fs->meta.file_table[idx];
  if (stored != 0)
    return stored - 1;
  return NULL_NODE_ID;
}

/* ---------- File operations ---------- */

int fs_create_file(FileSystem *fs, const char *name, const uint8_t *data,
                   uint64_t size) {
  if (!fs || !name)
    return 0;
  log_msg(LOG_INFO, "Attempting to create file: %s", name);

  uint32_t head_id = fs_allocate_node(fs);
  if (head_id == NULL_NODE_ID) {
    printf("Error: No free node.\n");
    return 0;
  }
  uint32_t idx = hash_str(name) % HASH_TABLE_SIZE;
  fs->meta.file_table[idx] = head_id + 1;

  FsNode *head = &fs->table[head_id];
  head->status = NODE_SINGLE_NODE_FILE;
  memset(head->data.header_file.file_name, 0, FILE_NAME_SIZE);
  strncpy(head->data.header_file.file_name, name, FILE_NAME_SIZE - 1);
  head->data.header_file.file_size = size;
  head->data.header_file.next_id = NULL_NODE_ID;

  if (size <= DATA_BYTES_PER_NODE) {
    if (data && size > 0)
      memcpy(head->data.header_file.data, data, (size_t)size);
    printf("New single-node file created.\n");
    return 1;
  }

  head->status = NODE_FILE_START;
  uint64_t bytes_written = 0;
  uint64_t first_chunk =
      (size < DATA_BYTES_PER_NODE) ? size : DATA_BYTES_PER_NODE;
  if (data && first_chunk > 0)
    memcpy(head->data.header_file.data, data, (size_t)first_chunk);
  bytes_written += first_chunk;

  uint32_t cur_id = fs_allocate_node(fs);
  if (cur_id == NULL_NODE_ID) {
    printf("Error: No free node.\n");
    return 0;
  }
  head->data.header_file.next_id = cur_id;

  while (bytes_written < size) {
    FsNode *cur = &fs->table[cur_id];
    uint64_t chunk = (size - bytes_written < DATA_BYTES_PER_NODE)
                         ? (size - bytes_written)
                         : DATA_BYTES_PER_NODE;
    if (data && chunk > 0)
      memcpy(cur->data.data_file.data, data + bytes_written, (size_t)chunk);
    bytes_written += chunk;

    if (bytes_written >= size) {
      cur->status = NODE_FILE_END;
      cur->data.data_file.next_id = NULL_NODE_ID;
      break;
    } else {
      cur->status = NODE_FILE_DATA;
      uint32_t next_id = fs_allocate_node(fs);
      if (next_id == NULL_NODE_ID) {
        printf("Error: No free node.\n");
        return 0;
      }
      cur->data.data_file.next_id = next_id;
      cur_id = next_id;
    }
  }

  printf("New file created with multiple nodes.\n");
  return 1;
}

int fs_write_file(FileSystem *fs, const char *name, const uint8_t *data,
                  uint64_t size) {
  if (!fs || !name)
    return 0;
  log_msg(LOG_INFO, "Attempting to create file: %s", name);

  uint32_t head_id = fs_find_file_node(fs, name);
  if (head_id == NULL_NODE_ID) {
    log_msg(LOG_INFO, "File not found, creating a new file...");
    return fs_create_file(fs, name, data, size);
  }

  FsNode *head = &fs->table[head_id];
  memset(head->data.header_file.file_name, 0, FILE_NAME_SIZE);
  strncpy(head->data.header_file.file_name, name, FILE_NAME_SIZE - 1);
  head->data.header_file.file_size = size;

  uint64_t bytes_written = 0;

  if (size <= DATA_BYTES_PER_NODE) {
    head->status = NODE_SINGLE_NODE_FILE;
    if (data && size > 0)
      memcpy(head->data.header_file.data, data, (size_t)size);
    cleanup_chain(fs, head->data.header_file.next_id);
    head->data.header_file.next_id = NULL_NODE_ID;
    printf("Wrote single-node file.\n");
    return 1;
  }

  if (head->status == NODE_SINGLE_NODE_FILE ||
      head->data.header_file.next_id == NULL_NODE_ID) {
    uint32_t first = fs_allocate_node(fs);
    if (first == NULL_NODE_ID) {
      printf("Error: No free nodes.\n");
      return 0;
    }
    head->data.header_file.next_id = first;
    fs->table[first].status = NODE_FILE_END; /* temporary sentinel */
  }

  head->status = NODE_FILE_START;
  uint64_t first_chunk =
      (size < DATA_BYTES_PER_NODE) ? size : DATA_BYTES_PER_NODE;
  if (data && first_chunk > 0)
    memcpy(head->data.header_file.data, data, (size_t)first_chunk);
  bytes_written += first_chunk;

  uint32_t cur_id = head->data.header_file.next_id;

  while (bytes_written < size) {
    FsNode *cur = &fs->table[cur_id];
    uint64_t chunk = (size - bytes_written < DATA_BYTES_PER_NODE)
                         ? (size - bytes_written)
                         : DATA_BYTES_PER_NODE;
    if (data && chunk > 0)
      memcpy(cur->data.data_file.data, data + bytes_written, (size_t)chunk);
    bytes_written += chunk;

    if (bytes_written >= size) {
      cur->status = NODE_FILE_END;
      cleanup_chain(fs, cur->data.data_file.next_id);
      cur->data.data_file.next_id = NULL_NODE_ID;
      break;
    }

    if (cur->status == NODE_FILE_END) {
      uint32_t next = fs_allocate_node(fs);
      if (next == NULL_NODE_ID) {
        printf("Error: No free nodes.\n");
        return 0;
      }
      cur->data.data_file.next_id = next;
      cur->status = NODE_FILE_DATA;
      fs->table[next].status = NODE_FILE_END;
    }
    cur_id = cur->data.data_file.next_id;
  }

  printf("Data written successfully.\n");
  return 1;
}

uint8_t *fs_read_file(const FileSystem *fs, const char *name, int meta_only,
                      uint64_t *out_size) {
  if (out_size)
    *out_size = 0;
  if (!fs || !name)
    return NULL;

  uint32_t head_id = fs_find_file_node(fs, name);
  if (head_id == NULL_NODE_ID) {
    printf("File not found: %s\n", name);
    return NULL;
  }

  const FsNode *node = &fs->table[head_id];
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
      printf("File size: %llu, node count: 1\n", (unsigned long long)size);
      return NULL;
    }
    return buf;
  }

  uint32_t cur = node->data.header_file.next_id;
  size_t node_count = 1;
  while (cur != NULL_NODE_ID && bytes_read < size) {
    const FsNode *d = &fs->table[cur];
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
    printf("File size: %llu, node count: %zu\n", (unsigned long long)size,
           node_count);
    return NULL;
  }
  return buf;
}

int fs_delete_file(FileSystem *fs, const char *name) {
  if (!fs || !name)
    return 0;
  uint32_t head_id = fs_find_file_node(fs, name);
  if (head_id == NULL_NODE_ID) {
    printf("Error: file not found.\n");
    return 0;
  }

  fs->meta.file_table[hash_str(name) % HASH_TABLE_SIZE] = 0;

  FsNode *head = &fs->table[head_id];
  if (head->status == NODE_SINGLE_NODE_FILE) {
    fs_deallocate_node(fs, head_id);
    printf("Deleted single node file.\n");
    return 1;
  }

  uint32_t cur = head->data.header_file.next_id;
  fs_deallocate_node(fs, head_id);
  while (cur != NULL_NODE_ID) {
    uint32_t next = fs->table[cur].data.data_file.next_id;
    fs_deallocate_node(fs, cur);
    cur = next;
  }
  printf("Deleted file.\n");
  return 1;
}

/* ---------- Image I/O ---------- */

int fs_write_image(const FileSystem *fs, const char *filename) {
  uint8_t *buf = NULL;
  size_t bytes = 0;
  if (!fs_to_image(fs, &buf, &bytes))
    return 0;
  int ok = fs_write_os_file(filename, buf, bytes);
  free(buf);
  return ok;
}

int fs_read_image(FileSystem *fs, const char *filename) {
  size_t bytes = 0;
  uint8_t *buf = fs_read_os_file(filename, &bytes);
  if (!buf || bytes == 0) {
    return 0;
  }
  int ok = fs_from_image(fs, buf, bytes);
  free(buf);
  return ok;
}

/* ---------- Introspection ---------- */

const FsMeta *fs_meta(const FileSystem *fs) { return fs ? &fs->meta : NULL; }
const FsNode *fs_table(const FileSystem *fs) { return fs ? fs->table : NULL; }
size_t fs_table_size(const FileSystem *fs) { return fs ? fs->table_count : 0; }
