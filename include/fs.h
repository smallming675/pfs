#ifndef FS_H
#define FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILE_NAME_SIZE 64
#define ROOT 0
#define DATA_BYTES_PER_NODE 1024
#define DIR_ENTRIES_COUNT (DATA_BYTES_PER_NODE + 11) / 4
#define CHUNK_SIZE 4096
#define NULL_NODE_ID 0xFFFFFFFF

typedef enum {
  NODE_FREE = 0,
  NODE_USED = 1,      /* allocated (allocator bookkeeping) */
  NODE_DIR_ENTRY = 2, /* node 0, root directory name */
  NODE_SINGLE_NODE_FILE = 3,
  NODE_FILE_START = 4, /* header node */
  NODE_FILE_DATA = 5,  /* intermediate data node */
  NODE_FILE_END = 6    /* tail data node */
} node_status;

typedef struct {
  char dir_name[FILE_NAME_SIZE];
  uint32_t entry_count;
  uint32_t entries[DIR_ENTRIES_COUNT];
} dir_entry;

typedef struct {
  char file_name[FILE_NAME_SIZE];
  uint64_t file_size;
  uint32_t next_id;
  uint8_t data[DATA_BYTES_PER_NODE];
} header_file;

typedef struct {
  uint32_t next_id;
  uint8_t data[DATA_BYTES_PER_NODE];
} data_file;

typedef union {
  dir_entry dir_entry;
  header_file header_file;
  data_file data_file;
} node_data;

typedef struct {
  node_status status;
  node_data data;
} fs_node;

typedef struct {
  uint32_t total_node_count;
  uint32_t smallest_id_deallocated_node; /* next free in
                                            [1..largest_id_allocated_node], */
  uint32_t largest_id_allocated_node;    /* highest id ever allocated (>= 0) */
} fs_info;

typedef struct {
  fs_info meta;
  fs_node *table;
} fs;

uint32_t hash_str(const char *s);

size_t fs_get_file_size(const char *filename);
uint8_t *fs_read_os_file(const char *filename, size_t *out_bytes);
int fs_write_os_file(const char *filename, const uint8_t *data, size_t bytes);

int fs_init(fs *fs, uint32_t nodes);
int fs_from_image(fs *fs, void *buffer, size_t bytes);
int fs_to_image(const fs *fs, uint8_t **out_buf, size_t *out_bytes);
void fs_free(fs *fs);

uint32_t fs_allocate_node(fs *fs);
void fs_deallocate_node(fs *fs, uint32_t id);

uint32_t find_dir_node(const fs *fs, const char *dir_name,
                       uint32_t dir_node_id);
uint32_t find_file_node(const fs *fs, const char *name, uint32_t dir_node_id);
int create_file(fs *fs, const char *name, uint32_t dir_node_id,
                const uint8_t *data, uint64_t size);
int write_file(fs *fs, const char *name, uint32_t dir_node_id,
               const uint8_t *data, uint64_t size);
uint8_t *read_file(const fs *fs, const char *name, uint32_t dir_node_id,
                   bool meta_only, uint64_t *out_size);
int delete_file(fs *fs, const char *name, uint32_t dir_node_id);

int fs_write_image(const fs *fs, const char *filename);
int fs_read_image(fs *fs, const char *filename);

const fs_info *fs_meta(const fs *fs);
const fs_node *fs_table(const fs *fs);
size_t fs_table_size(const fs *fs);
#endif
