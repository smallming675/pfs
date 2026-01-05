#ifndef FS_H
#define FS_H

#include <stdint.h>
#include <stddef.h>

#define FILE_NAME_SIZE 64
#define DATA_BYTES_PER_NODE 1024
#define HASH_TABLE_SIZE 1024
#define CHUNK_SIZE 4096
#define NULL_NODE_ID 0xFFFFFFFFu

typedef enum {
    NODE_FREE = 0,
    NODE_USED = 1,           /* generic allocated (allocator bookkeeping) */
    NODE_DIR_ENTRY = 2,      /* node 0, root directory name */
    NODE_SINGLE_NODE_FILE = 3,
    NODE_FILE_START = 4,     /* header node for multi-node file */
    NODE_FILE_DATA = 5,      /* intermediate data node */
    NODE_FILE_END = 6        /* tail data node */
} NodeStatus;

typedef struct {
    char dir_name[FILE_NAME_SIZE];
} DirEntry;

typedef struct {
    char     file_name[FILE_NAME_SIZE];
    uint64_t file_size;
    uint32_t next_id; /* first data node for multi-node file or NULL_NODE_ID */
    uint8_t  data[DATA_BYTES_PER_NODE];
} HeaderFile;

typedef struct {
    uint32_t next_id;
    uint8_t  data[DATA_BYTES_PER_NODE];
} DataFile;

typedef union {
    DirEntry   dir_entry;
    HeaderFile header_file;
    DataFile   data_file;
} NodeData;

typedef struct {
    NodeStatus status;
    NodeData   data;
} FsNode;

typedef struct {
    uint32_t total_node_count;
    uint32_t smallest_id_deallocated_node; /* next free in [1..largest_id_allocated_node], or NULL_NODE_ID */
    uint32_t largest_id_allocated_node;    /* highest id ever allocated (>= 0) */
    uint32_t file_table[HASH_TABLE_SIZE];  /* head_id + 1 to distinguish 0 as empty */
} FsMeta;

/* Filesystem object */
typedef struct {
    FsMeta  meta;
    FsNode* table;
    size_t  table_count;
} FileSystem;

/* Utilities */
uint32_t hash_str(const char* s);

/* OS helpers */
size_t fs_get_file_size(const char* filename);
uint8_t* fs_read_os_file(const char* filename, size_t* out_bytes);
int fs_write_os_file(const char* filename, const uint8_t* data, size_t bytes);

/* Filesystem constructors/serializers */
int fs_init(FileSystem* fs, uint32_t nodes);
int fs_from_image(FileSystem* fs, void* buffer, size_t bytes);
int fs_to_image(const FileSystem* fs, uint8_t** out_buf, size_t* out_bytes);
void fs_free(FileSystem* fs);

/* Node allocation/deallocation */
uint32_t fs_allocate_node(FileSystem* fs);
void fs_deallocate_node(FileSystem* fs, uint32_t id);

/* File table + operations */
uint32_t fs_find_file_node(const FileSystem* fs, const char* name);
int fs_create_file(FileSystem* fs, const char* name, const uint8_t* data, uint64_t size);
int fs_write_file(FileSystem* fs, const char* name, const uint8_t* data, uint64_t size);
uint8_t* fs_read_file(const FileSystem* fs, const char* name, int meta_only, uint64_t* out_size);
int fs_delete_file(FileSystem* fs, const char* name);

/* Image I/O convenience */
int fs_write_image(const FileSystem* fs, const char* filename);
int fs_read_image(FileSystem* fs, const char* filename);

/* Introspection */
const FsMeta* fs_meta(const FileSystem* fs);
const FsNode* fs_table(const FileSystem* fs);
size_t fs_table_size(const FileSystem* fs);

#endif /* FS_H */

