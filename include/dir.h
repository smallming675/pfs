#ifndef DIR_H
#define DIR_H
#include "fs.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  char **parts;
  size_t count;
} file_path;

typedef struct {
  uint32_t dir_id;
  char *filename;
} resolved_path;

bool has_name_conflict(const fs *fs, uint32_t dir_node_id, const char *name);
int create_file_at_dir(fs *fs, uint32_t dir_node_id, const char *file_name,
                       const uint8_t *data, uint64_t size);
bool is_valid_dir(const fs *fs, const char *dir_name, uint32_t dir_node_id);
bool is_valid_path(const fs *fs, const char *name, uint32_t dir_node_id);
void free_resolved_path(resolved_path *rp);
resolved_path resolve_path(const fs *fs, const char *path, uint32_t start_dir);
int create_dir(fs *fs, uint32_t dir_node_id, const char *dir_name);
int remove_file_from_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id);
int insert_node_to_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id);
int write_from_path(fs *fs, const char *file_path, const uint8_t *data,
                    uint64_t size);
uint8_t *read_from_path(const fs *fs, const char *path, bool meta_only,
                        uint64_t *out_size);
int delete_from_path(fs *fs, const char *path);
int delete_dir(fs *fs, const char *name, uint32_t parent_dir_node_id); 
file_path file_path_split(const char *path);
void file_path_free(file_path *fp);
char *file_path_join(const file_path *fp);

#endif
