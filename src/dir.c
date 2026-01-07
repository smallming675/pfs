#include "dir.h"
#include "fs.h"
#include "logger.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool is_valid_dir(const fs *fs, const char *dir_name, uint32_t dir_node_id) {
  uint32_t next_id = find_dir_node(fs, dir_name, dir_node_id);
  if (next_id == NULL_NODE_ID || fs->table[next_id].status != NODE_DIR_ENTRY) {
    return false;
  }
  return true;
}

bool is_valid_path(const fs *fs, const char *dir_name, uint32_t dir_node_id) {
  uint32_t next_id = find_dir_node(fs, dir_name, dir_node_id);
  if (next_id == NULL_NODE_ID) {
    return false;
  }
  return true;
}

char *file_path_join(const file_path *fp) {
  if (!fp || fp->count == 0)
    return NULL;
  size_t total = 0;
  for (size_t i = 0; i < fp->count; i++) {
    total += strlen(fp->parts[i]) + 1;
  }
  char *out = malloc(total);
  out[0] = '\0';
  for (size_t i = 0; i < fp->count; i++) {
    strcat(out, fp->parts[i]);
    if (i + 1 < fp->count)
      strcat(out, "/");
  }
  return out;
}

void file_path_free(file_path *fp) {
  if (!fp || !fp->parts)
    return;
  for (size_t i = 0; i < fp->count; i++) {
    free(fp->parts[i]);
  }
  free(fp->parts);
  fp->parts = NULL;
  fp->count = 0;
}

file_path file_path_split(const char *path) {
  file_path fp = {NULL, 0};
  size_t len = strlen(path);
  char *buf = malloc(len + 1);
  size_t buf_len = 0;

  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\' && i + 1 < len && path[i + 1] == '/') {
      buf[buf_len++] = '/';
      i++;
    } else if (path[i] == '/') {
      buf[buf_len] = '\0';
      fp.parts = realloc(fp.parts, (fp.count + 2) * sizeof(char *));
      char *token = malloc(buf_len + 1);
      memcpy(token, buf, buf_len + 1);
      fp.parts[fp.count++] = token;
      buf_len = 0;
    } else {
      buf[buf_len++] = path[i];
    }
  }
  buf[buf_len] = '\0';
  fp.parts = realloc(fp.parts, (fp.count + 2) * sizeof(char *));
  char *token = malloc(buf_len + 1);
  memcpy(token, buf, buf_len + 1);
  fp.parts[fp.count++] = token;
  fp.parts[fp.count] = NULL;

  free(buf);
  return fp;
}

int remove_file_from_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO, "Removing node with id %i from directory %i...",
          file_node_id, dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return 1;
  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (uint32_t i = 0; i < count; i++) {
    if (fs->table[dir_node_id].data.dir_entry.entries[i] == file_node_id) {
      // since any directory cannot contain the root, using 0 is safe here
      fs->table[dir_node_id].data.dir_entry.entries[i] = 0;
      log_msg(LOG_INFO, "Removed node with id %i from directory %i",
              file_node_id);

      fs->table[dir_node_id].data.dir_entry.entry_count--;
      return 1;
    }
  }
  return 0;
}
int insert_file_to_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO, "Inserting node with id %i into directory %i...",
          file_node_id, dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY)
    return 1;
  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  fs->table[dir_node_id].data.dir_entry.entries[count] = file_node_id;
  fs->table[dir_node_id].data.dir_entry.entry_count++;
  return 0;
}

int create_dir(fs *fs, uint32_t dir_node_id, char *dir_name) {
  log_msg(LOG_INFO, "Creating directory '%s'.", dir_name);
  uint32_t node_id = fs_allocate_node(fs);
  fs->table[dir_node_id].status = NODE_DIR_ENTRY;
  fs->table[dir_node_id].data.dir_entry.entry_count = 0;
  strncpy(fs->table[dir_node_id].data.dir_entry.dir_name, dir_name,
          FILE_NAME_SIZE - 1);
  uint32_t top = fs->table[dir_node_id].data.dir_entry.entry_count;
  fs->table[dir_node_id].data.dir_entry.entries[top] = node_id;
  log_msg(LOG_INFO, "Successfully created directory '%s'.", dir_name);
  return node_id;
}

int write_from_path(fs *fs, const char *path, const uint8_t *data,
                    uint64_t size) {
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename)
    return 0;
  int ok = write_file(fs, rp.filename, rp.dir_id, data, size);
  free_resolved_path(&rp);
  return ok;
}

uint8_t *read_from_path(fs *fs, const char *path, int meta_only,
                        uint64_t *out_size) {
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename)
    return NULL;
  uint8_t *buf = read_file(fs, rp.filename, rp.dir_id, meta_only, out_size);
  free_resolved_path(&rp);
  return buf;
}

int delete_from_path(fs *fs, const char *path) {
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename)
    return 0;
  int ok = delete_file(fs, rp.filename, rp.dir_id);
  free_resolved_path(&rp);
  return ok;
}

void free_resolved_path(resolved_path *rp) {
  if (rp && rp->filename) {
    free(rp->filename);
    rp->filename = NULL;
  }
}

resolved_path resolve_path(fs *fs, const char *path, uint32_t start_dir) {
  log_msg(LOG_INFO, "Resolving path '%s'.", path);
  resolved_path rp = {NULL_NODE_ID, NULL};
  file_path fp = file_path_split(path);
  if (fp.count == 0) {
    file_path_free(&fp);
    return rp;
  }

  /* start from given directory (cwd_id) or root if absolute */
  rp.dir_id = (path[0] == '/') ? 0 : start_dir;

  for (size_t i = 0; i + 1 < fp.count; i++) {
    const char *dirname = fp.parts[i];
    if (dirname[0] == '\0') {
      /* skip empty components from leading/trailing slashes */
      continue;
    }
    uint32_t next_id = find_dir_node(fs, dirname, rp.dir_id);
    if (next_id == NULL_NODE_ID) {
      log_msg(LOG_ERROR, "Directory not found: '%s'.", dirname);
      file_path_free(&fp);
      rp.dir_id = NULL_NODE_ID;
      return rp;
    }
    rp.dir_id = next_id;
  }

  const char *last = fp.parts[fp.count - 1];
  if (last[0] != '\0') {
    rp.filename = malloc(strlen(last) + 1);
    strcpy(rp.filename, last);
    log_msg(LOG_INFO, "Found file name '%s', within directory id '%u'.",
            rp.filename, rp.dir_id);
  } else {
    /* path ended with '/', treat as directory */
    rp.filename = NULL;
    log_msg(LOG_INFO, "Resolved directory id '%u'.", rp.dir_id);
  }

  file_path_free(&fp);
  return rp;
}

char **split_path(const char *path) {
  size_t len = strlen(path);
  char **res = NULL;
  size_t count = 0;

  char *buf = malloc(len + 1);
  size_t buf_len = 0;

  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\' && i + 1 < len && path[i + 1] == '/') {
      buf[buf_len++] = '/';
      i++;
    } else if (path[i] == '/') {
      buf[buf_len] = '\0';
      res = realloc(res, (count + 2) * sizeof(char *));
      size_t token_len = buf_len;
      char *token = malloc(token_len + 1);
      memcpy(token, buf, token_len + 1);
      res[count] = token;
      count++;
      buf_len = 0;
    } else {
      buf[buf_len++] = path[i];
    }
  }
  buf[buf_len] = '\0';
  res = realloc(res, (count + 2) * sizeof(char *));
  size_t token_len = buf_len;
  char *token = malloc(token_len + 1);
  memcpy(token, buf, token_len + 1);
  res[count] = token;
  count++;
  res[count] = NULL;

  free(buf);
  return res;
}
