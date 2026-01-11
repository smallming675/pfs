#include "dir.h"
#include "fs.h"
#include "logger.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

file_path file_path_split(const char *path) {
  file_path fp = {NULL, 0};
  if (!path)
    return fp;

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
      fp.parts[fp.count++] = strdup(buf);
      buf_len = 0;
    } else {
      buf[buf_len++] = path[i];
    }
  }
  buf[buf_len] = '\0';
  fp.parts = realloc(fp.parts, (fp.count + 2) * sizeof(char *));
  fp.parts[fp.count++] = strdup(buf);
  fp.parts[fp.count] = NULL;

  free(buf);
  log_msg(LOG_DEBUG, "file_path_split: Split path '%s' into %zu parts.", path,
          fp.count);
  return fp;
}

void file_path_free(file_path *fp) {
  if (!fp || !fp->parts)
    return;
  for (size_t i = 0; i < fp->count; i++)
    free(fp->parts[i]);
  free(fp->parts);
  fp->parts = NULL;
  fp->count = 0;
  log_msg(LOG_DEBUG, "file_path_free: Freed file_path structure.");
}

char *file_path_join(const file_path *fp) {
  if (!fp || fp->count == 0)
    return NULL;
  size_t total = 1;
  for (size_t i = 0; i < fp->count; i++)
    total += strlen(fp->parts[i]) + 1;
  char *out = malloc(total);
  out[0] = '\0';
  for (size_t i = 0; i < fp->count; i++) {
    strcat(out, fp->parts[i]);
    if (i + 1 < fp->count)
      strcat(out, "/");
  }
  log_msg(LOG_DEBUG, "file_path_join: Joined %zu parts into path '%s'.",
          fp->count, out);
  return out;
}

bool is_valid_dir(const fs *fs, const char *dir_name, uint32_t dir_node_id) {
  log_msg(LOG_INFO,
          "is_valid_dir: Checking if '%s' is a valid directory under node %u.",
          dir_name, dir_node_id);
  uint32_t id = find_dir_node(fs, dir_name, dir_node_id);
  if (id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "is_valid_dir: Directory '%s' not found under node %u.",
            dir_name, dir_node_id);
    return false;
  }
  if (fs->table[id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "is_valid_dir: Node %u for '%s' is not a directory.", id,
            dir_name);
    return false;
  }
  log_msg(LOG_INFO, "is_valid_dir: Directory '%s' resolved to node %u.",
          dir_name, id);
  return true;
}

bool is_valid_path(const fs *fs, const char *name, uint32_t dir_node_id) {
  uint32_t id = find_dir_node(fs, name, dir_node_id);
  log_msg(LOG_DEBUG, "is_valid_path: Validating path '%s' under node %u: %s",
          name, dir_node_id, id == NULL_NODE_ID ? "NOT FOUND" : "FOUND");
  return id != NULL_NODE_ID;
}

bool has_name_conflict(const fs *fs, uint32_t dir_node_id, const char *name) {
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR,
            "has_name_conflict: Node %u is not a directory, cannot check for "
            "conflicts.",
            dir_node_id);
    return true;
  }

  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (uint32_t i = 0; i < count; i++) {
    uint32_t id = fs->table[dir_node_id].data.dir_entry.entries[i];
    if (id == NULL_NODE_ID)
      continue;

    if (fs->table[id].status == NODE_DIR_ENTRY &&
        strcmp(fs->table[id].data.dir_entry.dir_name, name) == 0) {
      log_msg(
          LOG_DEBUG,
          "has_name_conflict: Conflict: directory '%s' already exists in %u.",
          name, dir_node_id);
      return true;
    }
    if ((fs->table[id].status == NODE_SINGLE_NODE_FILE ||
         fs->table[id].status == NODE_FILE_START) &&
        strcmp(fs->table[id].data.header_file.file_name, name) == 0) {
      log_msg(LOG_DEBUG,
              "has_name_conflict: Conflict: file '%s' already exists in %u.",
              name, dir_node_id);
      return true;
    }
  }
  return false;
}

int create_file_at_dir(fs *fs, uint32_t dir_node_id, const char *file_name,
                       const uint8_t *data, uint64_t size) {
  log_msg(LOG_INFO, "create_file_at_dir: Creating file '%s' in directory %u.",
          file_name, dir_node_id);

  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "create_file_at_dir: Node %u is not a directory.",
            dir_node_id);
    return NULL_NODE_ID;
  }

  if (has_name_conflict(fs, dir_node_id, file_name)) {
    log_msg(LOG_ERROR,
            "create_file_at_dir: Cannot create file '%s': name conflict in "
            "directory %u.",
            file_name, dir_node_id);
    return NULL_NODE_ID;
  }

  uint32_t node_id = fs_allocate_node(fs);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "create_file_at_dir: No free node available to create file '%s'.",
            file_name);
    return NULL_NODE_ID;
  }
  int ok = write_file(fs, file_name, dir_node_id, data, size);
  if (!ok) {
    log_msg(
        LOG_ERROR,
        "create_file_at_dir: Failed to initialize file '%s' in directory %u.",
        file_name, dir_node_id);
    return NULL_NODE_ID;
  }
  if (insert_file_to_dir(fs, dir_node_id, node_id)) {
    log_msg(
        LOG_ERROR,
        "create_file_at_dir: Failed to insert file node %u into directory %u.",
        node_id, dir_node_id);
    return NULL_NODE_ID;
  }

  log_msg(LOG_INFO,
          "create_file_at_dir: File '%s' created as node %u in directory %u.",
          file_name, node_id, dir_node_id);
  log_msg(LOG_DEBUG, "create_file_at_dir: Directory %u now has %u entries.",
          dir_node_id, fs->table[dir_node_id].data.dir_entry.entry_count);

  return node_id;
}

int insert_file_to_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO,
          "insert_file_to_dir: Inserting node %u into directory %u...",
          file_node_id, dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "insert_file_to_dir: Node %u is not a directory.",
            dir_node_id);
    return 1;
  }

  const char *new_name = NULL;
  if (fs->table[file_node_id].status == NODE_DIR_ENTRY) {
    new_name = fs->table[file_node_id].data.dir_entry.dir_name;
  } else if (fs->table[file_node_id].status == NODE_SINGLE_NODE_FILE ||
             fs->table[file_node_id].status == NODE_FILE_START) {
    new_name = fs->table[file_node_id].data.header_file.file_name;
  }

  if (new_name && has_name_conflict(fs, dir_node_id, new_name)) {
    log_msg(LOG_ERROR,
            "insert_file_to_dir: Cannot insert node %u: name '%s' already "
            "exists in directory %u.",
            file_node_id, new_name, dir_node_id);
    return 1;
  }

  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  fs->table[dir_node_id].data.dir_entry.entries[count] = file_node_id;
  fs->table[dir_node_id].data.dir_entry.entry_count++;
  fs->table[dir_node_id].st.st_mtime = time(NULL);
  fs->table[dir_node_id].st.st_ctime = time(NULL);
  log_msg(LOG_INFO, "insert_file_to_dir: Inserted node %u into directory %u.",
          file_node_id, dir_node_id);
  log_msg(LOG_DEBUG, "insert_file_to_dir: Directory %u now has %u entries.",
          dir_node_id, fs->table[dir_node_id].data.dir_entry.entry_count);
  return 0;
}

int remove_file_from_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO, "remove_file_from_dir: Removing node %u from directory %u.",
          file_node_id, dir_node_id);
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "remove_file_from_dir: Node %u is not a directory.",
            dir_node_id);
    return 1;
  }

  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  for (uint32_t i = 0; i < count; i++) {
    if (fs->table[dir_node_id].data.dir_entry.entries[i] == file_node_id) {
      fs->table[dir_node_id].data.dir_entry.entries[i] = NULL_NODE_ID;
      for (uint32_t j = i; j < count - 1; ++j) {
        fs->table[dir_node_id].data.dir_entry.entries[j] =
            fs->table[dir_node_id].data.dir_entry.entries[j + 1];
      }
      fs->table[dir_node_id].data.dir_entry.entries[count - 1] = NULL_NODE_ID;
      fs->table[dir_node_id].data.dir_entry.entry_count--;
      fs->table[dir_node_id].st.st_mtime = time(NULL);
      fs->table[dir_node_id].st.st_ctime = time(NULL);
      log_msg(LOG_INFO,
              "remove_file_from_dir: Node %u removed from directory %u.",
              file_node_id, dir_node_id);
      return 1;
    }
  }

  log_msg(LOG_ERROR, "remove_file_from_dir: Node %u not found in directory %u.",
          file_node_id, dir_node_id);
  return 0;
}

int create_dir(fs *fs, uint32_t parent_id, const char *name) {
  log_msg(LOG_INFO, "create_dir: Creating directory '%s' under parent %u.",
          name, parent_id);
  if (fs->table[parent_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "create_dir: Parent node %u is not a directory.",
            parent_id);
    return NULL_NODE_ID;
  }

  uint32_t count = fs->table[parent_id].data.dir_entry.entry_count;
  if (has_name_conflict(fs, parent_id, name)) {
    log_msg(LOG_ERROR,
            "create_dir: Cannot create subdir '%s': already exists in "
            "directory %i.",
            name, parent_id);
    return 1;
  }

  uint32_t node_id = fs_allocate_node(fs);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "create_dir: No free node available to create directory '%s'.",
            name);
    return NULL_NODE_ID;
  }

  fs->table[node_id].status = NODE_DIR_ENTRY;
  fs->table[node_id].data.dir_entry.entry_count = 0;
  strncpy(fs->table[node_id].data.dir_entry.dir_name, name, FILE_NAME_SIZE - 1);

  fs->table[node_id].st.st_mode = S_IFDIR | 0755; // rwx-rx-rx
  fs->table[node_id].st.st_nlink = 2;
  fs->table[node_id].st.st_uid = getuid();
  fs->table[node_id].st.st_gid = getgid();
  fs->table[node_id].st.st_atime = time(NULL);
  fs->table[node_id].st.st_mtime = time(NULL);
  fs->table[node_id].st.st_ctime = time(NULL);
  fs->table[node_id].st.st_size = 0;

  fs->table[parent_id].data.dir_entry.entries[count] = node_id;
  fs->table[parent_id].data.dir_entry.entry_count++;
  fs->table[parent_id].st.st_nlink++;
  fs->table[parent_id].st.st_mtime = time(NULL);
  fs->table[parent_id].st.st_ctime = time(NULL);

  log_msg(LOG_INFO,
          "create_dir: Directory '%s' created as node %u under parent %u.",
          name, node_id, parent_id);
  log_msg(LOG_DEBUG, "create_dir: Parent %u now has %u entries.", parent_id,
          fs->table[parent_id].data.dir_entry.entry_count);
  return node_id;
}

int delete_directory(fs *fs, const char *name, uint32_t parent_dir_node_id) {
  log_msg(LOG_INFO, "delete_directory: Deleting directory '%s' from parent %u.",
          name, parent_dir_node_id);

  uint32_t dir_to_delete_id = find_dir_node(fs, name, parent_dir_node_id);
  if (dir_to_delete_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "delete_directory: Directory '%s' not found under parent %u.", name,
            parent_dir_node_id);
    return 0; 
  }

  if (fs->table[dir_to_delete_id].data.dir_entry.entry_count > 0) {
    log_msg(LOG_ERROR, "delete_directory: Directory '%s' is not empty.", name);
    return 0;
  }

  if (remove_file_from_dir(fs, parent_dir_node_id, dir_to_delete_id) == 0) {
    log_msg(LOG_ERROR,
            "delete_directory: Failed to remove directory entry from parent.");
    return 0;
  }

  fs_deallocate_node(fs, dir_to_delete_id);
  memset(&fs->table[dir_to_delete_id], 0,
         sizeof(fs_node)); 
  log_msg(LOG_INFO, "delete_directory: Deallocated node %u for directory '%s'.",
          dir_to_delete_id, name);

  fs->table[parent_dir_node_id].st.st_nlink--;
  fs->table[parent_dir_node_id].st.st_mtime = time(NULL);
  fs->table[parent_dir_node_id].st.st_ctime = time(NULL);

  log_msg(LOG_INFO, "delete_directory: Successfully deleted directory '%s'.",
          name);
  return 1;
}

int write_from_path(fs *fs, const char *path, const uint8_t *data,
                    uint64_t size) {
  log_msg(LOG_INFO, "write_from_path: Writing to path '%s' (%llu bytes).", path,
          (unsigned long long)size);
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR, "write_from_path: Invalid path '%s'.", path);
    free_resolved_path(&rp);
    return 0;
  }
  int ok = write_file(fs, rp.filename, rp.dir_id, data, size);
  log_msg(ok ? LOG_INFO : LOG_ERROR, "write_from_path: Write %s for '%s'.",
          ok ? "succeeded" : "failed", path);
  free_resolved_path(&rp);
  return ok;
}

uint8_t *read_from_path(fs *fs, const char *path, int meta_only,
                        uint64_t *out_size) {
  log_msg(LOG_INFO, "read_from_path: Reading from path '%s'.", path);
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR, "read_from_path: Invalid path '%s'.", path);
    free_resolved_path(&rp);
    return NULL;
  }

  uint8_t *buf = read_file(fs, rp.filename, rp.dir_id, meta_only, out_size);
  if (!buf) {
    log_msg(LOG_ERROR,
            "read_from_path: Failed to read file '%s' in directory %u.",
            rp.filename, rp.dir_id);
  } else {
    log_msg(LOG_INFO, "read_from_path: Read %llu bytes from '%s'.",
            (unsigned long long)*out_size, path);
  }
  free_resolved_path(&rp);
  return buf;
}

int delete_from_path(fs *fs, const char *path) {
  log_msg(LOG_INFO, "delete_from_path: Deleting path '%s'.", path);
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR, "delete_from_path: Invalid path '%s'.", path);
    free_resolved_path(&rp);
    return 0;
  }

  uint32_t target_node_id =
      find_file_node(fs, rp.filename, rp.dir_id); 
  bool is_dir = false;
  if (target_node_id ==
      NULL_NODE_ID) { 
    target_node_id = find_dir_node(fs, rp.filename, rp.dir_id);
    if (target_node_id != NULL_NODE_ID) {
      is_dir = true;
    }
  }

  if (target_node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "delete_from_path: Node '%s' not found under parent %u.",
            rp.filename, rp.dir_id);
    free_resolved_path(&rp);
    return 0;
  }

  int ok;
  if (is_dir) {
    ok = delete_directory(fs, rp.filename, rp.dir_id);
  } else {
    ok = delete_file(fs, rp.filename, rp.dir_id);
  }

  log_msg(ok ? LOG_INFO : LOG_ERROR, "delete_from_path: Delete %s for '%s'.",
          ok ? "succeeded" : "failed", path);
  free_resolved_path(&rp);
  return ok;
}

void free_resolved_path(resolved_path *rp) {
  if (rp && rp->filename) {
    log_msg(LOG_DEBUG, "free_resolved_path: Freeing resolved filename '%s'.",
            rp->filename);
    free(rp->filename);
    rp->filename = NULL;
  }
}

resolved_path resolve_path(fs *fs, const char *path, uint32_t start_dir) {
  log_msg(LOG_INFO, "resolve_path: Resolving path '%s' from start dir %u.",
          path, start_dir);
  resolved_path rp = {NULL_NODE_ID, NULL};
  file_path fp = file_path_split(path);
  if (fp.count == 0) {
    log_msg(LOG_ERROR, "resolve_path: Path '%s' split into zero components.",
            path);
    file_path_free(&fp);
    return rp;
  }

  rp.dir_id = (path[0] == '/') ? 0 : start_dir;

  for (size_t i = 0; i + 1 < fp.count; i++) {
    if (fp.parts[i][0] == '\0')
      continue;
    uint32_t next_id = find_dir_node(fs, fp.parts[i], rp.dir_id);
    if (next_id == NULL_NODE_ID) {
      log_msg(LOG_ERROR,
              "resolve_path: Directory '%s' not found under node %u.",
              fp.parts[i], rp.dir_id);
      file_path_free(&fp);
      rp.dir_id = NULL_NODE_ID;
      return rp;
    }
    log_msg(LOG_DEBUG, "resolve_path: Component '%s' resolved to node %u.",
            fp.parts[i], next_id);
    rp.dir_id = next_id;
  }

  const char *last = fp.parts[fp.count - 1];
  if (last[0] != '\0') {
    rp.filename = strdup(last);
    log_msg(LOG_INFO,
            "resolve_path: Final component '%s' resolved in directory %u.",
            rp.filename, rp.dir_id);
  } else {
    log_msg(LOG_INFO,
            "resolve_path: Path ended with '/', resolved directory id %u.",
            rp.dir_id);
  }

  file_path_free(&fp);
  return rp;
}
