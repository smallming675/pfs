#include "dir.h"
#include "fs.h"
#include "logger.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

file_path file_path_split(const char *path) {
    log_msg(LOG_DEBUG, "file_path_split: path='%s'", path);
    file_path fp = {NULL, 0};
    if (!path) {
        errno = EINVAL;
        return fp;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        return fp;
    }

    char *p = strtok(path_copy, "/");
    while (p != NULL) {
        char **new_parts = realloc(fp.parts, (fp.count + 1) * sizeof(char *));
        if (!new_parts) {
            for (size_t i = 0; i < fp.count; i++) {
                free(fp.parts[i]);
            }
            free(fp.parts);
            fp.parts = NULL;
            fp.count = 0;
            break;
        }
        fp.parts = new_parts;
        fp.parts[fp.count] = strdup(p);
        if (!fp.parts[fp.count]) {
            for (size_t i = 0; i < fp.count; i++) {
                free(fp.parts[i]);
            }
            free(fp.parts);
            fp.parts = NULL;
            fp.count = 0;
            break;
        }
        fp.count++;
        p = strtok(NULL, "/");
    }

    free(path_copy);
    log_msg(LOG_DEBUG, "file_path_split: Split path '%s' into %zu parts.", path, fp.count);
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
  if (!fp) {
    errno = EINVAL;
    return NULL;
  }
  if (fp->count == 0) {
    char *empty_str = strdup("");
    if (!empty_str) {
      log_msg(LOG_ERROR, "file_path_join: Failed to allocate empty string: %s",
              strerror(errno));
    }
    return empty_str;
  }

  size_t total_len = 0;
  for (size_t i = 0; i < fp->count; ++i) {
    if (fp->parts[i] == NULL) {
      log_msg(LOG_ERROR, "file_path_join: Encountered NULL part in file_path.");
      errno = EFAULT;
      return NULL;
    }
    total_len += strlen(fp->parts[i]);
    if (i < fp->count - 1)
      total_len++;
  }

  char *path = (char *)malloc(total_len + 1);
  if (!path) {
    log_msg(LOG_ERROR, "file_path_join: Failed to allocate path string: %s",
            strerror(errno));
    return NULL;
  }
  path[0] = '\0';

  for (size_t i = 0; i < fp->count; ++i) {
    strcat(path, fp->parts[i]);
    if (i < fp->count - 1)
      strcat(path, "/");
  }
  return path;
}

bool is_valid_dir(const fs *fs, const char *dir_name, uint32_t dir_node_id) {
  log_msg(LOG_INFO,
          "is_valid_dir: Checking if '%s' is a valid directory under node %u.",
          dir_name, dir_node_id);
  uint32_t id = find_node(fs, dir_name, dir_node_id, true);
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
  uint32_t id = find_node(fs, name, dir_node_id, true);
  log_msg(LOG_DEBUG, "is_valid_path: Validating path '%s' under node %u: %s",
          name, dir_node_id, id == NULL_NODE_ID ? "NOT FOUND" : "FOUND");
  return id != NULL_NODE_ID;
}

bool has_name_conflict(const fs *fs, uint32_t dir_node_id, const char *name) {
  if (!fs || !name) {
    log_msg(LOG_ERROR,
            "has_name_conflict: Invalid arguments: fs or name is NULL.");
    return true;
  }
  if (find_node(fs, name, dir_node_id, false) != NULL_NODE_ID) {
    return true;
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
  if (insert_node_to_dir(fs, dir_node_id, node_id)) {
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

int insert_node_to_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO,
          "insert_node_to_dir: Inserting node %u into directory %u...",
          file_node_id, dir_node_id);
  if (!fs || dir_node_id == NULL_NODE_ID || file_node_id == NULL_NODE_ID) {
    errno = EINVAL;
    return -EINVAL;
  }
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "insert_node_to_dir: Node %u is not a directory.",
            dir_node_id);
    errno = ENOTDIR;
    return -ENOTDIR;
  }

  if (fs->table[dir_node_id].data.dir_entry.entry_count >= DIR_ENTRIES_COUNT) {
    log_msg(LOG_ERROR, "insert_node_to_dir: Directory %u is full.",
            dir_node_id);
    errno = ENOSPC;
    return -ENOSPC;
  }

  uint32_t count = fs->table[dir_node_id].data.dir_entry.entry_count;
  fs->table[dir_node_id].data.dir_entry.entries[count] = file_node_id;
  fs->table[dir_node_id].data.dir_entry.entry_count++;
  fs->table[dir_node_id].st.st_mtime = time(NULL);
  fs->table[dir_node_id].st.st_ctime = time(NULL);
  log_msg(LOG_INFO, "insert_node_to_dir: Inserted node %u into directory %u.",
          file_node_id, dir_node_id);
  log_msg(LOG_DEBUG, "insert_node_to_dir: Directory %u now has %u entries.",
          dir_node_id, fs->table[dir_node_id].data.dir_entry.entry_count);
  return 0;
}

int remove_file_from_dir(fs *fs, uint32_t dir_node_id, uint32_t file_node_id) {
  log_msg(LOG_INFO, "remove_file_from_dir: Removing node %u from directory %u.",
          file_node_id, dir_node_id);
  if (!fs || dir_node_id == NULL_NODE_ID || file_node_id == NULL_NODE_ID) {
    errno = EINVAL;
    return -EINVAL;
  }
  if (fs->table[dir_node_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR, "remove_file_from_dir: Node %u is not a directory.",
            dir_node_id);
    errno = ENOTDIR;
    return -ENOTDIR;
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
      return 0;
    }
  }

  log_msg(LOG_ERROR, "remove_file_from_dir: Node %u not found in directory %u.",
          file_node_id, dir_node_id);
  errno = ENOENT;
  return -ENOENT;
}

int create_dir(fs *fs, uint32_t parent_id, const char *name) {
  log_msg(LOG_INFO, "create_dir: Creating directory '%s' under parent %u.",
          name, parent_id);
  if (!fs || !name) {
    errno = EINVAL;
    return -EINVAL;
  }
  if (parent_id == NULL_NODE_ID ||
      fs->table[parent_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR,
            "create_dir: Parent node %u is not a directory or invalid.",
            parent_id);
    errno = ENOTDIR;
    return -ENOTDIR;
  }

  if (has_name_conflict(fs, parent_id, name)) {
    log_msg(LOG_ERROR,
            "create_dir: Cannot create subdir '%s': already exists in "
            "directory %u.",
            name, parent_id);
    errno = EEXIST;
    return -EEXIST;
  }
  if (fs->table[parent_id].data.dir_entry.entry_count >= DIR_ENTRIES_COUNT) {
    log_msg(LOG_ERROR, "create_dir: Parent directory %u is full.", parent_id);
    errno = ENOSPC;
    return -ENOSPC;
  }

  uint32_t node_id = fs_allocate_node(fs);
  if (node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "create_dir: No free node available to create directory '%s': %s",
            name, strerror(errno));
    return -errno;
  }

  fs->table[node_id].status = NODE_DIR_ENTRY;
  fs->table[node_id].data.dir_entry.entry_count = 0;
  memset(fs->table[node_id].data.dir_entry.dir_name, 0, FILE_NAME_SIZE);
  strncpy(fs->table[node_id].data.dir_entry.dir_name, name, FILE_NAME_SIZE - 1);

  fs->table[node_id].st.st_mode = S_IFDIR | 0755; // rwx-rx-rx
  fs->table[node_id].st.st_nlink = 2;             // . and ..
  fs->table[node_id].st.st_uid = getuid();
  fs->table[node_id].st.st_gid = getgid();
  fs->table[node_id].st.st_atime = time(NULL);
  fs->table[node_id].st.st_mtime = time(NULL);
  fs->table[node_id].st.st_ctime = time(NULL);
  fs->table[node_id].st.st_size = 0;

  int insert_result = insert_node_to_dir(fs, parent_id, node_id);
  if (insert_result != 0) {
    log_msg(
        LOG_ERROR,
        "create_dir: Failed to insert new directory '%s' into parent %u: %s",
        name, parent_id, strerror(-insert_result));
    fs_deallocate_node(fs, node_id);
    return insert_result;
  }

  fs->table[parent_id].st.st_nlink++;
  log_msg(LOG_INFO,
          "create_dir: Directory '%s' created as node %u under parent %u.",
          name, node_id, parent_id);
  log_msg(LOG_DEBUG, "create_dir: Parent %u now has %u entries.", parent_id,
          fs->table[parent_id].data.dir_entry.entry_count);
  return 0;
}

int delete_dir(fs *fs, const char *name, uint32_t parent_dir_node_id) {
  log_msg(LOG_INFO, "delete_directory: Deleting directory '%s' from parent %u.",
          name, parent_dir_node_id);
  if (!fs || !name) {
    errno = EINVAL;
    return -EINVAL;
  }
  if (parent_dir_node_id == NULL_NODE_ID ||
      fs->table[parent_dir_node_id].status != NODE_DIR_ENTRY) {
    errno = ENOTDIR;
    return -ENOTDIR;
  }

  uint32_t dir_to_delete_id = find_node(fs, name, parent_dir_node_id, true);
  if (dir_to_delete_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR,
            "delete_directory: Directory '%s' not found under parent %u.", name,
            parent_dir_node_id);
    return -ENOENT;
  }

  if (fs->table[dir_to_delete_id].status != NODE_DIR_ENTRY) {
    log_msg(LOG_ERROR,
            "delete_directory: Node '%s' (id: %u) is not a directory.", name,
            dir_to_delete_id);
    errno = ENOTDIR;
    return -ENOTDIR;
  }

  if (fs->table[dir_to_delete_id].data.dir_entry.entry_count > 0) {
    log_msg(LOG_ERROR, "delete_directory: Directory '%s' is not empty.", name);
    errno = ENOTEMPTY;
    return -ENOTEMPTY;
  }

  int remove_result =
      remove_file_from_dir(fs, parent_dir_node_id, dir_to_delete_id);
  if (remove_result != 0) {
    log_msg(LOG_ERROR,
            "delete_directory: Failed to remove directory entry '%s' from "
            "parent %u: %s",
            name, parent_dir_node_id, strerror(-remove_result));
    return remove_result;
  }

  fs_deallocate_node(fs, dir_to_delete_id);
  memset(&fs->table[dir_to_delete_id], 0, sizeof(fs_node));
  log_msg(LOG_INFO, "delete_directory: Deallocated node %u for directory '%s'.",
          dir_to_delete_id, name);

  fs->table[parent_dir_node_id].st.st_nlink--;
  fs->table[parent_dir_node_id].st.st_mtime = time(NULL);
  fs->table[parent_dir_node_id].st.st_ctime = time(NULL);

  log_msg(LOG_INFO, "delete_directory: Successfully deleted directory '%s'.",
          name);
  return 0; 
}

int write_from_path(fs *fs, const char *path, const uint8_t *data,
                    uint64_t size) {
  log_msg(LOG_INFO, "write_from_path: Writing to path '%s' (%llu bytes).", path,
          (unsigned long long)size);
  if (!fs || !path) {
    errno = EINVAL;
    return -EINVAL;
  }
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR,
            "write_from_path: Invalid path '%s' or resolution failed: %s", path,
            strerror(errno));
    free_resolved_path(&rp);
    return -errno;
  }

  int result = write_file(fs, rp.filename, rp.dir_id, data, size);
  if (result != 0) {
    log_msg(LOG_ERROR, "write_from_path: Write failed for '%s': %s", path,
            strerror(-result));
  } else {
    log_msg(LOG_INFO, "write_from_path: Write succeeded for '%s'.", path);
  }
  free_resolved_path(&rp);
  return result;
}

uint8_t *read_from_path(const fs *fs, const char *path, bool meta_only,
                        uint64_t *out_size) {
  log_msg(LOG_INFO, "read_from_path: Reading from path '%s'.", path);
  if (!fs || !path) {
    errno = EINVAL;
    return NULL;
  }
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR,
            "read_from_path: Invalid path '%s' or resolution failed: %s", path,
            strerror(errno));
    free_resolved_path(&rp);
    return NULL;
  }

  uint8_t *buf = read_file(fs, rp.filename, rp.dir_id, meta_only, out_size);
  if (!buf) {
    log_msg(LOG_ERROR,
            "read_from_path: Failed to read file '%s' in directory %u: %s",
            rp.filename, rp.dir_id, strerror(errno));
  } else {
    log_msg(LOG_INFO, "read_from_path: Read %llu bytes from '%s'.",
            (unsigned long long)*out_size, path);
  }
  free_resolved_path(&rp);
  return buf;
}

int delete_from_path(fs *fs, const char *path) {
  log_msg(LOG_INFO, "delete_from_path: Deleting path '%s'.", path);
  if (!fs || !path) {
    errno = EINVAL;
    return -EINVAL;
  }
  resolved_path rp = resolve_path(fs, path, ROOT);
  if (rp.dir_id == NULL_NODE_ID || !rp.filename) {
    log_msg(LOG_ERROR,
            "delete_from_path: Invalid path '%s' or resolution failed: %s",
            path, strerror(errno));
    free_resolved_path(&rp);
    return -errno;
  }

  uint32_t target_node_id = find_node(fs, rp.filename, rp.dir_id, false);
  if (target_node_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "delete_from_path: Node '%s' not found under parent %u.",
            rp.filename, rp.dir_id);
    free_resolved_path(&rp);
    return -ENOENT;
  }

  int result;
  if (fs->table[target_node_id].status == NODE_DIR_ENTRY) {
    result = delete_dir(fs, rp.filename, rp.dir_id);
  } else {
    result = delete_file(fs, rp.filename, rp.dir_id);
  }

  if (result != 0) {
    log_msg(LOG_ERROR, "delete_from_path: Delete failed for '%s': %s", path,
            strerror(-result));
  } else {
    log_msg(LOG_INFO, "delete_from_path: Delete succeeded for '%s'.", path);
  }
  free_resolved_path(&rp);
  return result;
}

void free_resolved_path(resolved_path *rp) {
  if (rp && rp->filename) {
    log_msg(LOG_DEBUG, "free_resolved_path: Freeing resolved filename '%s'.",
            rp->filename);
    free(rp->filename);
    rp->filename = NULL;
  }
}

resolved_path resolve_path(const fs *fs, const char *path, uint32_t start_dir) {
  log_msg(LOG_INFO, "resolve_path: Resolving path '%s' from start dir %u.",
          path, start_dir);
  resolved_path rp = {NULL_NODE_ID, NULL};
  if (!fs || !path) {
    errno = EINVAL;
    return rp;
  }

  file_path fp = file_path_split(path);
  if (fp.parts == NULL) {
    log_msg(LOG_ERROR, "resolve_path: Path '%s' split failed: %s", path,
            strerror(errno));
    return rp;
  }
  if (fp.count == 0) {
    log_msg(LOG_ERROR, "resolve_path: Path '%s' split into zero components.",
            path);
    errno = EINVAL;
    file_path_free(&fp);
    return rp;
  }

  uint32_t current_dir_id = start_dir;
  uint32_t component_start_index = 0;

  if (path[0] == '/') {
    current_dir_id = ROOT;
    if (fp.count > 0 && strcmp(fp.parts[0], "") == 0) {
      component_start_index = 1;
    }
  }

  for (uint32_t i = component_start_index; i < fp.count - 1; ++i) {
    if (current_dir_id == NULL_NODE_ID) {
      file_path_free(&fp);
      return rp;
    }
    current_dir_id = find_node(fs, fp.parts[i], current_dir_id, true);
    if (current_dir_id == NULL_NODE_ID) {
      log_msg(LOG_ERROR, "resolve_path: Component '%s' not found in path '%s'.",
              fp.parts[i], path);
      file_path_free(&fp);
      return rp;
    }
    if (fs->table[current_dir_id].status != NODE_DIR_ENTRY) {
      log_msg(LOG_ERROR,
              "resolve_path: Component '%s' in path '%s' is not a directory.",
              fp.parts[i], path);
      errno = ENOTDIR;
      file_path_free(&fp);
      return rp;
    }
  }

  rp.dir_id = current_dir_id;
  rp.filename = strdup(fp.parts[fp.count - 1]);
  if (!rp.filename) {
    log_msg(LOG_ERROR, "resolve_path: Failed to duplicate filename '%s': %s",
            fp.parts[fp.count - 1], strerror(errno));
    file_path_free(&fp);
    return rp;
  }

  file_path_free(&fp);
  log_msg(LOG_INFO,
          "resolve_path: Path '%s' resolved to dir_id %u, filename '%s'.", path,
          rp.dir_id, rp.filename);
  return rp;
}
