#include "dir.h"
#include "fs.h"
#include "logger.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *IMAGE_FILE = "disk.img";

static uint32_t cwd_id = 0;
static char cwd_path[256] = "/";

static void ensure_image(fs *myfs, uint32_t nodes) {
  if (fs_read_image(myfs, IMAGE_FILE)) {
    log_msg(LOG_INFO,
            "ensure_image: No image found, initializing new filesystem with %u "
            "nodes",
            nodes);
    fs_init(myfs, nodes);
    fs_write_image(myfs, IMAGE_FILE);
  }
}

static int cmd_mkdir(fs *myfs, const char *subdir_name) {
  resolved_path rp = resolve_path(myfs, cwd_path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "cmd_mkdir: Invalid path %s\n", cwd_path);
    free_resolved_path(&rp);
    return 0;
  }
  if (!create_dir(myfs, rp.dir_id, subdir_name)) {
    log_msg(LOG_ERROR, "cmd_mkdir: Failed to create directory %s\n",
            subdir_name);
    return 0;
  }
  log_msg(LOG_INFO, "cmd_mkdir: Successfully created directory %s\n",
          subdir_name);
  return 1;
}

static void cmd_cat(fs *myfs, const char *path) {
  uint64_t size = 0;
  uint8_t *buf = read_from_path(myfs, path, 0, &size);
  if (!buf) {
    log_msg(LOG_ERROR, "cmd_cat: Cannot read %s\n", path);
    return;
  }
  fwrite(buf, 1, size, stdout);
  free(buf);
  log_msg(LOG_INFO, "cmd_cat: Successfully read %llu bytes from %s\n",
          (unsigned long long)size, path);
}

static void cmd_write(fs *myfs, const char *path, const char *os_file) {
  size_t bytes = 0;
  uint8_t *data = fs_read_os_file(os_file, &bytes);
  if (!data) {
    log_msg(LOG_ERROR, "cmd_write: Cannot open OS file %s\n", os_file);
    return;
  }
  if (!write_from_path(myfs, path, data, bytes)) {
    log_msg(LOG_ERROR, "cmd_write: Failed to write %s to file system\n", path);
  } else {
    log_msg(LOG_INFO, "cmd_write: Successfully wrote %zu bytes from %s to %s\n",
            bytes, os_file, path);
  }
  free(data);
}

static void cmd_rm(fs *myfs, const char *path) {
  if (!delete_from_path(myfs, path)) {
    log_msg(LOG_ERROR, "cmd_rm: Failed to delete %s\n", path);
  } else {
    log_msg(LOG_INFO, "cmd_rm: Successfully deleted %s\n", path);
  }
}

static void cmd_ls(fs *myfs, const char *path) {
  log_msg(LOG_INFO, "cmd_ls: Running 'ls' on '%s'.", path);
  if (!path) {
    log_msg(LOG_DEBUG,
            "cmd_ls: Path not provided, using current working directory: %s",
            cwd_path);
    cmd_ls(myfs, cwd_path);
    return;
  }

  resolved_path rp = resolve_path(myfs, path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "cmd_ls: Cannot access %s\n", path);
    printf("ls: cannot access %s\n", path); // Keep printf for user feedback
    free_resolved_path(&rp);
    return;
  }

  uint32_t dir_id = rp.dir_id;
  size_t count = myfs->table[dir_id].data.dir_entry.entry_count;

  for (size_t i = 0; i < count; i++) {
    uint32_t entry = myfs->table[dir_id].data.dir_entry.entries[i];
    if (!entry)
      continue;
    node_status status = myfs->table[entry].status;
    if (status == NODE_FILE_START || status == NODE_SINGLE_NODE_FILE) {
      printf("%s ", myfs->table[entry].data.header_file.file_name);
    }
    if (status == NODE_DIR_ENTRY) {
      printf(
          "%s/ ",
          myfs->table[entry].data.dir_entry.dir_name); // Add / for directories
    }
  }
  printf("\n");
  log_msg(LOG_INFO, "cmd_ls: Successfully listed contents of %s", path);
  free_resolved_path(&rp); // Free resolved path after use
}

static void cmd_cd(fs *myfs, const char *path) {
  log_msg(LOG_INFO, "cmd_cd: Changing directory to '%s'.", path);
  resolved_path rp = resolve_path(myfs, path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    log_msg(LOG_ERROR, "cmd_cd: No such directory: %s\n", path);
    printf("cd: no such directory: %s\n", path);
    free_resolved_path(&rp);
    return;
  }

  if (rp.filename) { // If path refers to a file, not a directory
    uint32_t next_id = find_dir_node(myfs, rp.filename, rp.dir_id);
    if (!is_valid_dir(myfs, rp.filename, rp.dir_id)) {
      log_msg(LOG_ERROR, "cmd_cd: Not a directory: %s\n", path);
      printf("cd: not a directory: %s\n", path);
      free_resolved_path(&rp);
      return;
    }
    cwd_id = next_id;
  } else {
    cwd_id = rp.dir_id;
  }

  if (path[0] == '/') {
    strncpy(cwd_path, path, sizeof(cwd_path) - 1);
    cwd_path[sizeof(cwd_path) - 1] = '\0';
  } else {
    size_t len = strlen(cwd_path);
    if (len > 1 && cwd_path[len - 1] != '/')
      strncat(cwd_path, "/", sizeof(cwd_path) - len - 1);
    strncat(cwd_path, path, sizeof(cwd_path) - strlen(cwd_path) - 1);
    strncat(cwd_path, "/", sizeof(cwd_path) - strlen(cwd_path) - 1);
  }

  log_msg(LOG_INFO,
          "cmd_cd: Successfully changed directory to %s (node id: %u)",
          cwd_path, cwd_id);
  free_resolved_path(&rp);
}

int main(void) {
  fs myfs;
  ensure_image(&myfs, 128);

  cwd_id = 0;
  strcpy(cwd_path, "/");

  char *line = NULL;
  size_t cap = 0;
  printf("fs:%s$ ", cwd_path);
  while (getline(&line, &cap, stdin) != -1) {
    line[strcspn(line, "\n")] = '\0';
    if (strcmp(line, "exit") == 0)
      break;

    char *cmd = strtok(line, " ");
    if (!cmd) {
      printf("fs:%s$ ", cwd_path);
      continue;
    }

    if (strcmp(cmd, "cat") == 0) {
      char *path = strtok(NULL, " ");
      if (path)
        cmd_cat(&myfs, path);
    } else if (strcmp(cmd, "write") == 0) {
      char *path = strtok(NULL, " ");
      char *os_file = strtok(NULL, " ");
      if (path && os_file)
        cmd_write(&myfs, path, os_file);
    } else if (strcmp(cmd, "rm") == 0) {
      char *path = strtok(NULL, " ");
      if (path)
        cmd_rm(&myfs, path);
    } else if (strcmp(cmd, "ls") == 0) {
      char *path = strtok(NULL, " ");
      cmd_ls(&myfs, path);
    } else if (strcmp(cmd, "cd") == 0) {
      char *path = strtok(NULL, " ");
      if (path)
        cmd_cd(&myfs, path);
    } else if (strcmp(cmd, "mkdir") == 0) {
      char *path = strtok(NULL, " ");
      if (path)
        cmd_mkdir(&myfs, path);
    } else {
      printf("unknown command: %s\n", cmd);
    }

    printf("fs:%s$ ", cwd_path);
  }
  free(line);

  fs_write_image(&myfs, IMAGE_FILE);
  fs_free(&myfs);
  return 0;
}
