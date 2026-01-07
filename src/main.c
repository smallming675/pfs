#include "dir.h"
#include "fs.h"
#include "logger.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *IMAGE_FILE = "disk.img";

static uint32_t cwd_id = 0;
static char cwd_path[256] = "/";

static void ensure_image(fs *myfs, uint32_t nodes) {
  if (!fs_read_image(myfs, IMAGE_FILE)) {
    printf("No image found, initializing new filesystem with %u nodes\n",
           nodes);
    fs_init(myfs, nodes);
    fs_write_image(myfs, IMAGE_FILE);
  }
}

static int cmd_mkdir(fs *myfs, const char *subdir_name) {
  resolved_path rp = resolve_path(myfs, cwd_path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    printf("mkdir: invalid path %s\n", cwd_path);
    free_resolved_path(&rp);
    return 0;
  }

  uint32_t new_id = fs_allocate_node(myfs);
  if (new_id == NULL_NODE_ID) {
    printf("mkdir: no space left\n");
    free_resolved_path(&rp);
    return 0;
  }

  fs_node *node = &myfs->table[new_id];
  node->status = NODE_DIR_ENTRY;
  strncpy(node->data.dir_entry.dir_name, subdir_name,
          sizeof(node->data.dir_entry.dir_name) - 1);
  node->data.dir_entry.dir_name[sizeof(node->data.dir_entry.dir_name) - 1] =
      '\0';
  if (insert_file_to_dir(myfs, rp.dir_id, new_id)) {
    printf("mkdir: failed to insert %s\n", subdir_name);
    free_resolved_path(&rp);
    return 0;
  }

  free_resolved_path(&rp);
  return 1;
}

static void cmd_cat(fs *myfs, const char *path) {
  uint64_t size = 0;
  uint8_t *buf = read_from_path(myfs, path, 0, &size);
  if (!buf) {
    printf("cat: cannot read %s\n", path);
    return;
  }
  fwrite(buf, 1, size, stdout);
  free(buf);
}

static void cmd_write(fs *myfs, const char *path, const char *os_file) {
  size_t bytes = 0;
  uint8_t *data = fs_read_os_file(os_file, &bytes);
  if (!data) {
    printf("write: cannot open %s\n", os_file);
    return;
  }
  if (!write_from_path(myfs, path, data, bytes)) {
    printf("write: failed to write %s\n", path);
  }
  free(data);
}

static void cmd_rm(fs *myfs, const char *path) {
  if (!delete_from_path(myfs, path)) {
    printf("rm: failed to delete %s\n", path);
  }
}

static void cmd_ls(fs *myfs, const char *path) {
  log_msg(LOG_INFO, "Running 'ls' on '%s'.", path);
  if (!path) {
    cmd_ls(myfs, cwd_path);
    return;
  }

  resolved_path rp = resolve_path(myfs, path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    printf("ls: cannot access %s\n", path);
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
      printf("%s ", myfs->table[entry].data.dir_entry.dir_name);
    }
    free_resolved_path(&rp);
  }
  printf("\n");
}

static void cmd_cd(fs *myfs, const char *path) {
  resolved_path rp = resolve_path(myfs, path, cwd_id);
  if (rp.dir_id == NULL_NODE_ID) {
    printf("cd: no such directory: %s\n", path);
    free_resolved_path(&rp);
    return;
  }

  if (rp.filename) {
    uint32_t next_id = find_dir_node(myfs, rp.filename, rp.dir_id);
    if (!is_valid_dir(myfs, rp.filename, rp.dir_id)) {
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
  }

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
