#define FUSE_USE_VERSION 26
#include "pfs.h"

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "fs.h"
#include "dir.h"
#include "logger.h"

fs my_fs;

int pfs_getattr(const char *path, struct stat *stbuf)
{
    log_msg(LOG_DEBUG, "pfs_getattr: path='%s'", path);
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        memcpy(stbuf, &my_fs.table[ROOT].st, sizeof(struct stat));
        log_msg(LOG_INFO, "pfs_getattr: Retrieved attributes for root directory.");
        return 0;
    }

    uint32_t node_id = get_node_from_path(&my_fs, path);
    if (node_id == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "pfs_getattr: Path not found: %s", path);
        return -ENOENT;
    }

    memcpy(stbuf, &my_fs.table[node_id].st, sizeof(struct stat));
    log_msg(LOG_INFO, "pfs_getattr: Retrieved attributes for %s (node_id: %u).", path, node_id);
    return 0;
}

int pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
    log_msg(LOG_DEBUG, "pfs_readdir: path='%s'", path);
    (void)offset;
    (void)fi;

    uint32_t node_id = get_node_from_path(&my_fs, path);
    if (node_id == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "pfs_readdir: Path not found: %s", path);
        return -ENOENT;
    }

    if (my_fs.table[node_id].status != NODE_DIR_ENTRY) {
        log_msg(LOG_ERROR, "pfs_readdir: Not a directory: %s", path);
        return -ENOTDIR;
    }

    filler(buf, ".", &my_fs.table[node_id].st, 0);
    filler(buf, "..", &my_fs.table[ROOT].st, 0); // Assuming root is always '..' for now

    for (uint32_t i = 0; i < my_fs.table[node_id].data.dir_entry.entry_count; ++i) {
        uint32_t entry_id = my_fs.table[node_id].data.dir_entry.entries[i];
        if (entry_id != NULL_NODE_ID) {
            fs_node *entry_node = &my_fs.table[entry_id];
            const char *entry_name = NULL;

            if (entry_node->status == NODE_DIR_ENTRY) {
                entry_name = entry_node->data.dir_entry.dir_name;
            } else if (entry_node->status == NODE_SINGLE_NODE_FILE ||
                       entry_node->status == NODE_FILE_START) {
                entry_name = entry_node->data.header_file.file_name;
            }

            if (entry_name) {
                filler(buf, entry_name, &entry_node->st, 0);
                log_msg(LOG_DEBUG, "pfs_readdir: Added entry '%s' to buffer.", entry_name);
            }
        }
    }
    log_msg(LOG_INFO, "pfs_readdir: Successfully listed directory: %s", path);
    return 0;
}

int pfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    log_msg(LOG_DEBUG, "pfs_read: path='%s', size=%zu, offset=%lld", path, size, offset);
    (void)fi; // Unused parameter

    uint32_t node_id = get_node_from_path(&my_fs, path);
    if (node_id == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "pfs_read: File not found: %s", path);
        return -ENOENT;
    }

    if (!S_ISREG(my_fs.table[node_id].st.st_mode)) {
        log_msg(LOG_ERROR, "pfs_read: Not a regular file: %s", path);
        return -EISDIR; // Not a regular file
    }

    uint64_t file_size;
    uint8_t *file_content = read_from_path(&my_fs, path, false, &file_size);
    if (!file_content) {
        log_msg(LOG_ERROR, "pfs_read: Error reading file: %s", path);
        return -EIO; // Input/output error
    }

    uint64_t bytes_to_read = size;
    if ((uint64_t)offset < file_size) {
        if ((uint64_t)offset + bytes_to_read > file_size) {
            bytes_to_read = file_size - offset;
        }
        memcpy(buf, file_content + offset, bytes_to_read);
    } else {
        bytes_to_read = 0;
    }

    free(file_content);
    log_msg(LOG_INFO, "pfs_read: Successfully read %zu bytes from %s", bytes_to_read, path);
    return bytes_to_read;
}

int pfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    log_msg(LOG_DEBUG, "pfs_write: path='%s', size=%zu, offset=%lld", path, size, offset);
    (void)fi;

    uint32_t node_id = get_node_from_path(&my_fs, path);
    if (node_id == NULL_NODE_ID) {
        // For simplicity, we don't create files on write, just return ENOENT
        log_msg(LOG_ERROR, "pfs_write: File not found: %s", path);
        return -ENOENT;
    }

    if (!S_ISREG(my_fs.table[node_id].st.st_mode)) {
        log_msg(LOG_ERROR, "pfs_write: Not a regular file: %s", path);
        return -EISDIR;
    }

    uint64_t old_size;
    uint8_t *old_content = read_from_path(&my_fs, path, false, &old_size);
    if (!old_content && old_size > 0) {
        log_msg(LOG_ERROR, "pfs_write: Error reading existing file: %s", path);
        return -EIO;
    }

    uint64_t new_size = offset + size;
    if (new_size < old_size) {
        new_size = old_size;
    }

    uint8_t *new_content = (uint8_t*)realloc(old_content, new_size);
    if (!new_content) {
        log_msg(LOG_ERROR, "pfs_write: Failed to allocate memory for new content.");
        if (old_content) free(old_content);
        return -ENOMEM;
    }

    memcpy(new_content + offset, buf, size);

    if (write_from_path(&my_fs, path, new_content, new_size) == 0) {
        log_msg(LOG_ERROR, "pfs_write: Failed to write to file: %s", path);
        free(new_content);
        return -EIO;
    }

    free(new_content);
    log_msg(LOG_INFO, "pfs_write: Successfully wrote %zu bytes to %s", size, path);
    return size;
}

int pfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    log_msg(LOG_DEBUG, "pfs_mknod: path='%s', mode=%o", path, mode);
    (void)rdev;

    if (!S_ISREG(mode)) {
        log_msg(LOG_ERROR, "pfs_mknod: Only regular files can be created. Invalid mode: %o", mode);
        return -EACCES;
    }

    // Extract parent path and new file name
    char parent_path[256];
    char new_file_name[256];
    char *last_slash = strrchr(path, '/');
    if (last_slash == NULL || last_slash == path) {
        strcpy(parent_path, "/");
    } else {
        strncpy(parent_path, path, last_slash - path);
        parent_path[last_slash - path] = '\0';
    }
    strcpy(new_file_name, last_slash + 1);

    uint32_t parent_id = get_node_from_path(&my_fs, parent_path);
    if (parent_id == NULL_NODE_ID) {
        log_msg(LOG_ERROR, "pfs_mknod: Parent directory not found: %s", parent_path);
        return -ENOENT;
    }

    if (create_file(&my_fs, new_file_name, parent_id, NULL, 0) == 0) {
        log_msg(LOG_ERROR, "pfs_mknod: Failed to create file: %s", new_file_name);
        return -EIO;
    }

    log_msg(LOG_INFO, "pfs_mknod: Successfully created file: %s", path);
    return 0;
}

int pfs_unlink(const char *path)
{
    log_msg(LOG_DEBUG, "pfs_unlink: path='%s'", path);

    if (delete_from_path(&my_fs, path) == 0) {
        log_msg(LOG_ERROR, "pfs_unlink: Failed to delete file: %s", path);
        return -EIO;
    }

    log_msg(LOG_INFO, "pfs_unlink: Successfully deleted file: %s", path);
    return 0;
}


#ifndef TEST_BUILD
static struct fuse_operations pfs_oper = {
    .getattr	= pfs_getattr,
    .readdir	= pfs_readdir,
    .read		= pfs_read,
    .write      = pfs_write,
    .mknod      = pfs_mknod,
    .unlink     = pfs_unlink,
};

int main(int argc, char *argv[])
{
    int ret = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 < argc) {
                set_log_level(log_level_from_str(argv[i + 1]));
                // Remove the arguments from the list to be passed to fuse_main
                argv[i] = NULL;
                argv[i + 1] = NULL;
                i++;
            } else {
                fprintf(stderr, "Missing log level\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [FUSE options] [--log-level <level>]\n", argv[0]);
            printf("Log levels: INFO, WARN, ERROR, DEBUG\n");
            return 0;
        }
    }
    
    // Clean up argv
    int new_argc = 1;
    for(int i = 1; i < argc; i++) {
        if(argv[i] != NULL) {
            argv[new_argc] = argv[i];
            new_argc++;
        }
    }
    argc = new_argc;

    fs_init(&my_fs, 1000);
    log_msg(LOG_INFO, "main: FUSE file system initialized with 1000 nodes.");
    ret = fuse_main(argc, argv, &pfs_oper, NULL);
    return ret;
}
#endif // TEST_BUILD


