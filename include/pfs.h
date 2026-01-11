#ifndef PFS_H
#define PFS_H

#include <fuse.h>
#include "fs.h"

int pfs_getattr(const char *path, struct stat *stbuf);
int pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi);
int pfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi);
int pfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi);
int pfs_mknod(const char *path, mode_t mode, dev_t rdev);
int pfs_unlink(const char *path);
int pfs_utimens(const char *path, const struct timespec tv[2]);
int pfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int pfs_open(const char *path, struct fuse_file_info *fi);
int pfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);
int pfs_flush(const char *path, struct fuse_file_info *fi);
int pfs_symlink(const char *target, const char *newpath);
int pfs_readlink(const char *path, char *buf, size_t size);

#endif // PFS_H
