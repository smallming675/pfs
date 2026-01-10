# PFS

This project is a custom file system written in C. It provides a command-line tool (`fs_tool`) for direct interaction with the file system image, and a FUSE (Filesystem in Userspace) implementation (`pfs`) that allows the file system to be mounted and accessed like a regular directory.

## Building the project

To build the project, run the following command:

```bash
make
```

This will create two executables in the `bin` directory: `fs_tool` and `pfs`.

## Running `fs_tool`

The `fs_tool` can be used to interact with the file system image. It provides an interactive shell.

```bash
./bin/fs_tool
```

The tool will create and use a `disk.img` file in the project's root directory.

## Running the FUSE File System

To mount the file system using FUSE, you need a mount point. Create one if it doesn't exist:

```bash
mkdir /tmp/pfs
```

Then, run the `pfs` executable:

```bash
./bin/pfs -d /tmp/pfs
```

The `-d` flag enables FUSE's debug output, which is helpful for troubleshooting. The file system will be mounted at `/tmp/pfs`. To unmount it, use `fusermount`:

```bash
fusermount -u /tmp/pfs
```

