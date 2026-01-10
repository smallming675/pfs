# Project Overview

This project is a custom file system written in C. It provides a command-line tool (`fs_tool`) for direct interaction with the file system image, and a FUSE (Filesystem in Userspace) implementation (`pfs`) that allows the file system to be mounted and accessed like a regular directory.

## Main Technologies

*   **C:** The project is written entirely in C.
*   **FUSE:** Used to integrate the custom file system with the operating system.
*   **Make:** The project uses a `Makefile` for building the executables.

## Architecture

The file system is based on a flat array of nodes (`fs_node`) stored in a file (`disk.img`). Each node can be a directory, a file header, or a data block. Files are represented by a header node and a linked list of data nodes. Directories are represented by a node containing a list of node IDs of its children.

There are two main components:

*   **`fs_tool`:** A command-line tool for creating, populating, and managing the file system image. It provides an interactive shell with commands like `ls`, `cd`, `mkdir`, `write`, `cat`, and `rm`.
*   **`pfs`:** A FUSE implementation that allows the file system to be mounted on the host system. It implements the `getattr`, `readdir`, and `read` FUSE operations.

# Building and Running

## Building

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

# Development Conventions

*   **Coding Style:** The code follows a consistent style, with a focus on readability.
*   **Testing:** There is a `pfs_tests.c` file, suggesting that a testing framework is in use. The `test` target in the `Makefile` runs the tests.
*   **Error Handling:** Errors are generally handled by returning an error code or `NULL`, and messages are printed to `stderr` or logged using the custom `logger`.
