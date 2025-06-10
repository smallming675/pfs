This is a tool that provides a simple interface for interacting with the file system. Basic operations include:

### Commands
- `init`: Create a new file system
- `write`: Add a file to the system
- `read`: Retrieve a file's contents
- `delete`: Remove a file

### Usage
```bash
./fs_tool -d disk.img init
./fs_tool -d disk.img write local_file system_file
./fs_tool -d disk.img read system_file
```

