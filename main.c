#include <assert.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TABLE_SIZE 1024
#define NULL_NODE_ID 0xFFFFFFFF

#define FILE_NAME_SIZE 32
#define FILE_SIZE_SIZE 8
#define FILE_HEADER_SIZE (FILE_SIZE_SIZE + FILE_NAME_SIZE)
#define DATA_BYTES_PER_NODE 131072

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

typedef enum node_status {
  FREE,
  SINGLE_NODE_FILE,
  FILE_START,
  FILE_END,
  FILE_DATA,
  USED
} node_status;

typedef struct {
  node_status status;
  union {
    struct {
      uint32_t next_id;
      char file_name[32];
      uint64_t file_size;
      char data[DATA_BYTES_PER_NODE];
    } header_file;
    struct {
      uint32_t next_id;
      char data[DATA_BYTES_PER_NODE];
    } data_file;
    void *free;
  } data;
} fs_node;

typedef struct {
  struct {
    uint32_t smallest_id_deallocated_node;
    uint32_t largest_id_allocated_node;
  } meta;
  fs_node table[TABLE_SIZE];
} fs;

size_t get_file_size(const char *filename) {
  struct stat file_stat;
  if (stat(filename, &file_stat) != 0) {
    perror("Failed to get file size");
    return -1;
  }
  return file_stat.st_size;
}

char *read_os_file(const char *filename) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    perror("Failed to open file");
    return NULL;
  }

  char *buffer = NULL;
  size_t total_size = 0;
  size_t bytes_read;

#define CHUNK_SIZE 1024
  buffer = malloc(CHUNK_SIZE);
  if (!buffer) {
    perror("Failed to allocate memory");
    fclose(file);
    return NULL;
  }

  while ((bytes_read = fread(buffer + total_size, 1, CHUNK_SIZE, file)) > 0) {
    total_size += bytes_read;

    if (total_size % CHUNK_SIZE == 0) {
      char *temp = realloc(buffer, total_size + CHUNK_SIZE);
      if (!temp) {
        perror("Failed to reallocate memory");
        free(buffer);
        fclose(file);
        return NULL;
      }
      buffer = temp;
    }
  }

  if (ferror(file)) {
    perror("Error reading file");
    free(buffer);
    fclose(file);
    return NULL;
  }

  fclose(file);
  return buffer;
}

void write_fs_to_file(fs *file_system, const char *disk_image) {
  int fd = open(disk_image, O_RDWR | O_CREAT, 0666);
  if (fd < 0) {
    perror("Failed to open disk image");
    return;
  }

  if (write(fd, file_system, sizeof(fs)) != sizeof(fs)) {
    perror("Failed to write file system to disk");
  }

  free(file_system);
  close(fd);
}

void init_fs(const char *disk_image) {
  int fd = open(disk_image, O_RDWR | O_CREAT, 0666);
  if (fd < 0) {
    perror("Failed to open disk image");
    return;
  }

  fs *file_system = calloc(1, sizeof(fs));
  if (!file_system) {
    perror("Failed to allocate memory for file system");
    close(fd);
    return;
  }

  file_system->meta.smallest_id_deallocated_node = NULL_NODE_ID;
  file_system->meta.largest_id_allocated_node = 0;

  for (size_t i = 0; i < TABLE_SIZE; i++) {
    file_system->table[i].status = FREE;
  }

  if (write(fd, file_system, sizeof(fs)) != sizeof(fs)) {
    perror("Failed to write file system to disk");
  }

  free(file_system);
  close(fd);
  printf("File system initialized successfully.\n");
}

void deallocate_node(fs *file_system, uint32_t node_id) {
  assert(node_id < TABLE_SIZE);

  if (file_system->table[node_id].status == FREE) {
    return;
  }

  file_system->table[node_id].status = FREE;

  if (node_id < file_system->meta.smallest_id_deallocated_node) {
    file_system->meta.smallest_id_deallocated_node = node_id;
  }

  if (node_id == file_system->meta.largest_id_allocated_node &&
      file_system->meta.largest_id_allocated_node > 0) {
    file_system->meta.largest_id_allocated_node--;
  }
}

uint32_t allocate_node(fs *file_system) {
  if (file_system->meta.smallest_id_deallocated_node != NULL_NODE_ID) {
    uint32_t node_id = file_system->meta.smallest_id_deallocated_node;

    file_system->table[node_id].status = USED;

    for (uint32_t i = node_id + 1;
         i <= file_system->meta.largest_id_allocated_node; i++) {
      if (file_system->table[i].status == FREE) {
        file_system->meta.smallest_id_deallocated_node = i;
        return node_id;
      }
    }
  }

  uint32_t node_id = file_system->meta.largest_id_allocated_node++;
  file_system->table[node_id].status = USED;
  return node_id;
}

uint32_t find_file_node(const fs *file_system, const char *file_name) {
  for (uint32_t i = 0; i < TABLE_SIZE; i++) {
    const fs_node *node = &file_system->table[i];
    if (!(node->status == FILE_START || node->status == SINGLE_NODE_FILE)) {
      continue;
    }
    if (strcmp(node->data.header_file.file_name, file_name)) {
      continue;
    }

    return i;
  }

  return NULL_NODE_ID;
}

void create_file(fs *file_system, const char *file_name, const char *data,
                 uint64_t file_size) {
  uint32_t node_id = allocate_node(file_system);
  if (node_id == NULL_NODE_ID) {
    printf("Error: No free space to create a new file.\n");
    return;
  }

  fs_node *node = &file_system->table[node_id];
  memcpy(node->data.header_file.file_name, file_name, FILE_NAME_SIZE);
  node->data.header_file.file_size = file_size;

  if (file_size <= (DATA_BYTES_PER_NODE - FILE_HEADER_SIZE)) {
    node->status = SINGLE_NODE_FILE;
    memcpy(&node->data.header_file.data, data, file_size);
    printf("New single-node file created and data written successfully.\n");
    return;
  }

  node->status = FILE_START;
  memcpy(&node->data.header_file.data, data,
         DATA_BYTES_PER_NODE - FILE_HEADER_SIZE);
  size_t bytes_written = DATA_BYTES_PER_NODE;
  uint32_t free_node = allocate_node(file_system);
  node->data.header_file.next_id = free_node;
  node = &file_system->table[free_node];

  while (bytes_written < file_size) {
    memcpy(&node->data.data_file.data, data, DATA_BYTES_PER_NODE);
    bytes_written += DATA_BYTES_PER_NODE;

    if (bytes_written < file_size) {
      free_node = allocate_node(file_system);
      node->status = FILE_DATA;
      node->data.data_file.next_id = free_node;
      node = &file_system->table[free_node];
    }
  }

  node->status = FILE_END;
  printf("New file created and data written successfully.\n");
  return;
}

void write_file(fs *file_system, const char *file_name, const char *data,
                size_t file_size) {
  size_t bytes_written = 0;
  uint32_t node_id = find_file_node(file_system, file_name);

  if (node_id == NULL_NODE_ID) {
    printf("File not found! Creating a new file...\n");
    create_file(file_system, file_name, data, file_size);
    return;
  }

  fs_node *node = &file_system->table[node_id];
  memcpy(node->data.header_file.file_name, file_name, FILE_SIZE_SIZE);
  node->data.header_file.file_size = file_size;

  uint32_t required_node_count =
      (file_size + DATA_BYTES_PER_NODE - 1) / DATA_BYTES_PER_NODE;

  if (required_node_count == 1) {
    node->status = SINGLE_NODE_FILE;
    memcpy(&node->data.header_file.data, data, file_size);
  } else {
    if (node->status == SINGLE_NODE_FILE) {
      uint32_t free_node = allocate_node(file_system);
      if (free_node == NULL_NODE_ID) {
        printf("Error: No free nodes available!\n");
        return;
      }
      node->data.header_file.next_id = free_node;
      file_system->table[free_node].status = FILE_END;
    }

    node->status = FILE_START;
    uint32_t current_node_id = node->data.header_file.next_id;

    while (bytes_written < file_size) {
      int bytes_to_write = MIN(DATA_BYTES_PER_NODE, file_size - bytes_written);
      fs_node *current_node = &file_system->table[current_node_id];

      memcpy(&current_node->data.data_file.data, &data[bytes_written],
             bytes_to_write);
      bytes_written += bytes_to_write;
      if (bytes_written >= file_size) {
        current_node->status = FILE_END;
        current_node->data.data_file.next_id = NULL_NODE_ID;
        break;
      }

      if (current_node->status != FILE_END) {
        current_node->status = FILE_DATA;
        current_node_id = current_node->data.data_file.next_id;
        continue;
      }

      uint32_t free_node = allocate_node(file_system);
      if (free_node == NULL_NODE_ID) {
        printf("Error: No free nodes available!\n");
        return;
      }
      current_node->data.data_file.next_id = free_node;
      current_node->status = FILE_DATA;
      current_node_id = free_node;
      file_system->table[free_node].status = FILE_END;
    }
  }

  uint32_t next_node_id = node->data.header_file.next_id;
  while (node->data.data_file.next_id == FILE_DATA) {
    fs_node *next_node = &file_system->table[next_node_id];
    uint32_t temp_next_id = next_node->data.data_file.next_id;
    deallocate_node(file_system, temp_next_id);
    next_node_id = temp_next_id;
  }
  deallocate_node(file_system, next_node_id);

  printf("Data written successfully.\n");
}

void read_file(const fs *file_system, const char *file_name,
               int file_meta_flag) {
  uint32_t node_id = find_file_node(file_system, file_name);
  if (node_id == NULL_NODE_ID) {
    printf("File not found: %s\n", file_name);
    return;
  }

  const fs_node *node = &file_system->table[node_id];
  printf("File found: %s\n", file_name);

  uint64_t file_size = node->data.header_file.file_size;
  char *buffer = malloc(file_size);
  if (!buffer) {
    perror("Failed to allocate memory for file buffer");
    return;
  }

  long bytes_read = 0;
  size_t node_count = 1;

  int bytes_to_read =
      MIN(DATA_BYTES_PER_NODE - FILE_HEADER_SIZE, file_size - bytes_read);
  memcpy(&buffer[bytes_read], &node->data.header_file.data,
         DATA_BYTES_PER_NODE);
  bytes_read += bytes_to_read;
  if (node->status == SINGLE_NODE_FILE) {
    if (file_meta_flag) {
      printf("File size: %li bytes, node count: 1\n", file_size);
      return;
    }
    printf("File content:\n%s\n", buffer);
    return;
  }

  node = &file_system->table[node->data.header_file.next_id];

  do {
    int bytes_to_read =
        MIN(DATA_BYTES_PER_NODE - FILE_HEADER_SIZE, file_size - bytes_read);
    memcpy(&buffer[bytes_read], &node->data.data_file.data, bytes_to_read);
    bytes_read += bytes_to_read;

    if (node->status == FILE_END || bytes_read >= file_size) {
      break;
    }
    node_count++;
    node = &file_system->table[node->data.data_file.next_id];
  } while (1);

  if (file_meta_flag) {
    printf("File size: %li bytes, node count: %zu\n", file_size, node_count);
    return;
  }

  printf("File content:\n%s\n", buffer);
  free(buffer);
  return;
}

void delete_file(fs *file_system, char *file_name) {
  uint32_t node_id = find_file_node(file_system, file_name);
  if (node_id == NULL_NODE_ID) {
    printf("Error: file not found.\n");
    return;
  }

  fs_node *node = &file_system->table[node_id];
  if (node->status == SINGLE_NODE_FILE) {
    deallocate_node(file_system, node_id);
    printf("Deleted single node file.\n");
    return;
  }

  uint64_t file_size = node->data.header_file.file_size;
  uint32_t file_node_count = (file_size - 1) / DATA_BYTES_PER_NODE + 1;
  uint32_t *nodes = malloc(file_node_count * sizeof(uint32_t));

  nodes[0] = node_id;
  uint32_t node_index = 1;

  do {
    nodes[node_index] = node->data.data_file.next_id;
    node = &file_system->table[node->data.data_file.next_id];
    node_index++;
  } while ((&file_system->table[node->data.data_file.next_id])->status !=
           FILE_END);

  nodes[node_index] = node->data.data_file.next_id;
  for (int i = 0; i < file_node_count; i++) {
    deallocate_node(file_system, nodes[i]);
  }

  free(nodes);
  printf("Deleted file with %i nodes.\n", file_node_count);
  return;
}

fs *read_from_fs(char *fs_file_name) {
  int fd = open(fs_file_name, O_RDWR | O_CREAT, 0666);
  if (fd < 0) {
    perror("Failed to open disk image");
    return NULL;
  }

  fs *file_system = malloc(sizeof(fs));
  if (!file_system) {
    perror("Failed to allocate memory for file system");
    close(fd);
    return NULL;
  }

  if (read(fd, file_system, sizeof(fs)) != sizeof(fs)) {
    perror("Failed to read file system");
    free(file_system);
    close(fd);
    return NULL;
  }

  close(fd);
  return file_system;
}

int main(int argc, char *argv[]) {
  int opt;
  int file_size_flag = 0;
  char *fs_file_name;
  while ((opt = getopt(argc, argv, "sd:")) != -1) {
    switch (opt) {
    case 's':
      file_size_flag = 1;
      break;
    case 'd':
      fs_file_name = optarg;
      break;
    case '?':
      fprintf(stderr, "Unknown option `-%c`.\n", optopt);
      return 1;
    }
  }

  if (optind >= argc) {
    return 1;
  }

  if (strcmp(argv[optind], "init") == 0) {
    if (strcmp(fs_file_name, "") == 0) {
      printf("No disk image specified!, use `-d <disk_image> to specify an "
             "image.\n");
      return 1;
    }

    init_fs(fs_file_name);
    return 0;
  }

  if (strcmp(argv[optind], "write") == 0) {
    if (argc < 3) {
      printf("`write` needs a file name and data to write!\n");
      return 1;
    }

    char *file_name = argv[optind + 2];

    char *os_file_name = argv[optind + 1];
    char *data = read_os_file(os_file_name);
    size_t file_size = get_file_size(os_file_name);

    if (!data) {
      printf("Input File not found!\n");
      return 1;
    }

    if (strcmp(fs_file_name, "") == 0) {
      printf("No disk image specified!, use `-d <disk_image> to specify an "
             "image.\n");
      return 1;
    }

    fs *file_system = read_from_fs(fs_file_name);
    write_file(file_system, file_name, data, file_size);
    write_fs_to_file(file_system, fs_file_name);
    return 0;
  }

  if (strcmp(argv[optind], "read") == 0) {
    if (argc < 2) {
      printf("`read` needs a file name!\n");
      return 1;
    }

    if (strcmp(fs_file_name, "") == 0) {
      printf("No disk image specified!, use `-d <disk_image> to specify an "
             "image.\n");
      return 1;
    }

    fs *file_system = read_from_fs(fs_file_name);
    read_file(file_system, argv[optind + 1], file_size_flag);
    free(file_system);
    return 0;
  }

  if (strcmp(argv[optind], "delete") == 0) {
    char *file_name = argv[optind + 1];
    if (strcmp(fs_file_name, "") == 0) {
      printf("No disk image specified!, use `-d <disk_image> to specify an "
             "image.\n");
      return 1;
    }

    fs *file_system = read_from_fs(fs_file_name);
    delete_file(file_system, file_name);
    write_fs_to_file(file_system, fs_file_name);
    return 0;
  }

  if (strcmp(argv[optind], "exam") == 0) {
    if (strcmp(fs_file_name, "") == 0) {
      printf("No disk image specified!, use `-d <disk_image> to specify an "
             "image.\n");
      return 1;
    }
    fs *file_system = read_from_fs(fs_file_name);
    for (int i = 0; i <= 20; i++) {
      printf("%i\n", file_system->table[i].status);
    }
  }
}
