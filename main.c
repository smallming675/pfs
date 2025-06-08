#include <fcntl.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FS_SIZE 134217728 // 128 MB
#define TABLE_SIZE 1024
#define DATA_BYTES_PER_NODE 131070
#define NULL_CLUSTER_ID 0xFFFFFFFF

// Why arent these in stdlib??
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef struct fs_meta {
  uint32_t last_deallocated_node;
} fs_meta;

typedef enum node_status {
  FREE,
  SINGLE_CLUSTER_FILE,
  FILE_START,
  FILE_END,
  FILE_DATA,
} node_status;

typedef struct fs_node {
  uint32_t next_id;
  node_status status;
  char data[DATA_BYTES_PER_NODE];
} fs_node;

typedef struct fs {
  fs_meta meta;
  fs_node table[TABLE_SIZE];
} fs;

void init_fs() {
  int fd = open("disk.img", O_RDWR | O_CREAT, 0666);
  if (fd < 0) {
    printf("Failed to open disk image");
  }

  fs *file_system = malloc(sizeof(fs));
  fs_meta meta;
  meta.last_deallocated_node = uint32_t;
  file_system->meta = meta;
  fs_node node;
  node.next_id = 0;
  for (size_t i = 0; i > TABLE_SIZE; i++) {
    file_system->table[i] = node;
  }

  write(fd, file_system, sizeof(fs));
  close(fd);
};

uint8_t find_free_cluster(fs *file_system) {
  if (file_system->meta.last_deallocated_node != 255){
    return file_system->meta.last_deallocated_node;
  }

  int free_cluster = 255;
  for (uint32_t j = 0; j < TABLE_SIZE; j++) {
    if (file_system->table[j].status == FREE) {
      free_cluster = j;
      break;
    }
  }
  return free_cluster;
};
int main(int argc, char *argv[]) {
  int opt;
  int amend_flag = 0;
  int create_file_flag = 0;
  while ((opt = getopt(argc, argv, "ac")) != -1) {
    switch (opt) {
    case 'a':
      amend_flag = 1;
      break;
    case 'c':
      create_file_flag = 1;
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
    init_fs();
    printf("File system init success\n");
  }

  if (strcmp(argv[optind], "write") == 0) {
    if (argc < 3) {
      printf("`write` needs a file name and data to write!\n");
      return 1;
    }

    char *file_name = argv[optind + 1];
    FILE *f = fopen(argv[optind + 2], "r");
    if (f == NULL || fseek(f, 0, SEEK_END)) {
      return 1;
    }
    long length = ftell(f);
    rewind(f);
    if (length == -1 || (unsigned long)length >= SIZE_MAX) {
      return 1;
    }

    uint32_t file_size = length;

    char *data_to_write = malloc(file_size + 1);
    if (data_to_write == NULL ||
        fread(data_to_write, 1, file_size, f) != file_size) {
      free(data_to_write);
      return 1;
    }

    fclose(f);

    if (!data_to_write) {
      printf("Input File not found!\n");
      return 1;
    }

    int fd = open("disk.img", O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
      perror("Failed to open disk image");
      return 1;
    }

    fs *file_system = malloc(sizeof(fs));
    if (!file_system) {
      perror("Failed to allocate memory for file system");
      close(fd);
      return 1;
    }

    if (read(fd, file_system, sizeof(fs)) != sizeof(fs)) {
      perror("Failed to read file system");
      free(file_system);
      close(fd);
      return 1;
    }

    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
      fs_node *node = &file_system->table[i];
      if (node->status == FILE_START || node->status == SINGLE_CLUSTER_FILE) {
        if (strncmp((char *)node->data, file_name, 32) == 0) {
          printf("File found with same name: %s\n", file_name);

          int cluster_count_needed =
              1 + ((file_size - 1) / DATA_BYTES_PER_NODE);

          int cluster_count_file = 1;
          fs_node *current_node = node;

          if (current_node->status != SINGLE_CLUSTER_FILE) {
            printf("File is in multiple clusters, looping through clusters to "
                   "find count...\n");
            while (current_node->status != FILE_END) {
              current_node = &file_system->table[current_node->next_id];
              cluster_count_file++;
            }
            printf("File contains %i clusters.\n", cluster_count_file);
          }

          if (cluster_count_needed <= cluster_count_file) {
            int bytes_written = 0;
            current_node = node;
            while (bytes_written < file_size) {
              int bytes_to_write = DATA_BYTES_PER_NODE;
              if (bytes_written + bytes_to_write > file_size) {
                bytes_to_write = file_size - bytes_written;
              }
              memcpy(&current_node->data[36], data_to_write + bytes_written,
                     bytes_to_write);
              bytes_written += bytes_to_write;

              if (bytes_written < file_size) {
                current_node = &file_system->table[current_node->next_id];
              }
            }
            printf("Data written successfully to existing clusters.\n");
          } else {
            printf("Allocating new clusters...\n");
            int bytes_written = 0;
            current_node = node;
            while (bytes_written < file_size) {
              int bytes_to_write = DATA_BYTES_PER_NODE;
              if (bytes_written + bytes_to_write > file_size) {
                bytes_to_write = file_size - bytes_written;
              }
              memcpy(&current_node->data[36], data_to_write + bytes_written,
                     bytes_to_write);
              bytes_written += bytes_to_write;

              if (bytes_written < file_size) {
                int free_cluster = find_free_cluster(file_system);
                for (uint32_t j = 0; j < TABLE_SIZE; j++) {
                  if (file_system->table[j].status == FREE) {
                    free_cluster = j;
                    break;
                  }
                }

                current_node->next_id = free_cluster;
                current_node = &file_system->table[free_cluster];
                current_node->status = FILE_DATA;
              }
            }
            printf("Data written successfully with new clusters allocated.\n");
          }

          memcpy(&node->data[32], &file_size, sizeof(short));

          lseek(fd, 0, SEEK_SET);
          write(fd, file_system, sizeof(fs));
          free(file_system);
          close(fd);
          return 0;
        }
      }
    }

    if (!create_file_flag) {
      printf(
          "File not found! use -c to create a file if a file is not found.\n");
      return 1;
    }

    // File not found, create a new file
    printf("File not found! Creating a new file...\n");
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
      if (file_system->table[i].status == FREE) {
        fs_node *new_node = &file_system->table[i];
        strncpy((char *)new_node->data, file_name, 32);

        memcpy(&new_node->data[32], &file_size, sizeof(uint32_t));
        int bytes_written = 0;
        int first_cluster_index = i;
        int last_cluster_index = -1;

        while (bytes_written < file_size) {
          int bytes_to_write = DATA_BYTES_PER_NODE;
          if (bytes_written + bytes_to_write > file_size) {
            bytes_to_write = file_size - bytes_written;
          }

          memcpy(&new_node->data[36], &data_to_write[bytes_written],
                 bytes_to_write);
          bytes_written += bytes_to_write;

          if (bytes_written < file_size) {
            int free_cluster = -1;
            for (uint32_t j = 0; j < TABLE_SIZE; j++) {
              if (file_system->table[j].status == FREE) {
                free_cluster = j;
                break;
              }
            }
            if (free_cluster == -1) {
              printf("Error: Not enough space to create file.\n");
              free(file_system);
              close(fd);
              return 1;
            }

            new_node->next_id = free_cluster;
            last_cluster_index = free_cluster;
            new_node = &file_system->table[free_cluster];
            new_node->status = FILE_DATA;
          }
        }

        file_system->table[first_cluster_index].status =
            (bytes_written <= DATA_BYTES_PER_NODE) ? SINGLE_CLUSTER_FILE
                                                   : FILE_START;

        if (last_cluster_index != -1) {
          file_system->table[last_cluster_index].status = FILE_END;
        }

        lseek(fd, 0, SEEK_SET);
        write(fd, file_system, sizeof(fs));
        printf("New file created and data written successfully.\n");
        free(file_system);
        close(fd);
        return 0;
      }
    }

    printf("Error: No free space to create a new file.\n");
    free(file_system);
    close(fd);
    return 1;
  }

  if (strcmp(argv[optind], "read") == 0) {
    if (argc < 2) {
      printf("`read` needs a file name!\n");
      return 1;
    }

    char *file_name = argv[optind + 1];
    int fd = open("disk.img", O_RDWR | O_CREAT, 0666);
    fs *file_system = malloc(sizeof(fs));
    read(fd, file_system, sizeof(fs));
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
      fs_node *node = &file_system->table[i];
      if (node->status == FILE_START || node->status == SINGLE_CLUSTER_FILE) {
        if (strncmp((char *)node->data, file_name, 32) == 0) {
          printf("File found with same name: %s\n", file_name);
          uint32_t file_size;
          memcpy(&file_size, &node->data[32], 4);
          char *buffer = malloc(file_size);

          if (node->status == SINGLE_CLUSTER_FILE) {
            printf("%s", buffer);
            memcpy(buffer, &node->data[36], file_size);
            return 0;
          }

          long bytes_written = 0;
          do {
            memcpy(&buffer[bytes_written], &node->data[36],
                   DATA_BYTES_PER_NODE - 36);
            bytes_written += DATA_BYTES_PER_NODE;
            node = &file_system->table[node->next_id];

          } while ((&file_system->table[node->next_id])->status == FILE_DATA);
          printf("%s", buffer);
          return 0;
        }
      }
    }
    printf("File not found!\n");
    return 1;
  }

  if (strcmp(argv[optind], "delete") == 0) {
  }
}
