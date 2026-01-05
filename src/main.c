#include "fs.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

static void usage(void) {
    printf("Usage:\n"
           "  -d <disk_image>\n"
           "  -b <node_count>\n"
           "Commands:\n"
           "  init\n"
           "  write <os_file> <fs_name>\n"
           "  read  <fs_name> [-s]\n"
           "  delete <fs_name>\n"
           "  exam\n");
}

int main(int argc, char** argv) {
    int opt = 0;
    int file_size_flag = 0;
    int fs_nodes = 0;
    const char* disk_image = "";

    while ((opt = getopt(argc, argv, "sd:b:")) != -1) {
        switch (opt) {
            case 's': file_size_flag = 1; break;
            case 'd': disk_image = optarg; break;
            case 'b': fs_nodes = atoi(optarg); break;
            default: usage(); return 1;
        }
    }
    if (optind >= argc) { usage(); return 1; }
    const char* cmd = argv[optind];

    FileSystem fs;
    memset(&fs, 0, sizeof(fs));

    if (strcmp(cmd, "init") == 0) {
        if (!disk_image || strcmp(disk_image, "") == 0) {
            printf("No disk image specified! Use -d <disk_image>.\n");
            return 1;
        }
        if (fs_nodes <= 0) {
            printf("No disk size specified! Use -b <node_count>.\n");
            return 1;
        }
        if (!fs_init(&fs, (uint32_t)fs_nodes)) return 1;
        int ok = fs_write_image(&fs, disk_image);
        fs_free(&fs);
        return ok ? 0 : 1;
    }

    if (strcmp(cmd, "write") == 0) {
        if (argc < optind + 3) {
            printf("`write` needs: <os_file> <fs_name>\n");
            return 1;
        }
        const char* os_file = argv[optind + 1];
        const char* fs_name = argv[optind + 2];

        if (!fs_read_image(&fs, disk_image)) { printf("No disk image or empty.\n"); return 1; }

        size_t bytes = 0;
        uint8_t* data = fs_read_os_file(os_file, &bytes);
        if (!data) { printf("Input file not found.\n"); fs_free(&fs); return 1; }

        int ok = fs_write_file(&fs, fs_name, data, (uint64_t)bytes);
        free(data);
        if (!ok) { fs_free(&fs); return 1; }
        ok = fs_write_image(&fs, disk_image);
        fs_free(&fs);
        return ok ? 0 : 1;
    }

    if (strcmp(cmd, "read") == 0) {
        if (argc < optind + 2) { printf("`read` needs <fs_name>\n"); return 1; }
        const char* fs_name = argv[optind + 1];

        if (!fs_read_image(&fs, disk_image)) { printf("No disk image or empty.\n"); return 1; }

        uint64_t size = 0;
        uint8_t* buf = fs_read_file(&fs, fs_name, file_size_flag, &size);
        if (!file_size_flag && buf && size > 0) {
            fwrite(buf, 1, (size_t)size, stdout);
            fputc('\n', stdout);
        }
        free(buf);
        fs_free(&fs);
        return 0;
    }

    if (strcmp(cmd, "delete") == 0) {
        if (argc < optind + 2) { printf("`delete` needs <fs_name>\n"); return 1; }
        const char* fs_name = argv[optind + 1];

        if (!fs_read_image(&fs, disk_image)) { printf("No disk image or empty.\n"); return 1; }
        int ok = fs_delete_file(&fs, fs_name);
        if (!ok) { fs_free(&fs); return 1; }
        ok = fs_write_image(&fs, disk_image);
        fs_free(&fs);
        return ok ? 0 : 1;
    }

    if (strcmp(cmd, "exam") == 0) {
        if (!fs_read_image(&fs, disk_image)) { printf("No disk image or empty.\n"); return 1; }
        size_t n = fs_table_size(&fs);
        const FsNode* tab = fs_table(&fs);
        for (int i = 0; i <= 20 && i < (int)n; i++) {
            printf("%d\n", (int)tab[i].status);
        }
        fs_free(&fs);
        return 0;
    }

    usage();
    return 1;
}

