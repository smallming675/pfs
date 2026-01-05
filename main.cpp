#include "fs.cpp"
#include <getopt.h>
#include <iostream>

static void usage() {
    std::cout << "Usage:\n"
              << "  -d <disk_image>\n"
              << "  -b <node_count>\n"
              << "Commands:\n"
              << "  init\n"
              << "  write <os_file> <fs_name>\n"
              << "  read  <fs_name> [-s]\n"
              << "  delete <fs_name>\n"
              << "  exam\n";
}

int main(int argc, char** argv) {
    int opt = 0;
    bool file_size_flag = false;
    int fs_nodes = 0;
    const char* disk_image = "";

    while ((opt = getopt(argc, argv, "sd:b:")) != -1) {
        switch (opt) {
            case 's': file_size_flag = true; break;
            case 'd': disk_image = optarg; break;
            case 'b': fs_nodes = std::atoi(optarg); break;
            default: usage(); return 1;
        }
    }
    if (optind >= argc) { usage(); return 1; }
    std::string cmd = argv[optind];

    try {
        if (cmd == "init") {
            if (!disk_image || std::strcmp(disk_image, "") == 0) {
                std::printf("No disk image specified! Use -d <disk_image>.\n");
                return 1;
            }
            if (fs_nodes <= 0) {
                std::printf("No disk size specified! Use -b <node_count>.\n");
                return 1;
            }
            FileSystem fs(fs_nodes);
            if (!fs.write_image(disk_image)) return 1;
            return 0;
        }

        if (cmd == "write") {
            if (argc < optind + 3) {
                std::printf("`write` needs: <os_file> <fs_name>\n");
                return 1;
            }
            const char* os_file = argv[optind + 1];
            const char* fs_name = argv[optind + 2];

            auto img = FileSystem::read_os_file(disk_image);
            if (img.empty()) { std::printf("No disk image or empty.\n"); return 1; }
            auto fs = FileSystem::from_image(img.data(), img.size());

            auto data = FileSystem::read_os_file(os_file);
            if (data.empty()) { std::printf("Input file not found.\n"); return 1; }

            if (!fs.write_file(fs_name, data.data(), data.size())) return 1;
            if (!fs.write_image(disk_image)) return 1;
            return 0;
        }

        if (cmd == "read") {
            if (argc < optind + 2) { std::printf("`read` needs <fs_name>\n"); return 1; }
            const char* fs_name = argv[optind + 1];

            auto img = FileSystem::read_os_file(disk_image);
            if (img.empty()) { std::printf("No disk image or empty.\n"); return 1; }
            auto fs = FileSystem::from_image(img.data(), img.size());

            auto buf = fs.read_file(fs_name, file_size_flag);
            if (!file_size_flag && !buf.empty()) {
                std::cout.write(reinterpret_cast<const char*>(buf.data()), buf.size());
                std::cout << "\n";
            }
            return 0;
        }

        if (cmd == "delete") {
            if (argc < optind + 2) { std::printf("`delete` needs <fs_name>\n"); return 1; }
            const char* fs_name = argv[optind + 1];

            auto img = FileSystem::read_os_file(disk_image);
            if (img.empty()) { std::printf("No disk image or empty.\n"); return 1; }
            auto fs = FileSystem::from_image(img.data(), img.size());

            if (!fs.delete_file(fs_name)) return 1;
            if (!fs.write_image(disk_image)) return 1;
            return 0;
        }

        if (cmd == "exam") {
            auto img = FileSystem::read_os_file(disk_image);
            if (img.empty()) { std::printf("No disk image or empty.\n"); return 1; }
            auto fs = FileSystem::from_image(img.data(), img.size());
            for (int i = 0; i <= 20 && i < (int)fs.table().size(); i++) {
                std::printf("%d\n", (int)fs.table()[i].status);
            }
            return 0;
        }

        usage();
        return 1;

    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

