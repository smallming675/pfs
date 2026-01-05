#pragma once
#include "fs.hpp"
#include "logger.cpp"
#include <stdexcept>

class FileSystem {
public:
    explicit FileSystem(uint32_t nodes)
    : meta_(), table_(nodes) {
        meta_.total_node_count = nodes;
        meta_.smallest_id_deallocated_node = NULL_NODE_ID;
        meta_.largest_id_allocated_node = 0;

        // init root dir at node 0
        if (nodes == 0) throw std::runtime_error("No nodes");
        table_[0].status = NodeStatus::DIR_ENTRY;
        std::memset(table_[0].data.dir_entry.dir_name, 0, FILE_NAME_SIZE);
        std::strncpy(table_[0].data.dir_entry.dir_name, "root", FILE_NAME_SIZE);
        // mark remaining as FREE
        for (uint32_t i = 1; i < nodes; ++i) {
            table_[i].status = NodeStatus::FREE;
        }
    }

    // Load from raw image (memory buffer)
    static FileSystem from_image(void* buffer, size_t bytes) {
        if (bytes < sizeof(FsMeta)) throw std::runtime_error("Image too small");
        auto* meta = reinterpret_cast<FsMeta*>(buffer);
        size_t nodes = meta->total_node_count;
        size_t expected = sizeof(FsMeta) + nodes * sizeof(FsNode);
        if (bytes < expected) throw std::runtime_error("Corrupt image");

        FileSystem fs(nodes);
        fs.meta_ = *meta;
        auto* node_base = reinterpret_cast<uint8_t*>(buffer) + sizeof(FsMeta);
        std::memcpy(fs.table_.data(), node_base, nodes * sizeof(FsNode));
        return fs;
    }

    // Serialize to raw image (allocates buffer)
    std::vector<uint8_t> to_image() const {
        std::vector<uint8_t> out(sizeof(FsMeta) + table_.size() * sizeof(FsNode));
        std::memcpy(out.data(), &meta_, sizeof(FsMeta));
        std::memcpy(out.data() + sizeof(FsMeta), table_.data(), table_.size() * sizeof(FsNode));
        return out;
    }

    // OS file I/O helpers
    static size_t get_file_size(const char* filename) {
        struct stat st{};
        if (stat(filename, &st) != 0) { perror("stat"); return size_t(-1); }
        return st.s_size;
    }

    static std::vector<uint8_t> read_os_file(const char* filename) {
        FILE* f = std::fopen(filename, "rb");
        if (!f) { perror("fopen"); return {}; }
        std::vector<uint8_t> buf; buf.reserve(CHUNK_SIZE);
        uint8_t chunk[CHUNK_SIZE];
        size_t n;
        while ((n = std::fread(chunk, 1, CHUNK_SIZE, f)) > 0) {
            buf.insert(buf.end(), chunk, chunk + n);
        }
        if (std::ferror(f)) { perror("fread"); buf.clear(); }
        std::fclose(f);
        return buf;
    }

    static bool write_os_file(const char* filename, const std::vector<uint8_t>& data) {
        int fd = ::open(filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) { perror("open"); return false; }
        ssize_t w = ::write(fd, data.data(), data.size());
        if (w < 0 || static_cast<size_t>(w) != data.size()) { perror("write"); ::close(fd); return false; }
        ::close(fd);
        return true;
    }

    // Node allocator/deallocator
    uint32_t allocate_node() {
        if (meta_.smallest_id_deallocated_node != NULL_NODE_ID) {
            uint32_t id = meta_.smallest_id_deallocated_node;
            table_[id].status = NodeStatus::USED;
            // advance smallest free
            uint32_t next = NULL_NODE_ID;
            for (uint32_t i = id + 1; i <= meta_.largest_id_allocated_node; ++i) {
                if (table_[i].status == NodeStatus::FREE) { next = i; break; }
            }
            meta_.smallest_id_deallocated_node = next;
            return id;
        }
        // extend allocation window
        if (meta_.largest_id_allocated_node + 1 >= meta_.total_node_count) {
            return NULL_NODE_ID;
        }
        uint32_t id = ++meta_.largest_id_allocated_node;
        table_[id].status = NodeStatus::USED;
        return id;
    }

    void deallocate_node(uint32_t id) {
        if (id >= table_.size()) return;
        auto& node = table_[id];
        if (node.status == NodeStatus::FREE) return;
        node.status = NodeStatus::FREE;

        if (meta_.smallest_id_deallocated_node == NULL_NODE_ID ||
            id < meta_.smallest_id_deallocated_node) {
            meta_.smallest_id_deallocated_node = id;
        }
        if (id == meta_.largest_id_allocated_node && meta_.largest_id_allocated_node > 0) {
            meta_.largest_id_allocated_node--;
        }
    }

    // Lookup
    uint32_t find_file_node(const char* name) const {
        unsigned idx = hash_str(name) % HASH_TABLE_SIZE;
        uint32_t stored = meta_.file_table[idx];
        if (stored != 0) return stored - 1; 
        return NULL_NODE_ID;
    }

    // Create file
    bool create_file(const char* name, const uint8_t* data, uint64_t size) {
Logger::log(LogLevel::INFO, "Attempting to create file: " + std::string(name));
        uint32_t head_id = allocate_node();
        if (head_id == NULL_NODE_ID) { 
          std::printf("Error: No free node.\n"); return false; }

        unsigned idx = hash_str(name) % HASH_TABLE_SIZE;
        meta_.file_table[idx] = head_id + 1;

        FsNode& head = table_[head_id];
        head.status = NodeStatus::SINGLE_NODE_FILE;
        std::memset(head.data.header_file.file_name, 0, FILE_NAME_SIZE);
        std::strncpy(head.data.header_file.file_name, name, FILE_NAME_SIZE);
        head.data.header_file.file_size = size;
        head.data.header_file.next_id = NULL_NODE_ID;

        if (size <= DATA_BYTES_PER_NODE) {
            std::memcpy(head.data.header_file.data, data, size);
            std::printf("New single-node file created.\n");
            return true;
        }

        // Multi-node
        head.status = NodeStatus::FILE_START;
        uint64_t bytes_written = 0;
        uint64_t first_chunk = MIN<uint64_t>(DATA_BYTES_PER_NODE, size);
        std::memcpy(head.data.header_file.data, data, first_chunk);
        bytes_written += first_chunk;

        uint32_t cur_id = allocate_node();
        if (cur_id == NULL_NODE_ID) { std::printf("Error: No free node.\n"); return false; }
        head.data.header_file.next_id = cur_id;

        while (bytes_written < size) {
            FsNode& cur = table_[cur_id];
            uint64_t chunk = MIN<uint64_t>(DATA_BYTES_PER_NODE, size - bytes_written);
            std::memcpy(cur.data.data_file.data, data + bytes_written, chunk);
            bytes_written += chunk;

            if (bytes_written >= size) {
                cur.status = NodeStatus::FILE_END;
                cur.data.data_file.next_id = NULL_NODE_ID;
                break;
            } else {
                cur.status = NodeStatus::FILE_DATA;
                uint32_t next_id = allocate_node();
                if (next_id == NULL_NODE_ID) { std::printf("Error: No free node.\n"); return false; }
                cur.data.data_file.next_id = next_id;
                cur_id = next_id;
            }
        }

        std::printf("New file created with multiple nodes.\n");
        return true;
    }

    // Write file (overwrite or create)
    bool write_file(const char* name, const uint8_t* data, uint64_t size) {
Logger::log(LogLevel::INFO, "Attempting to create file: " + std::string(name));
        uint32_t head_id = find_file_node(name);
        if (head_id == NULL_NODE_ID) {
Logger::log(LogLevel::INFO, "File not found,! Creating a new file...\n");
            return create_file(name, data, size);
        }

        FsNode& head = table_[head_id];
        std::memset(head.data.header_file.file_name, 0, FILE_NAME_SIZE);
        std::strncpy(head.data.header_file.file_name, name, FILE_NAME_SIZE);
        head.data.header_file.file_size = size;

        uint64_t bytes_written = 0;

        if (size <= DATA_BYTES_PER_NODE) {
            head.status = NodeStatus::SINGLE_NODE_FILE;
            std::memcpy(head.data.header_file.data, data, size);
            cleanup_chain(head.data.header_file.next_id); // free old chain
            head.data.header_file.next_id = NULL_NODE_ID;
            std::printf("Wrote single-node file.\n");
            return true;
        }

        // Ensure a chain exists
        if (head.status == NodeStatus::SINGLE_NODE_FILE || head.data.header_file.next_id == NULL_NODE_ID) {
            uint32_t first = allocate_node();
            if (first == NULL_NODE_ID) { std::printf("Error: No free nodes.\n"); return false; }
            head.data.header_file.next_id = first;
            table_[first].status = NodeStatus::FILE_END; // temporary sentinel
        }

        head.status = NodeStatus::FILE_START;
        uint64_t first_chunk = MIN<uint64_t>(DATA_BYTES_PER_NODE, size);
        std::memcpy(head.data.header_file.data, data, first_chunk);
        bytes_written += first_chunk;

        uint32_t cur_id = head.data.header_file.next_id;

        while (bytes_written < size) {
            FsNode& cur = table_[cur_id];
            uint64_t chunk = MIN<uint64_t>(DATA_BYTES_PER_NODE, size - bytes_written);
            std::memcpy(cur.data.data_file.data, data + bytes_written, chunk);
            bytes_written += chunk;

            if (bytes_written >= size) {
                cur.status = NodeStatus::FILE_END;
                // free any remainder of old chain
                cleanup_chain(cur.data.data_file.next_id);
                cur.data.data_file.next_id = NULL_NODE_ID;
                break;
            }

            // Need a next node
            if (cur.status == NodeStatus::FILE_END) {
                uint32_t next = allocate_node();
                if (next == NULL_NODE_ID) { std::printf("Error: No free nodes.\n"); return false; }
                cur.data.data_file.next_id = next;
                cur.status = NodeStatus::FILE_DATA;
                table_[next].status = NodeStatus::FILE_END;
            }
            cur_id = cur.data.data_file.next_id;
        }

        std::printf("Data written successfully.\n");
        return true;
    }

    // Read file content or metadata
    std::vector<uint8_t> read_file(const char* name, bool meta_only = false) const {
        uint32_t head_id = find_file_node(name);
        if (head_id == NULL_NODE_ID) {
            std::printf("File not found: %s\n", name);
            return {};
        }

        const FsNode* node = &table_[head_id];
        uint64_t size = node->data.header_file.file_size;
        std::vector<uint8_t> buf;
        buf.resize(size);

        uint64_t bytes_read = 0;
        // header chunk
        uint64_t chunk = MIN<uint64_t>(DATA_BYTES_PER_NODE, size);
        std::memcpy(buf.data(), node->data.header_file.data, chunk);
        bytes_read += chunk;

        if (node->status == NodeStatus::SINGLE_NODE_FILE || bytes_read >= size) {
            if (meta_only) {
                std::printf("File size: %llu, node count: 1\n", (unsigned long long)size);
                return {};
            }
            return buf;
        }

        // traverse chain
        uint32_t cur = node->data.header_file.next_id;
        size_t node_count = 1;
        while (cur != NULL_NODE_ID && bytes_read < size) {
            const FsNode* d = &table_[cur];
            uint64_t chunk2 = MIN<uint64_t>(DATA_BYTES_PER_NODE, size - bytes_read);
            std::memcpy(buf.data() + bytes_read, d->data.data_file.data, chunk2);
            bytes_read += chunk2;
            node_count++;
            if (d->status == NodeStatus::FILE_END || bytes_read >= size) break;
            cur = d->data.data_file.next_id;
        }

        if (meta_only) {
            std::printf("File size: %llu, node count: %zu\n", (unsigned long long)size, node_count);
            return {};
        }
        return buf;
    }

    // Delete file
    bool delete_file(const char* name) {
        uint32_t head_id = find_file_node(name);
        if (head_id == NULL_NODE_ID) { std::printf("Error: file not found.\n"); return false; }

        FsNode& head = table_[head_id];
        // clear hash entry
        meta_.file_table[hash_str(name) % HASH_TABLE_SIZE] = 0;

        if (head.status == NodeStatus::SINGLE_NODE_FILE) {
            deallocate_node(head_id);
            std::printf("Deleted single node file.\n");
            return true;
        }

        // Free chain including tail
        uint32_t cur = head.data.header_file.next_id;
        deallocate_node(head_id);
        while (cur != NULL_NODE_ID) {
            uint32_t next = table_[cur].data.data_file.next_id;
            deallocate_node(cur);
            cur = next;
        }
        std::printf("Deleted file.\n");
        return true;
    }

    // Persist image
    bool write_image(const char* filename) const {
        auto img = to_image();
        return write_os_file(filename, img);
    }

    // Load image
    static FileSystem read_image(const char* filename) {
        auto buf = read_os_file(filename);
        if (buf.empty()) throw std::runtime_error("read_image failed");
        return FileSystem::from_image(buf.data(), buf.size());
    }

    const FsMeta& meta() const { return meta_; }
    FsMeta& meta() { return meta_; }
    const std::vector<FsNode>& table() const { return table_; }
    std::vector<FsNode>& table() { return table_; }

private:
    // Free a linked list starting at id (inclusive)
    void cleanup_chain(uint32_t start_id) {
        uint32_t cur = start_id;
        while (cur != NULL_NODE_ID) {
            uint32_t next = table_[cur].data.data_file.next_id;
            deallocate_node(cur);
            cur = next;
        }
    }

    FsMeta meta_;
    std::vector<FsNode> table_;
};

