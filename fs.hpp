#pragma once
#include <cstdint>
#include <array>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static constexpr uint32_t NULL_NODE_ID = 0xFFFFFFFF;
static constexpr size_t FILE_NAME_SIZE = 32;
static constexpr size_t FILE_SIZE_SIZE = 8;
static constexpr size_t FILE_HEADER_SIZE = (FILE_SIZE_SIZE + FILE_NAME_SIZE);
static constexpr size_t DATA_BYTES_PER_NODE = 8192;
static constexpr size_t CHUNK_SIZE = 1024;
static constexpr size_t HASH_TABLE_SIZE = 32768;
static constexpr size_t DIR_ENTRIES_SIZE = 2051;
static constexpr size_t PATH_LIMIT = 16;

template <typename T>
inline T MIN(T a, T b) { return a < b ? a : b; }
template <typename T>
inline T MAX(T a, T b) { return a > b ? a : b; }

enum class NodeStatus : uint8_t {
    FREE,
    SINGLE_NODE_FILE,
    FILE_START,
    FILE_END,
    FILE_DATA,
    DIR_ENTRY,
    USED
};

struct DirEntry {
    char dir_name[FILE_NAME_SIZE];
    uint32_t entries[DIR_ENTRIES_SIZE];
};

struct HeaderFile {
    uint32_t next_id;
    char file_name[FILE_NAME_SIZE];
    uint64_t file_size;
    char data[DATA_BYTES_PER_NODE];
};

struct DataFile {
    uint32_t next_id;
    char data[DATA_BYTES_PER_NODE];
};

struct FsNode {
    NodeStatus status{};
    union {
        DirEntry      dir_entry;
        HeaderFile    header_file;
        DataFile      data_file;
    } data;
};

struct FsMeta {
    uint32_t smallest_id_deallocated_node = NULL_NODE_ID;
    uint32_t largest_id_allocated_node    = 0;
    uint32_t total_node_count             = 0;
    std::array<uint32_t, HASH_TABLE_SIZE> file_table{};
};

inline unsigned int hash_str(const char* s) {
    unsigned int h = 0;
    while (*s) { h = static_cast<unsigned char>(*s++) + 31 * h; }
    return h;
}
