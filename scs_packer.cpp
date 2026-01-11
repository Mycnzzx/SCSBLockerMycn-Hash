#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <zlib.h>

namespace fs = std::filesystem;

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr u64 BLOCK_SIZE = 16;

#pragma pack(push, 1)
struct HashFsV2Header {
    u32 magic;                       // "SCS#"
    u16 version;                     // 2
    u16 salt;                        // 0
    char hash_method[4];             // "CITY"
    u32 num_entries;
    u32 entry_table_length;
    u32 num_metadata_entries;
    u32 metadata_table_length;
    u64 entry_table_start;
    u64 metadata_table_start;
    u64 security_descriptor_offset;
    u32 platform;                    // 0 = PC
};
static_assert(sizeof(HashFsV2Header) == 56);

struct EntryTableEntry {
    u64 hash;
    u32 metadata_index;
    u16 metadata_count;
    u16 flags;
};
static_assert(sizeof(EntryTableEntry) == 16);
#pragma pack(pop)

// ------------------------------------------------------------
// Hash exatamente igual TruckLib (CityHash simplificado)
// ------------------------------------------------------------
u64 ScsHash(std::string path) {
    if (!path.empty() && path[0] == '/') path.erase(0, 1);
    std::transform(path.begin(), path.end(), path.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    for (char& c : path) if (c == '\\') c = '/';

    const u64 K1 = 0x9ddfea08eb382d69ULL;
    size_t len = path.size();
    const char* s = path.c_str();

    u64 hash = K1 ^ len;
    while (len >= 8) {
        u64 k;
        memcpy(&k, s, 8);
        k *= K1;
        k ^= k >> 47;
        k *= K1;
        hash ^= k;
        hash *= K1;
        s += 8;
        len -= 8;
    }
    return hash;
}

// ------------------------------------------------------------
// Metadata exatamente como MainMetadata.cs
// ------------------------------------------------------------
void write_metadata(std::vector<u8>& buf,
                    u32 cSize, u32 uSize,
                    u64 offset, bool compressed)
{
    buf.push_back(cSize & 0xFF);
    buf.push_back((cSize >> 8) & 0xFF);
    buf.push_back((cSize >> 16) & 0xFF);
    buf.push_back(((cSize >> 24) & 0x0F) | (compressed ? 0x10 : 0x00));

    buf.push_back(uSize & 0xFF);
    buf.push_back((uSize >> 8) & 0xFF);
    buf.push_back((uSize >> 16) & 0xFF);
    buf.push_back((uSize >> 24) & 0x0F);

    u32 unknown = 0;
    u32 offsetBlock = static_cast<u32>(offset / BLOCK_SIZE);

    for (int i = 0; i < 4; ++i) buf.push_back(reinterpret_cast<u8*>(&unknown)[i]);
    for (int i = 0; i < 4; ++i) buf.push_back(reinterpret_cast<u8*>(&offsetBlock)[i]);
}

void align16(std::ofstream& f) {
    while (f.tellp() % BLOCK_SIZE != 0)
        f.put(0);
}

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Uso: scs_packer <pasta_mod> <saida.scs>\n";
        return 1;
    }

    fs::path input = argv[1];
    fs::path output = argv[2];

    std::ofstream scs(output, std::ios::binary);
    if (!scs) {
        std::cerr << "Erro ao criar arquivo\n";
        return 1;
    }

    // Reserva espaço EXATO do header
    scs.seekp(sizeof(HashFsV2Header));

    struct Item { u64 hash; fs::path path; };
    std::vector<Item> files;

    for (auto& p : fs::recursive_directory_iterator(input)) {
        if (!p.is_regular_file()) continue;
        std::string rel = "/" + fs::relative(p.path(), input).generic_string();
        files.push_back({ ScsHash(rel), p.path() });
    }

    std::sort(files.begin(), files.end(),
              [](auto& a, auto& b){ return a.hash < b.hash; });

    std::vector<EntryTableEntry> entries;
    std::vector<u8> metaTable;

    for (u32 i = 0; i < files.size(); ++i) {
        std::ifstream in(files[i].path, std::ios::binary);
        std::vector<u8> raw((std::istreambuf_iterator<char>(in)), {});

        uLongf cSize = compressBound(raw.size());
        std::vector<u8> comp(cSize);
        compress(comp.data(), &cSize, raw.data(), raw.size());
        comp.resize(cSize);

        align16(scs);
        u64 dataOffset = scs.tellp();
        scs.write(reinterpret_cast<char*>(comp.data()), comp.size());

        entries.push_back({
            files[i].hash,
            i,
            1,
            0x4 // compressed
        });

        metaTable.push_back(128);
        metaTable.push_back(0);
        metaTable.push_back(0);
        metaTable.push_back(0);
        write_metadata(metaTable,
                       static_cast<u32>(comp.size()),
                       static_cast<u32>(raw.size()),
                       dataOffset,
                       true);
    }

    align16(scs);
    u64 entryStart = scs.tellp();
    scs.write(reinterpret_cast<char*>(entries.data()),
              entries.size() * sizeof(EntryTableEntry));

    align16(scs);
    u64 metaStart = scs.tellp();
    scs.write(reinterpret_cast<char*>(metaTable.data()), metaTable.size());

    HashFsV2Header h{};
    memcpy(&h.magic, "SCS#", 4);
    h.version = 2;
    memcpy(h.hash_method, "CITY", 4);
    h.num_entries = h.num_metadata_entries = static_cast<u32>(entries.size());
    h.entry_table_start = entryStart;
    h.entry_table_length = entries.size() * sizeof(EntryTableEntry);
    h.metadata_table_start = metaStart;
    h.metadata_table_length = metaTable.size();
    h.security_descriptor_offset = 0;
    h.platform = 0;

    scs.seekp(0);
    scs.write(reinterpret_cast<char*>(&h), sizeof(h));

    std::cout << "SCS HashFS V2 gerado com sucesso\n";
    return 0;
}
