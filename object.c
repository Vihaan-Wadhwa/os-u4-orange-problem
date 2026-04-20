// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    // Step 1: Build the header string e.g. "blob 16\0"
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // header is e.g. "blob 16" + null byte
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    // header_len does NOT include the null terminator, but we want it in the object
    // so full object = header (with \0) + data
    size_t full_len = header_len + 1 + len;  // +1 for the '\0'

    // Allocate buffer for full object
    uint8_t *full = malloc(full_len);
    if (!full) return -1;

    // Copy header (including \0), then data
    memcpy(full, header, header_len + 1);    // copies "blob 16\0"
    memcpy(full + header_len + 1, data, len);

    // Step 2: Compute SHA-256 of the full object
    compute_hash(full, full_len, id_out);

    // Step 3: Deduplication — if object already exists, nothing to do
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Step 4: Create shard directory .pes/objects/XX/
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    // Make sure .pes/objects/ itself exists
    mkdir(OBJECTS_DIR, 0755);

    // Make the shard subdir e.g. .pes/objects/2f/
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);  // ignore error if already exists

    // Step 5: Final object path and a temp path in the same directory
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/%.2s/tmp_XXXXXX", OBJECTS_DIR, hex);

    // Create temp file using mkstemp (safe cross-platform temp file)
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Step 6: Write the full object to the temp file
    ssize_t written = write(fd, full, full_len);
    free(full);

    if (written < 0 || (size_t)written != full_len) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    // Step 7: fsync to flush data to disk
    if (fsync(fd) < 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    // Step 8: Atomically rename temp file to final path
    if (rename(tmp_path, final_path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    // Step 9: fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    // Step 1: Get the file path for this object
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(f);
        return -1;
    }

    uint8_t *buf = malloc((size_t)file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    // Step 3: Parse the header — find the '\0' that separates header from data
    uint8_t *null_ptr = memchr(buf, '\0', (size_t)file_size);
    if (!null_ptr) {
        free(buf);
        return -1;
    }

    // Header is everything before the '\0'
    // e.g. "blob 16"
    char *header = (char *)buf;
    size_t header_len = null_ptr - buf;  // length without the '\0'

    // Parse type from header
    if      (strncmp(header, "blob ",   5) == 0) *type_out = OBJ_BLOB;
    else if (strncmp(header, "tree ",   5) == 0) *type_out = OBJ_TREE;
    else if (strncmp(header, "commit ", 7) == 0) *type_out = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    // Parse the size from header (the number after the space)
    char *space = strchr(header, ' ');
    if (!space) {
        free(buf);
        return -1;
    }
    size_t declared_size = (size_t)atol(space + 1);

    // Data starts right after the '\0'
    uint8_t *data_start = null_ptr + 1;
    size_t data_len = (size_t)file_size - (header_len + 1);

    // Check declared size matches actual data length
    if (data_len != declared_size) {
        free(buf);
        return -1;
    }

    // Step 4: Verify integrity — recompute hash and compare to expected
    ObjectID computed;
    compute_hash(buf, (size_t)file_size, &computed);

    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // Step 5: Allocate output buffer and copy data portion
    *data_out = malloc(data_len);
    if (!*data_out) {
        free(buf);
        return -1;
    }
    memcpy(*data_out, data_start, data_len);
    *len_out = data_len;

    free(buf);
    return 0;
}