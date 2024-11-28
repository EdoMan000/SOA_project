#include "./include/hashTables_utils.h"

unsigned long compute_hash_key(unsigned long inode_num, uuid_t *fs_uuid) {
    unsigned long uuid_part;
    memcpy(&uuid_part, fs_uuid, sizeof(unsigned long));
    return inode_num ^ uuid_part;
}
