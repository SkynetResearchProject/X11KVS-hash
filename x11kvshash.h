#ifndef X11KVSHASH_H
#define X11KVSHASH_H

#ifdef __cplusplus
extern "C" {
#endif
void x11kvs_hash(const char* input, char* output);
void x11kvs_hash1(const char* input, char* output, const unsigned int level);
void HashX11KV(const char* input, char* output);
static inline void Hash(const char* hash, const char* hash1, const char* hash2, char* output);

#ifdef __cplusplus
}
#endif

#endif
