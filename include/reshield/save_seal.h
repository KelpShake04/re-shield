#ifndef RESHIELD_SAVE_SEAL_H
#define RESHIELD_SAVE_SEAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Save/config file seal: an HMAC-SHA256 tag you store next to the data, to notice casual edits
 * and corruption of a save or settings file.
 *
 * WHAT THIS IS NOT. The key has to live in your game binary, so anyone who can read the binary
 * or the process memory can recover it and forge a valid tag. This detects a player editing a
 * save in a hex editor or a text editor, a truncated write, and a half-synced cloud file. It does
 * NOT stop a determined attacker, and it proves nothing about who wrote the file. For anything
 * with stakes (leaderboards, online rewards, multiplayer) the server must own the state.
 * See docs/save-seal.md.
 *
 * All functions are pure computation: no I/O, no allocation, no global state, safe to call from
 * any thread. Verification time does not depend on how many bytes of a tag matched.
 */

#define RESHIELD_SAVE_TAG_SIZE 32u

/**
 * HMAC-SHA256 (RFC 2104 / RFC 4231), built on the library's own SHA-256.
 * A key longer than 64 bytes is hashed first, as the RFC requires.
 * `msg` may be NULL only when msg_len is 0.
 * Returns 0 on success, -1 on invalid arguments: NULL key or out, key_len 0 (an empty key is
 * refused on purpose, it is almost always a bug), msg NULL with msg_len > 0, or a message so
 * long that SHA-256's 64-bit length counter cannot represent it. `out` is untouched on failure.
 */
int reshield_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t out[32]);

/**
 * Tag for a save blob: HMAC-SHA256(key, "reshield-save-v1\0" || data). The prefix separates
 * these tags from any other HMAC you compute with the same key. `data` may be NULL only when
 * len is 0 (an empty save is valid). Same return values as reshield_hmac_sha256().
 */
int reshield_save_tag(const uint8_t *key, size_t key_len,
                      const void *data, size_t len,
                      uint8_t out_tag[32]);

/**
 * Recomputes the tag and compares it with `tag` in constant time.
 * Returns 1 if they match, 0 if not, -1 on invalid arguments (same rules as
 * reshield_save_tag(), plus a NULL `tag`). Treat -1 as "could not check", not as "edited".
 */
int reshield_save_verify(const uint8_t *key, size_t key_len,
                         const void *data, size_t len,
                         const uint8_t tag[32]);

#ifdef __cplusplus
}
#endif

#endif /* RESHIELD_SAVE_SEAL_H */
