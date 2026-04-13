#include <stdint.h>
#include <string.h>
#include <emscripten.h>

#define KECCAK_ROUNDS 24
#define RATE_BYTES 136

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

EMSCRIPTEN_KEEPALIVE
static uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

EMSCRIPTEN_KEEPALIVE
static void keccak_f(uint64_t state[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (int i = 0; i < 25; i++)
            state[i] ^= D[i%5];

        // Rho and Pi
        uint64_t current = state[1];
        int x = 1, y = 0;
        for (int t = 0; t < 24; t++) {
            int nx = y;
            int ny = (2*x + 3*y) % 5;
            uint64_t tmp = state[nx + 5*ny];
            state[nx + 5*ny] = rotl64(current, (t+1)*(t+2)/2 % 64);
            current = tmp;
            x = nx; y = ny;
        }

        // Chi
        for (int y = 0; y < 5; y++) {
            int base = y*5;
            uint64_t row0 = state[base];
            uint64_t row1 = state[base+1];
            uint64_t row2 = state[base+2];
            uint64_t row3 = state[base+3];
            uint64_t row4 = state[base+4];
            state[base]   = row0 ^ ((~row1) & row2);
            state[base+1] = row1 ^ ((~row2) & row3);
            state[base+2] = row2 ^ ((~row3) & row4);
            state[base+3] = row3 ^ ((~row4) & row0);
            state[base+4] = row4 ^ ((~row0) & row1);
        }

        // Iota
        state[0] ^= RC[round];
    }
}

EMSCRIPTEN_KEEPALIVE
void shake256(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t output_len) {
    uint64_t state[25] = {0};
    uint32_t offset = 0;

    // Absorb
    while (offset < input_len) {
        uint32_t block = (input_len - offset) < RATE_BYTES ? (input_len - offset) : RATE_BYTES;
        for (uint32_t i = 0; i < block; i++) {
            int lane = i >> 3;
            int shift = (i & 7) << 3;
            state[lane] ^= ((uint64_t)input[offset + i]) << shift;
        }
        offset += block;
        if (block == RATE_BYTES || offset == input_len) {
            if (offset == input_len) {
                // padding
                int last = block;
                int lane = last >> 3;
                int shift = (last & 7) << 3;
                state[lane] ^= ((uint64_t)0x1F) << shift; // domain separation
                last++;
                lane = last >> 3;
                shift = (last & 7) << 3;
                state[lane] ^= ((uint64_t)0x80) << shift;
            }
            keccak_f(state);
        }
    }

    // Squeeze
    offset = 0;
    while (offset < output_len) {
        for (int i = 0; i < 25 && offset < output_len; i++) {
            uint64_t word = state[i];
            for (int j = 0; j < 8 && offset < output_len; j++) {
                output[offset++] = word & 0xFF;
                word >>= 8;
            }
        }
        if (offset < output_len) keccak_f(state);
    }
}