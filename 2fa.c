/*
 * 2FA TOTP Generator
 * Author: zhlhlf
 * Email: zhlhlf@gmail.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEPARATOR "\\"
#else
#include <unistd.h>
#define PATH_SEPARATOR "/"
#endif

#define MAX_URL_LEN 2048
#define MAX_SECRET_LEN 128
#define MAX_NAME_LEN 256
#define FILE_NAME ".2fa"

// --- SHA1 Implementation ---

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);

void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len) {
    uint32_t i, j;
    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) SHA1Transform(context->state, &data[i]);
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[20], SHA1_CTX *context) {
    unsigned char finalcount[8];
    uint32_t i;
    for (i = 0; i < 8; i++) finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    SHA1Update(context, (unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) SHA1Update(context, (unsigned char *)"\0", 1);
    SHA1Update(context, finalcount, 8);
    for (i = 0; i < 20; i++) digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00)|(rol(block->l[i],8)&0x00FF00FF))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    typedef union { unsigned char c[64]; uint32_t l[16]; } CHAR64LONG16;
    CHAR64LONG16* block = (CHAR64LONG16*)buffer;
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

// --- HMAC-SHA1 Implementation ---

void hmac_sha1(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result) {
    SHA1_CTX ctx;
    unsigned char k_ipad[65];
    unsigned char k_opad[65];
    unsigned char tk[20];
    int i;

    if (key_len > 64) {
        SHA1Init(&ctx);
        SHA1Update(&ctx, key, key_len);
        SHA1Final(tk, &ctx);
        key = tk;
        key_len = 20;
    }

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    SHA1Init(&ctx);
    SHA1Update(&ctx, k_ipad, 64);
    SHA1Update(&ctx, data, data_len);
    SHA1Final(result, &ctx);

    SHA1Init(&ctx);
    SHA1Update(&ctx, k_opad, 64);
    SHA1Update(&ctx, result, 20);
    SHA1Final(result, &ctx);
}

// --- Base32 Decoding ---

int base32_decode(const char *encoded, unsigned char *result) {
    int buffer = 0;
    int bits_left = 0;
    int count = 0;
    const char *ptr = encoded;

    while (*ptr) {
        uint8_t val;
        char c = toupper(*ptr);
        ptr++;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else if (c == '=' || c == ' ' || c == '\n' || c == '\r') continue;
        else return -1; // Invalid character

        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            result[count++] = (unsigned char)((buffer >> (bits_left - 8)) & 0xFF);
            bits_left -= 8;
        }
    }
    return count;
}

// --- URL Decoding ---

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

// --- TOTP Generation ---

uint32_t generate_totp(const char *secret_base32) {
    unsigned char key[128];
    int key_len = base32_decode(secret_base32, key);
    if (key_len < 0) return 0;

    time_t t = time(NULL);
    uint64_t time_step = t / 30;
    unsigned char msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (unsigned char)(time_step & 0xFF);
        time_step >>= 8;
    }

    unsigned char hash[20];
    hmac_sha1(key, key_len, msg, 8, hash);

    int offset = hash[19] & 0xF;
    uint32_t binary =
        ((hash[offset] & 0x7F) << 24) |
        ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) |
        (hash[offset + 3] & 0xFF);

    return binary % 1000000;
}

// --- File Operations ---

void get_file_path(char *path, size_t size) {
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
#else
    const char *home = getenv("HOME");
#endif
    if (!home) {
        fprintf(stderr, "Error: Could not determine home directory.\n");
        exit(1);
    }
    snprintf(path, size, "%s%s%s", home, PATH_SEPARATOR, FILE_NAME);
}

typedef struct {
    char name[MAX_NAME_LEN];
    char secret[MAX_SECRET_LEN];
} Account;

int load_accounts(Account *accounts, int max_accounts) {
    char path[1024];
    get_file_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && count < max_accounts) {
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        char *sep = strchr(line, '|');
        if (sep) {
            *sep = '\0';
            strncpy(accounts[count].name, line, MAX_NAME_LEN - 1);
            strncpy(accounts[count].secret, sep + 1, MAX_SECRET_LEN - 1);
            count++;
        }
    }
    fclose(f);
    return count;
}

void save_accounts(Account *accounts, int count) {
    char path[1024];
    get_file_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("Error opening file for writing");
        return;
    }
    for (int i = 0; i < count; i++) {
        fprintf(f, "%s|%s\n", accounts[i].name, accounts[i].secret);
    }
    fclose(f);
}

// --- Main Logic ---

void add_account() {
    Account accounts[100];
    int count = load_accounts(accounts, 100);
    
    printf("请输入 otpauth URL (每行一个，输入空行结束):\n");
    
    char url[MAX_URL_LEN];
    while (1) {
        if (!fgets(url, sizeof(url), stdin)) break;
        
        // Trim newline and whitespace from end
        size_t len = strlen(url);
        while (len > 0 && (url[len-1] == '\n' || url[len-1] == '\r' || isspace(url[len-1]))) {
            url[--len] = '\0';
        }

        if (len == 0) break;

        // Simple parsing
        // otpauth://totp/LABEL?parameters
        char *label_start = strstr(url, "otpauth://totp/");
        if (!label_start) {
            printf("Invalid URL format: %s\n", url);
            continue;
        }
        label_start += strlen("otpauth://totp/");
        
        char *param_start = strchr(label_start, '?');
        if (!param_start) {
            printf("Invalid URL format (no parameters): %s\n", url);
            continue;
        }

        char label_encoded[MAX_NAME_LEN] = {0};
        size_t label_len = param_start - label_start;
        if (label_len >= MAX_NAME_LEN) label_len = MAX_NAME_LEN - 1;
        strncpy(label_encoded, label_start, label_len);
        
        char label[MAX_NAME_LEN];
        url_decode(label, label_encoded);

        char secret[MAX_SECRET_LEN] = {0};
        char *p = param_start + 1;
        while (*p) {
            char *key = p;
            char *val = strchr(p, '=');
            if (!val) break;
            *val = '\0';
            val++;
            
            char *next = strchr(val, '&');
            if (next) {
                *next = '\0';
                p = next + 1;
            } else {
                p = val + strlen(val);
            }

            if (strcmp(key, "secret") == 0) {
                strncpy(secret, val, MAX_SECRET_LEN - 1);
            }
        }

        if (strlen(secret) == 0) {
            printf("Could not find secret in URL: %s\n", url);
            continue;
        }

        if (count >= 100) {
            printf("Account limit reached.\n");
            break;
        }

        strncpy(accounts[count].name, label, MAX_NAME_LEN - 1);
        strncpy(accounts[count].secret, secret, MAX_SECRET_LEN - 1);
        count++;
        printf("Added: %s\n", label);
    }
    save_accounts(accounts, count);
}

void delete_account() {
    Account accounts[100];
    int count = load_accounts(accounts, 100);
    if (count == 0) {
        printf("No accounts found.\n");
        return;
    }

    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, accounts[i].name);
    }

    int choice;
    printf("请输入要删除的序号: ");
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        return;
    }

    for (int i = choice - 1; i < count - 1; i++) {
        accounts[i] = accounts[i + 1];
    }
    count--;
    save_accounts(accounts, count);
    printf("Deleted.\n");
}

void list_accounts(int specific_index) {
    Account accounts[100];
    int count = load_accounts(accounts, 100);
    if (count == 0) {
        printf("No accounts found.\n");
        return;
    }

    time_t t = time(NULL);
    int remaining = 30 - (t % 30);

    if (specific_index > 0) {
        if (specific_index <= count) {
            uint32_t code = generate_totp(accounts[specific_index - 1].secret);
            printf("\033[0;32m%06u\033[0m (%ds)\n", code, remaining);
        } else {
            printf("Index out of range.\n");
        }
    } else {
        for (int i = 0; i < count; i++) {
            uint32_t code = generate_totp(accounts[i].secret);
            printf("%d. %s: \033[0;32m%06u\033[0m (%ds)\n", i + 1, accounts[i].name, code, remaining);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        list_accounts(0);
    } else if (strcmp(argv[1], "a") == 0) {
        add_account();
    } else if (strcmp(argv[1], "d") == 0) {
        delete_account();
    } else {
        int idx = atoi(argv[1]);
        if (idx > 0) {
            list_accounts(idx);
        } else {
            printf("Usage:\n");
            printf("  2fa        Show all codes\n");
            printf("  2fa a      Add account\n");
            printf("  2fa d      Delete account\n");
            printf("  2fa <num>  Show code for specific account\n");
            printf("\nCreated by zhlhlf (zhlhlf@gmail.com)\n");
        }
    }
    return 0;
}
