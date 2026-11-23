/* Synthetic triage fixture for r2brief-core. Original code, MIT licensed.
 * It exists only to give the ELF triage evaluation a binary with a known
 * function list: direct calls, address-taken handlers that are never called
 * directly, recursion, a jump-table switch, constructors, and calls to the
 * imports r2b treats as sinks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NOINLINE __attribute__((noinline))

typedef int (*handler_fn)(const char *arg, char *out, size_t cap);

static volatile int g_sink;
static char g_banner[64];

NOINLINE static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

NOINLINE static uint32_t rotl32(uint32_t v, unsigned r) { return (v << (r & 31)) | (v >> ((32 - r) & 31)); }

NOINLINE static uint32_t mix(uint32_t a, uint32_t b) { return rotl32(a ^ b, 7) * 0x9e3779b1u; }

NOINLINE static unsigned long fib(unsigned n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

NOINLINE static int is_even(unsigned n);
NOINLINE static int is_odd(unsigned n) { return n == 0 ? 0 : is_even(n - 1); }
NOINLINE static int is_even(unsigned n) { return n == 0 ? 1 : is_odd(n - 1); }

NOINLINE static int classify(int c) {
    switch (c) {
    case 'a': return 11; case 'b': return 23; case 'c': return 37;
    case 'd': return 41; case 'e': return 53; case 'f': return 67;
    case 'g': return 79; case 'h': return 83; case 'i': return 97;
    default: return -1;
    }
}

NOINLINE static size_t count_class(const char *s) {
    size_t n = 0;
    for (; *s; s++) if (classify(*s) > 0) n++;
    return n;
}

/* Handlers below are reached only through the table: no direct call sites. */
NOINLINE static int h_copy(const char *arg, char *out, size_t cap) {
    if (strlen(arg) >= cap) return -1;
    strcpy(out, arg);
    return (int)strlen(out);
}

NOINLINE static int h_append(const char *arg, char *out, size_t cap) {
    if (strlen(out) + strlen(arg) >= cap) return -1;
    strcat(out, arg);
    return (int)strlen(out);
}

NOINLINE static int h_format(const char *arg, char *out, size_t cap) {
    if (cap < 32) return -1;
    return sprintf(out, "%08x:%s", fnv1a(arg), arg[0] ? "set" : "empty");
}

NOINLINE static int h_hash(const char *arg, char *out, size_t cap) {
    uint32_t h = mix(fnv1a(arg), (uint32_t)cap);
    return snprintf(out, cap, "%u", h);
}

NOINLINE static int h_blit(const char *arg, char *out, size_t cap) {
    size_t n = strlen(arg);
    if (n > cap) n = cap;
    memcpy(out, arg, n);
    return (int)n;
}

NOINLINE static int h_shift(const char *arg, char *out, size_t cap) {
    size_t n = strlen(arg);
    if (n + 1 > cap) return -1;
    memmove(out + 1, arg, n);
    out[0] = '>';
    return (int)n + 1;
}

NOINLINE static int h_fib(const char *arg, char *out, size_t cap) {
    return snprintf(out, cap, "%lu", fib((unsigned)strlen(arg) % 20));
}

NOINLINE static int h_parity(const char *arg, char *out, size_t cap) {
    return snprintf(out, cap, "%s", is_even((unsigned)strlen(arg)) ? "even" : "odd");
}

NOINLINE static int h_count(const char *arg, char *out, size_t cap) {
    return snprintf(out, cap, "%zu", count_class(arg));
}

NOINLINE static int h_run(const char *arg, char *out, size_t cap) {
    (void)out; (void)cap;
    if (getenv("R2B_FIXTURE_ALLOW_SYSTEM") == NULL) return 0;
    return system(arg);
}

struct command { const char *name; handler_fn fn; };

static const struct command k_commands[] = {
    {"copy", h_copy}, {"append", h_append}, {"format", h_format},
    {"hash", h_hash}, {"blit", h_blit}, {"shift", h_shift},
    {"fib", h_fib}, {"parity", h_parity}, {"count", h_count},
    {"run", h_run},
};

NOINLINE static const struct command *lookup(const char *name) {
    for (size_t i = 0; i < sizeof k_commands / sizeof k_commands[0]; i++)
        if (strcmp(k_commands[i].name, name) == 0) return &k_commands[i];
    return NULL;
}

struct node { int key; struct node *left, *right; };

NOINLINE static struct node *node_new(int key) {
    struct node *n = calloc(1, sizeof *n);
    if (n) n->key = key;
    return n;
}

NOINLINE static struct node *tree_insert(struct node *root, int key) {
    if (!root) return node_new(key);
    if (key < root->key) root->left = tree_insert(root->left, key);
    else root->right = tree_insert(root->right, key);
    return root;
}

NOINLINE static int tree_height(const struct node *n) {
    if (!n) return 0;
    int l = tree_height(n->left), r = tree_height(n->right);
    return 1 + (l > r ? l : r);
}

NOINLINE static long tree_sum(const struct node *n) { return n ? n->key + tree_sum(n->left) + tree_sum(n->right) : 0; }

NOINLINE static void tree_free(struct node *n) {
    if (!n) return;
    tree_free(n->left);
    tree_free(n->right);
    free(n);
}

NOINLINE static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

NOINLINE static long sorted_checksum(int *v, size_t n) {
    qsort(v, n, sizeof *v, cmp_int);
    long acc = 0;
    for (size_t i = 0; i < n; i++) acc = acc * 31 + v[i];
    return acc;
}

NOINLINE static void selftest(void) {
    int v[16];
    struct node *root = NULL;
    for (int i = 0; i < 16; i++) { v[i] = (int)(mix((uint32_t)i, 0x1234u) % 1000u); root = tree_insert(root, v[i]); }
    g_sink = tree_height(root) + (int)tree_sum(root) + (int)sorted_checksum(v, 16);
    tree_free(root);
}

__attribute__((constructor)) NOINLINE static void fixture_ctor(void) {
    snprintf(g_banner, sizeof g_banner, "r2b-fixture %u", (unsigned)fnv1a("ctor"));
}

__attribute__((destructor)) NOINLINE static void fixture_dtor(void) { g_sink ^= 0x5a5a; }

NOINLINE static void usage(const char *argv0) {
    fprintf(stderr, "%s\nusage: %s COMMAND ARG\n", g_banner, argv0);
}

int main(int argc, char **argv) {
    char out[128] = {0};
    selftest();
    if (argc < 3) { usage(argv[0]); return 2; }
    const struct command *cmd = lookup(argv[1]);
    if (!cmd) { usage(argv[0]); return 2; }
    int rc = cmd->fn(argv[2], out, sizeof out);
    puts(out);
    return rc < 0 ? 1 : 0;
}
