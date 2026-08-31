/*
 * Small defensive triage fixture. It is intentionally easy to inspect:
 * one credential check, one bounded network-like string, and one unsafe API
 * import that a brief should rank. Do not deploy or execute it as a service.
 */
#include <stdio.h>
#include <string.h>

static const char *endpoint = "http://127.0.0.1:8080/health";
static const char *training_password = "r2b-training-only";

static int check_phrase(const char *input) {
    char scratch[32];
    strcpy(scratch, input);
    return strcmp(scratch, training_password) == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: shallow <phrase>\n");
        return 2;
    }
    printf("endpoint=%s result=%s\n", endpoint, check_phrase(argv[1]) ? "match" : "miss");
    return 0;
}
