#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define NUM_ELEMENTS 10000000
#define NUM_RUNS 10

typedef struct {
    size_t start;
    size_t end;
} regmatch_t;

typedef struct {
    size_t start;
    size_t end;
} match_flat_t;

int main() {
    match_flat_t *arr_flat = malloc(NUM_ELEMENTS * sizeof(match_flat_t));

    // Flat 1D regmatch_t array allocating all matches' subexpressions sequentially
    regmatch_t *arr_rm_1d = malloc(NUM_ELEMENTS * 10 * sizeof(regmatch_t));

    for (size_t i = 0; i < NUM_ELEMENTS; i++) {
        arr_flat[i].start = i;
        arr_flat[i].end = i + 5;
        // Accessing first subexpression of each match i in flat 1D array: arr_rm_1d[i * 10]
        arr_rm_1d[i * 10].start = i;
        arr_rm_1d[i * 10].end = i + 5;
    }

    // Test flat AoS + flat 1D RM traversal (reading start, end, and rm[0] to simulate backreferences)
    double total_time_flat_with_rm = 0;
    for (int run = 0; run < NUM_RUNS; run++) {
        clock_t start = clock();
        size_t sum = 0;
        for (size_t i = 0; i < NUM_ELEMENTS; i++) {
            sum += arr_flat[i].start + arr_flat[i].end + arr_rm_1d[i * 10].start + arr_rm_1d[i * 10].end;
        }
        clock_t end = clock();
        total_time_flat_with_rm += (double)(end - start) / CLOCKS_PER_SEC;
        if (sum == 0xDEADBEEF) printf("sum: %sum\n");
    }

    printf("Flat + 1D RM avg time (simulating backrefs): %f seconds\n", total_time_flat_with_rm / NUM_RUNS);

    free(arr_flat);
    free(arr_rm_1d);
    return 0;
}
