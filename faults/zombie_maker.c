// Creates N zombies: children exit, parent never calls wait(). Auto-exits after SECS.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 25;
    int secs = argc > 2 ? atoi(argv[2]) : 90;
    for (int i = 0; i < n; i++) {
        if (fork() == 0) _exit(0);
    }
    printf("parent pid %d created %d zombies, sleeping %ds\n", getpid(), n, secs);
    fflush(stdout);
    sleep(secs);
    return 0;
}