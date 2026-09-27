#include <Foundation/Foundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
static void hb_init(void) {
    // Marker in den App-eigenen Container (sandbox-schreibbar)
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"?";
    FILE *m = fopen([[NSHomeDirectory() stringByAppendingPathComponent:@"hb_injected.txt"] UTF8String], "a");
    if (m) {
        fprintf(m, "%ld ctor lief in %s\n", (long)time(NULL), [bid UTF8String]);
        fclose(m);
    }
    // Loopback-TCP 8788 binden (sandbox-freundlicher ctor-Beweis)
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(8788);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            listen(fd, 8);
        } else {
            close(fd);
        }
    }
}
