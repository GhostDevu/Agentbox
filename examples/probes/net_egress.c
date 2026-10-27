/* Probe network egress: non-blocking connect to 1.1.1.1:53. An empty net
 * namespace fails (CONTAINED); real egress succeeds (CROSSED). Benign: sends nothing. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { printf("CONTAINED: socket() failed\n"); return 0; }
    fcntl(s, F_SETFL, O_NONBLOCK);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);

    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    if (rc == 0) { printf("CROSSED: connected to 1.1.1.1:53\n"); close(s); return 0; }
    if (errno != EINPROGRESS) {
        printf("CONTAINED: connect failed immediately (no network)\n");
        close(s); return 0;
    }
    /* wait up to 3s for the connection to complete */
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    struct timeval tv = {3, 0};
    if (select(s + 1, NULL, &wf, NULL, &tv) == 1) {
        int err = 0; socklen_t l = sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err == 0) printf("CROSSED: connected to 1.1.1.1:53\n");
        else printf("CONTAINED: connect failed (%s)\n", strerror(err));
    } else {
        printf("CONTAINED: connect timed out (no reachable network)\n");
    }
    close(s);
    return 0;
}
