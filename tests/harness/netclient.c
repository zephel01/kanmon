/* テスト用クライアント：指定 IP:port へ TCP 接続し、hold_ms 保持して閉じる、を count 回。
 * 自分の管理下の宛先・文書用 IP（RFC 5737）だけに向けること。
 * usage: netclient <ip> <port> <count> <interval_ms> <hold_ms> */
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s ip port count interval_ms hold_ms\n", argv[0]); return 2; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) return 2;
    int count = atoi(argv[3]), interval = atoi(argv[4]), hold = atoi(argv[5]);
    for (int i = 0; i < count; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        fcntl(s, F_SETFL, O_NONBLOCK);
        connect(s, (struct sockaddr *)&a, sizeof a);
        struct pollfd p = {s, POLLOUT, 0};
        poll(&p, 1, hold);
        usleep((useconds_t)hold * 1000);
        close(s);
        if (i + 1 < count) usleep((useconds_t)interval * 1000);
    }
    return 0;
}
