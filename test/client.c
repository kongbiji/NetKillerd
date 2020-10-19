#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int server_fd, nbyte;
    struct sockaddr_in servaddr;

    if(argc < 3)
    {
        printf("Usage: %s ip_address port\n", argv[0]);
        return -1;
    }

    if((server_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
    {
        perror("socket failed !");
        return -1;
    }
    
    servaddr.sin_family = AF_INET;

    inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
    servaddr.sin_port = htons(atoi(argv[2]));

    // 연결 요청,,
    if(connect(server_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("Connection failed !");
        return -1;
    }
    puts("Connection Success !");
    char buf[100]={0,};
    read(server_fd, buf, sizeof(buf));
    close(server_fd);

    printf("Server msg >> %s\n", buf);

    return 0;
}