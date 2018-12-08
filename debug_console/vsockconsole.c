#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) 
{
        int i;
        char buf[16];
        struct sockaddr_vm sa = {
                            .svm_family = AF_VSOCK,
                            .svm_cid = VMADDR_CID_ANY, 
                            .svm_port = 8888,
                       };

        printf("VM:\n");
        memcpy(buf, &sa, sizeof(sa));
        for(i=2;i<sizeof(sa);i++) {
                printf("x%02x", (unsigned char)buf[i]);
        }
        printf("\n");
        
        sa.svm_cid = atoi(argv[1]);

        printf("VMM:\n");
        memcpy(buf, &sa, sizeof(sa));
        printf("socat - SOCKET-CONNECT:40:0:");
        for(i=2;i<sizeof(sa);i++) {
                printf("x%02x", (unsigned char)buf[i]);
        }
        printf("\n");       
}

