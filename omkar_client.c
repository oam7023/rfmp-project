#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET client_socket;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;

    server.sin_family = AF_INET;
    server.sin_port = htons(5050);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    // Connect to the RFMP server
    connect(client_socket, (struct sockaddr*)&server, sizeof(server));
    char message[] = "SS,RFMP,v1.0,0\n";

    send(client_socket, message, strlen(message), 0);
    char buffer[1024];

    recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    buffer[1023] = '\0';

    printf("Server: %s\n", buffer);
    printf("RFMP C Client\n");
    char filename[100];

    printf("Enter filename to read: ");
    scanf("%99s", filename);

    char command[200];

    sprintf(command, "CM,openRead,%s\n", filename);

    send(client_socket, command, strlen(command), 0);
    int bytes_received;

    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    buffer[bytes_received] = '\0';

    printf("File contents:\n");
    printf("%s\n", buffer);

    closesocket(client_socket);
    WSACleanup();

    return 0;
}