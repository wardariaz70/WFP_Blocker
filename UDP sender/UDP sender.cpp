#include <iostream>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SEND_INTERVAL_SEC 5

const char* LOCAL_IP = "192.168.18.169";
const int LOCAL_PORT = 9999;

const char* TARGET_IP = "192.168.18.154";
const int TARGET_PORT = 9999;

SOCKET sendSocket;

void sendLoop() {
    
    sockaddr_in targetAddr = {};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &targetAddr.sin_addr);

    while (true) {
        const char* message = "WINDOWS MSG";
        int sent = sendto(sendSocket, message, strlen(message), 0, (sockaddr*)&targetAddr, sizeof(targetAddr));
        if (sent == SOCKET_ERROR) {
            std::cerr << "Send failed." << std::endl;
        } else {
            std::cout << "Packet sent." << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(SEND_INTERVAL_SEC));
    }

    closesocket(sendSocket);
}

void receiveLoop() {
    //SOCKET recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    //if (recvSocket == INVALID_SOCKET) {
    //    std::cerr << "Receiver socket creation failed." << std::endl;
    //    return;
    //}

    //sockaddr_in recvAddr = {};
    //recvAddr.sin_family = AF_INET;
    //recvAddr.sin_port = htons(LOCAL_PORT);
    ////recvAddr.sin_addr.s_addr = INADDR_ANY;

    //inet_pton(AF_INET, LOCAL_IP, &recvAddr.sin_addr);

    //if (bind(recvSocket, (sockaddr*)&recvAddr, sizeof(recvAddr)) == SOCKET_ERROR) {
    //    std::cerr << "Receiver bind failed." << std::endl;
    //    closesocket(recvSocket);
    //    return;
    //}

    char buffer[1024];
    sockaddr_in senderAddr;
    int senderAddrSize = sizeof(senderAddr);
    while (true) {
        int recvLen = recvfrom(sendSocket, buffer, sizeof(buffer) - 1, 0, (sockaddr*)&senderAddr, &senderAddrSize);
        if (recvLen == SOCKET_ERROR) {
            std::cerr << "[Receiver] Receive failed." << std::endl;
        }
        else {
            buffer[recvLen] = '\0';
            char senderIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &senderAddr.sin_addr, senderIp, INET_ADDRSTRLEN);
            std::cout << "[Receiver] Received from " << senderIp << ":" << ntohs(senderAddr.sin_port) << " => " << buffer << std::endl;
        }
    }

    closesocket(sendSocket);
}

int main() {
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cerr << "WSAStartup failed: " << wsaInit << std::endl;
        return 1;
    }
    /////////socket creation
    sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sendSocket == INVALID_SOCKET) {
        std::cerr << "Sender socket creation failed." << std::endl;
        return 1;
    }

    sockaddr_in localAddr = {};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(LOCAL_PORT);
    inet_pton(AF_INET, LOCAL_IP, &localAddr.sin_addr);

    if (bind(sendSocket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
        std::cerr << "Sender bind failed." << std::endl;
        closesocket(sendSocket);
        return 1;
    }

    /////////Socket bind end
    std::thread senderThread(sendLoop);
    std::thread receiverThread(receiveLoop);

    senderThread.join();
    receiverThread.join();

    WSACleanup();
    return 0;
}
