#include <iostream>
#include "Source.h"
#include <fstream>
#include <windows.h>
#include <stdio.h>
#include <string>

#pragma comment (lib, "Rpcrt4.lib")
#pragma comment (lib, "Advapi32.lib")

RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE /*hInterface*/, void* /*pBindingHandle*/)
{
    return RPC_S_OK;
}

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}

struct ClientInfo {
    HANDLE userToken;
    FILE* file;
    int file_status = 0;
    std::string login;
    std::string currentFile;
};

class ServerInfo {
public:
    static const int MAX_CLIENTS = 40;
    static const int BUFFER_SIZE = 1048576;
    static ClientInfo clients[MAX_CLIENTS];

    static int FindFreeSlot() {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].userToken == NULL) {
                return i;
            }
        }
        return -1;
    }

    static bool IsValidIndex(int index) {
        return index >= 0 && index < MAX_CLIENTS && clients[index].userToken != NULL;
    }
};

ClientInfo ServerInfo::clients[ServerInfo::MAX_CLIENTS];

int download_to_client(const char* path, unsigned char buf[1048576], int* length_buf, int index, int* check_eof)
{
    if (!ServerInfo::IsValidIndex(index)) {
        return -1;
    }

    // Имперсонация
    if (!ImpersonateLoggedOnUser(ServerInfo::clients[index].userToken)) {
        std::cout << "Impersonate error: " << GetLastError() << std::endl;
        return -1;
    }

    int result = 0;

    // Открываем файл если нужно
    if (!ServerInfo::clients[index].file_status) {
        errno_t err = fopen_s(&ServerInfo::clients[index].file, path, "rb");
        if (err != 0) {
            std::cout << "Cannot open file: " << path << " Error: " << err << std::endl;
            result = 1;
        }
        else {
            ServerInfo::clients[index].file_status = 1;
            ServerInfo::clients[index].currentFile = path;
        }
    }

    // Читаем файл если он открыт
    if (ServerInfo::clients[index].file != NULL && result == 0) {
        *length_buf = (int)fread(buf, 1, ServerInfo::BUFFER_SIZE, ServerInfo::clients[index].file);

        if (*length_buf < ServerInfo::BUFFER_SIZE) {
            if (feof(ServerInfo::clients[index].file)) {
                *check_eof = 1;
            }
            fclose(ServerInfo::clients[index].file);
            ServerInfo::clients[index].file = NULL;
            ServerInfo::clients[index].file_status = 0;
        }
        else {
            *check_eof = 0;
        }
    }
    else {
        *length_buf = 0;
        *check_eof = 1;
    }

    RevertToSelf();

    return result;
}

int send_to_server(const char* file_name, unsigned char buf[1048576], int length_buf, int index, int check_eof)
{
    if (!ServerInfo::IsValidIndex(index)) {
        return -1;
    }

    if (!ImpersonateLoggedOnUser(ServerInfo::clients[index].userToken)) {
        std::cout << "Impersonate error: " << GetLastError() << std::endl;
        return -1;
    }

    int result = 0;

    if (!ServerInfo::clients[index].file_status) {
        errno_t err = fopen_s(&ServerInfo::clients[index].file, file_name,
            check_eof ? "wb" : "ab");
        if (err != 0) {
            std::cout << "Cannot open file: " << file_name << " Error: " << err << std::endl;
            result = 1;
        }
        else {
            ServerInfo::clients[index].file_status = 1;
            ServerInfo::clients[index].currentFile = file_name;
        }
    }

    if (ServerInfo::clients[index].file != NULL && result == 0) {
        size_t written = fwrite(buf, 1, length_buf, ServerInfo::clients[index].file);
        if (written != length_buf) {
            std::cout << "Write error" << std::endl;
            result = 1;
        }
    }

    if (check_eof && ServerInfo::clients[index].file != NULL) {
        fclose(ServerInfo::clients[index].file);
        ServerInfo::clients[index].file = NULL;
        ServerInfo::clients[index].file_status = 0;
    }

    RevertToSelf();
    return result;
}

int delete_file_on_server(const char* path, int index)
{
    if (!ServerInfo::IsValidIndex(index)) {
        return -1;
    }

    if (!ImpersonateLoggedOnUser(ServerInfo::clients[index].userToken)) {
        std::cout << "Impersonate error: " << GetLastError() << std::endl;
        return -1;
    }

    int result = 0;

    if (remove(path) != 0) {
        std::cout << "Cannot delete file: " << path << " Error: " << errno << std::endl;
        result = 1;
    }
    else {
        std::cout << "File deleted: " << path << std::endl;
    }

    RevertToSelf();
    return result;
}

int login_client(const char* login, const char* password, int* index)
{
    HANDLE userToken = NULL;

    if (!LogonUserA(login,
        ".",
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &userToken))
    {
        DWORD error = GetLastError();
        std::cout << "LogonUser failed for " << login << " Error: " << error << std::endl;
        return -1;
    }

    // Находим свободный слот
    int clientIndex = ServerInfo::FindFreeSlot();
    if (clientIndex == -1) {
        std::cout << "Server is full" << std::endl;
        CloseHandle(userToken);
        return 1;
    }

    // Сохраняем информацию о клиенте
    ServerInfo::clients[clientIndex].userToken = userToken;
    ServerInfo::clients[clientIndex].login = login;
    ServerInfo::clients[clientIndex].file = NULL;
    ServerInfo::clients[clientIndex].file_status = 0;
    ServerInfo::clients[clientIndex].currentFile.clear();

    *index = clientIndex;

    std::cout << "Client " << login << " logged in successfully. Index: "
        << clientIndex << std::endl;

    return 0;
}

int client_out(int index)
{
    if (!ServerInfo::IsValidIndex(index)) {
        return -1;
    }

    std::cout << "Client " << ServerInfo::clients[index].login << " logging out" << std::endl;

    // Закрываем файл если открыт
    if (ServerInfo::clients[index].file != NULL) {
        fclose(ServerInfo::clients[index].file);
    }

    // Закрываем токен
    if (ServerInfo::clients[index].userToken != NULL) {
        CloseHandle(ServerInfo::clients[index].userToken);
    }

    // Очищаем данные
    ServerInfo::clients[index].userToken = NULL;
    ServerInfo::clients[index].file = NULL;
    ServerInfo::clients[index].file_status = 0;
    ServerInfo::clients[index].login.clear();
    ServerInfo::clients[index].currentFile.clear();

    return 0;
}

int main()
{
    std::string port;
    std::cout << "Enter port: ";
    std::getline(std::cin, port);

    RPC_STATUS status;

    // Инициализация массива клиентов
    for (int i = 0; i < ServerInfo::MAX_CLIENTS; i++) {
        ServerInfo::clients[i].userToken = NULL;
        ServerInfo::clients[i].file = NULL;
        ServerInfo::clients[i].file_status = 0;
    }

    // Регистрируем информацию об аутентификации
    status = RpcServerRegisterAuthInfoA(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL);

    if (status != RPC_S_OK) {
        std::cerr << "RpcServerRegisterAuthInfo failed: " << status << std::endl;
        return 1;
    }

    // Используем TCP/IP протокол
    status = RpcServerUseProtseqEpA(
        (RPC_CSTR)"ncacn_ip_tcp",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_CSTR)port.c_str(),
        NULL);

    if (status != RPC_S_OK) {
        std::cerr << "RpcServerUseProtseqEp failed: " << status << std::endl;
        return 1;
    }

    // Регистрируем интерфейс
    status = RpcServerRegisterIf2(
        RPC_v1_0_s_ifspec,
        NULL,
        NULL,
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        (unsigned)-1,
        SecurityCallback);

    if (status != RPC_S_OK) {
        std::cerr << "RpcServerRegisterIf2 failed: " << status << std::endl;
        return 1;
    }

    std::cout << "Server started on port " << port << std::endl;
    std::cout << "Waiting for connections..." << std::endl;

    status = RpcServerListen(
        1,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        FALSE);

    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING) {
        std::cerr << "RpcServerListen failed: " << status << std::endl;
        return 1;
    }

    // Ожидаем завершения
    std::cout << "Press Enter to stop server..." << std::endl;
    std::cin.get();

    return 0;
}