#include <iostream>
#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <memory>
#include "Source_h.h"

#pragma comment(lib, "Rpcrt4.lib")

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}

// Глобальная переменная (определена в Source_c.c)
extern handle_t hRPCBinding;

// Функция для подключения к серверу
RPC_STATUS ConnectToServer(const std::string& serverIP, const std::string& port)
{
    RPC_STATUS status;
    RPC_CSTR stringBinding = NULL;

    status = RpcStringBindingComposeA(
        NULL,
        (RPC_CSTR)"ncacn_ip_tcp",
        (RPC_CSTR)serverIP.c_str(),   // только IP
        (RPC_CSTR)port.c_str(),       // только port
        NULL,
        &stringBinding);

    if (status != RPC_S_OK) {
        std::cout << "RpcStringBindingCompose failed: " << status << std::endl;
        return status;
    }

    std::cout << "Binding: " << stringBinding << std::endl;

    status = RpcBindingFromStringBindingA(stringBinding, &hRPCBinding);
    RpcStringFreeA(&stringBinding);

    if (status != RPC_S_OK) {
        std::cout << "RpcBindingFromStringBinding failed: " << status << std::endl;
        return status;
    }

    return RPC_S_OK;
}


void DisconnectFromServer()
{
    if (hRPCBinding != NULL) {
        RpcBindingFree(&hRPCBinding);
        hRPCBinding = NULL;
        std::cout << "Disconnected from server" << std::endl;
    }
}

int main()
{
    std::string serverIP, port;

    std::cout << "=== RPC File Manager Client ===" << std::endl;
    std::cout << "Enter server IP (localhost or 127.0.0.1 for local): ";
    std::getline(std::cin, serverIP);

    std::cout << "Enter server port (e.g., 9090): ";
    std::getline(std::cin, port);

    // Подключаемся
    RPC_STATUS status = ConnectToServer(serverIP, port);
    if (status != RPC_S_OK) {
        std::cerr << "Failed to connect to server. Error code: " << status << std::endl;

        if (status == RPC_S_SERVER_UNAVAILABLE) {
            std::cerr << "Server is unavailable. Make sure:" << std::endl;
            std::cerr << "1. Server is running" << std::endl;
            std::cerr << "2. Firewall allows connections on port " << port << std::endl;
        }

        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "Connected successfully!" << std::endl;

    // Аутентификация
    std::string username, password;
    std::cout << "\n=== Login ===" << std::endl;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    int clientIndex = -1;
    std::cout << "Logging in..." << std::endl;

    int loginResult = login_client(
        (const unsigned char*)username.c_str(),
        (const unsigned char*)password.c_str(),
        &clientIndex);

    if (loginResult != 0 || clientIndex < 0) {
        std::cerr << "Login failed! Result: " << loginResult << std::endl;

        DisconnectFromServer();
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "Login successful! Your session ID: " << clientIndex << std::endl;

    // Используем вектор для избежания переполнения стека
    std::vector<unsigned char> buffer(1048576);

    // Главное меню
    while (true) {
        std::cout << "\n=== File Operations ===" << std::endl;
        std::cout << "1. Download file from server" << std::endl;
        std::cout << "2. Upload file to server" << std::endl;
        std::cout << "3. Delete file on server" << std::endl;
        std::cout << "4. Exit" << std::endl;
        std::cout << "Choice: ";

        std::string choiceStr;
        std::getline(std::cin, choiceStr);

        if (choiceStr == "1") {
            // Загрузка с сервера
            std::string serverPath, localPath;
            std::cout << "Server file path: ";
            std::getline(std::cin, serverPath);
            std::cout << "Local save path: ";
            std::getline(std::cin, localPath);

            int length_buf = 0;
            int check_eof = 0;

            std::ofstream outFile(localPath, std::ios::binary);
            if (!outFile) {
                std::cerr << "Cannot create local file" << std::endl;
                continue;
            }

            std::cout << "Downloading..." << std::endl;
            bool success = true;

            do {
                // Используем data() для получения указателя на буфер вектора
                int result = download_to_client(
                    (const unsigned char*)serverPath.c_str(),
                    buffer.data(),  // <- важно: data() вместо &buffer[0]
                    &length_buf,
                    clientIndex,
                    &check_eof);

                if (result != 0) {
                    std::cerr << "Download error: " << result << std::endl;
                    success = false;
                    break;
                }

                if (length_buf > 0) {
                    outFile.write((const char*)buffer.data(), length_buf);
                    std::cout << "Downloaded " << length_buf << " bytes" << std::endl;
                }

            } while (check_eof == 0);

            outFile.close();

            if (success) {
                std::cout << "Download completed!" << std::endl;
            }

        }
        else if (choiceStr == "2") {
            // Загрузка на сервер
            std::string localPath, serverPath;
            std::cout << "Local file path: ";
            std::getline(std::cin, localPath);
            std::cout << "Server save path: ";
            std::getline(std::cin, serverPath);

            std::ifstream inFile(localPath, std::ios::binary);
            if (!inFile) {
                std::cerr << "Cannot open local file" << std::endl;
                continue;
            }

            std::cout << "Uploading..." << std::endl;
            bool success = true;

            while (!inFile.eof()) {
                // Читаем в буфер
                inFile.read((char*)buffer.data(), buffer.size());
                std::streamsize bytesRead = inFile.gcount();

                if (bytesRead > 0) {
                    int check_eof = inFile.eof() ? 1 : 0;

                    int result = send_to_server(
                        (const unsigned char*)serverPath.c_str(),
                        buffer.data(),
                        (int)bytesRead,
                        clientIndex,
                        check_eof);

                    if (result != 0) {
                        std::cerr << "Upload error: " << result << std::endl;
                        success = false;
                        break;
                    }

                    std::cout << "Uploaded " << bytesRead << " bytes" << std::endl;
                }
            }

            inFile.close();

            if (success) {
                std::cout << "Upload completed!" << std::endl;
            }

        }
        else if (choiceStr == "3") {
            // Удаление
            std::string serverPath;
            std::cout << "File to delete on server: ";
            std::getline(std::cin, serverPath);

            int result = delete_file_on_server(
                (const unsigned char*)serverPath.c_str(),
                clientIndex);

            if (result == 0) {
                std::cout << "File deleted successfully!" << std::endl;
            }
            else {
                std::cerr << "Delete failed: " << result << std::endl;
            }

        }
        else if (choiceStr == "4") {
            // Выход
            client_out(clientIndex);
            DisconnectFromServer();
            std::cout << "Goodbye!" << std::endl;
            break;
        }
        else {
            std::cout << "Invalid choice!" << std::endl;
        }
    }

    return 0;
}