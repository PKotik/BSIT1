#include <iostream>
#include "Source.h"
#include <fstream>
#include <memory>
#include <windows.h>
#include <stdio.h>
#include <string>

#pragma comment (lib, "Rpcrt4.lib")

RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE /*hInterface*/, void* /*pBindingHandle*/)
{
	return RPC_S_OK; // Always allow anyone.
}

void* __RPC_USER midl_user_allocate(size_t size)
{
	return malloc(size);
}

// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void* p)
{
	free(p);
}

typedef struct client_info {
	handle_t handle;
	FILE* file;
	int file_status = 0;
	std::string login;
};

typedef struct server_info {
	const static int maxClients = 40;
	const static int maxBuffer = 1048576;
	static client_info clients[maxClients];
	static int clientsCount;
};

client_info server_info::clients[server_info::maxClients];
int server_info::clientsCount = 0;

int download_to_client(const char* path, unsigned char buf[1048576], int* length_buf, int index, int* check_eof)
{
	if (!ImpersonateLoggedOnUser(server_info::clients[index].handle))
	{
		std::cout << "Impersonate error." << std::endl;
		return -1;
	}
	if (!server_info::clients[index].file_status)
	{
		if (fopen_s(&server_info::clients[index].file, path, "rb") != 0 || !server_info::clients[index].file)
		{
			std::cout << "File isn't found." << std::endl;
			return 1;
		}
		server_info::clients[index].file_status = 1;
	}
	*length_buf = fread(buf, sizeof(char), server_info::maxBuffer, server_info::clients[index].file);
	if (*length_buf < server_info::maxBuffer)
	{
		server_info::clients[index].file_status = 0;
		fclose(server_info::clients[index].file);
	}
	return 0;
}

int send_to_server(const char* file_name, unsigned char buf[1048576], int length_buf, int index, int check_eof)
{
	if (!ImpersonateLoggedOnUser(server_info::clients[index].handle))
	{
		std::cout << "Impersonate error!" << std::endl;
		return -1;
	}

	if (!server_info::clients[index].file_status)
	{
		if (fopen_s(&server_info::clients[index].file, file_name, "wb") != 0 || !server_info::clients[index].file)
		{
			std::cout << "No write access" << std::endl;
			return 1;
		}
		server_info::clients[index].file_status = 1;
	}
	if (!server_info::clients[index].file)
	{
		std::cout << "No write access." << std::endl;
		return 1;
	}
	fwrite(buf, sizeof(char), length_buf, server_info::clients[index].file);
	if (length_buf < server_info::maxBuffer)
	{
		server_info::clients[index].file_status = 0;
		fclose(server_info::clients[index].file);
	}
	return 0;
}

int delete_file_on_server(const char* path, int index)
{
	if (!ImpersonateLoggedOnUser(server_info::clients[index].handle))
	{
		std::cout << "Impersonate error." << std::endl;
		return -1;
	}
	if (remove((const char*)path) == -1)
	{
		std::cout << "Error remove." << std::endl;
		return 1;
	}
	std::cout << "Successfully!" << std::endl;
	return 0;
}

int login_client(const char* login, const char* password, int* index)
{
	int i = 0;
	handle_t handle = 0;

	if (server_info::clientsCount > server_info::maxClients) return 1;

	while (server_info::clients[i].handle)
		i++;

	server_info::clients[i].login = login;

	if (i == server_info::maxClients) return 1;
	if (!LogonUserA((LPCSTR)login, NULL, (LPCSTR)password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &handle))
	{
		std::cout << "The user name or password is incorrect. Try again." << std::endl;
		return -1;
	}
	if (!ImpersonateLoggedOnUser(handle))
	{
		std::cout << "Impersonate error." << std::endl;
		return -1;
	}

	server_info::clients[i].handle = handle;
	server_info::clients[i].file = 0;
	server_info::clients[i].file_status = 0;
	*index = i;
	std::cout << "Client " << server_info::clients[i].login << " connected." << std::endl;
	return 0;
}

int client_out(int index)
{
	CloseHandle(server_info::clients[index].handle);
	server_info::clients[index].handle = NULL;
	server_info::clients[index].file = NULL;
	server_info::clients[index].file_status = 0;

	server_info::clientsCount--;
	std::cout << "Client " << server_info::clients[index].login << " disconnected" << std::endl;

	return 0;
}



int main()
{

	std::string address;
	std::cout << "Port:: ";
	std::cin >> address;

	RPC_STATUS status;
	
	RpcServerRegisterAuthInfoA(nullptr, RPC_C_AUTHN_WINNT, 0, nullptr);

	status = RpcServerUseProtseqEpA((RPC_CSTR)("ncacn_ip_tcp"), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)(address.c_str()), NULL);

	if (status)
		exit(status);

	status = RpcServerRegisterIf2(RPC_v1_0_s_ifspec, NULL, NULL, RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (unsigned)-1, SecurityCallback);

	if (status)
		exit(status);
	std::cout << "Listening..." << std::endl;

	status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
	if (status)
		exit(status);
}

