#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wscapi.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "Wscapi.lib")

const char* HealthToStr(WSC_SECURITY_PROVIDER_HEALTH h) {
    switch (h) {
    case WSC_SECURITY_PROVIDER_HEALTH_GOOD: return "GOOD";
    case WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED: return "NOTMONITORED";
    case WSC_SECURITY_PROVIDER_HEALTH_POOR: return "POOR";
    case WSC_SECURITY_PROVIDER_HEALTH_SNOOZE: return "SNOOZE";
    default: return "UNKNOWN";
    }
}

struct ProviderInfo {
    DWORD flag;
    const char* name;
};

static const ProviderInfo providers[] = {
    { WSC_SECURITY_PROVIDER_FIREWALL, "Firewall" },
    { WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS, "AutoUpdate settings" },
    { WSC_SECURITY_PROVIDER_ANTIVIRUS, "Antivirus" },
    { WSC_SECURITY_PROVIDER_ANTISPYWARE, "Antispyware (deprecated on recent Win10+)" },
    { WSC_SECURITY_PROVIDER_INTERNET_SETTINGS, "Internet settings" },
    { WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL, "User Account Control (UAC)" },
    { WSC_SECURITY_PROVIDER_SERVICE, "Security Center service (WSC service)" }
};

void PrintProvidersHealth() {
    std::cout << "Querying WSC provider health..." << std::endl;
    for (const auto& p : providers) {
        WSC_SECURITY_PROVIDER_HEALTH health = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
        HRESULT hr = WscGetSecurityProviderHealth(p.flag, &health);
        if (hr == S_OK) {
            std::cout << "  " << p.name << ": " << HealthToStr(health) << std::endl;
        }
        else if (hr == S_FALSE) {
            std::cout << "  " << p.name << ": (WSC service not running) -> " << HealthToStr(health) << std::endl;
        }
        else {
            std::cout << "  " << p.name << ": ERROR 0x" << std::hex << hr << std::dec << std::endl;
        }
    }
}

DWORD WINAPI WscChangeCallback(LPVOID /*lpParameter*/) {
    std::cout << std::endl << "*** WSC change detected! Re-querying status... ***" << std::endl;
    PrintProvidersHealth();
    std::cout << "--------------------------------------" << std::endl;
    return 0;
}

int main() {
    std::cout << "=== WSC Monitor (Windows Security Center) ===" << std::endl;

    PrintProvidersHealth();

    HANDLE hRegistration = NULL;
    HRESULT hr = WscRegisterForChanges(
        /*Reserved*/ nullptr,
        /*out*/ &hRegistration,
        /*lpCallbackAddress*/ (LPTHREAD_START_ROUTINE)WscChangeCallback,
        /*pContext*/ nullptr
    );

    if (FAILED(hr)) {
        std::cerr << "WscRegisterForChanges failed: 0x" << std::hex << hr << std::dec << std::endl;
        std::cerr << "Program will continue only with polling (no notifications)." << std::endl;
    }
    else {
        std::cout << "Registered for WSC changes. Registration handle: " << hRegistration << std::endl;
    }

    std::cout << std::endl
        << "Press ENTER to exit..." << std::endl;
    std::string dummy;
    std::getline(std::cin, dummy);

    if (hRegistration) {
        hr = WscUnRegisterChanges(hRegistration);
        if (FAILED(hr)) {
            std::cerr << "WscUnRegisterChanges failed: 0x" << std::hex << hr << std::dec << std::endl;
        }
        else {
            std::cout << "Unregistered from WSC changes." << std::endl;
        }
    }

    std::cout << "Exit." << std::endl;
    return 0;
}