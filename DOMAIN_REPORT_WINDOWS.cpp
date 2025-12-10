#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <regex>
#include <fstream>

// Color codes for Windows Terminal (supported natively in Win10+)
#define GREEN  "\033[1;32m"
#define CYAN   "\033[1;36m"
#define YELLOW "\033[1;33m"
#define RED    "\033[1;31m"
#define RESET  "\033[0m"

// Safe command runner
std::string run_cmd(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result;

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "ERROR";

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    _pclose(pipe);

    if (result.empty()) return "N/A";
    return result;
}

// Trim whitespace
std::string trim(const std::string &s) {
    std::string out = s;
    out.erase(0, out.find_first_not_of(" \n\r\t"));
    out.erase(out.find_last_not_of(" \n\r\t") + 1);
    return out;
}

// Check if input is IP
bool is_ip(const std::string& input) {
    std::regex ipv4(R"(^([0-9]{1,3}\.){3}[0-9]{1,3}$)");
    return std::regex_match(input, ipv4);
}

int main() {
    std::string target;
    std::cout << CYAN << "Enter a domain or IP: " << RESET;
    std::getline(std::cin, target);
    target = trim(target);

    bool isIP = is_ip(target);

    std::string ip = "N/A";
    std::string domain = "N/A";
    std::string rdns = "N/A";
    std::string whois = "N/A";
    std::string geo = "N/A";
    std::string ns = "N/A";
    std::string mx = "N/A";

    // -------------------------
    // DNS RESOLUTION (nslookup)
    // -------------------------
    if (isIP) {
        ip = target;
        domain = trim(run_cmd("nslookup " + target + " | find \"name =\""));
        if (domain.find("name =") != std::string::npos) {
            domain = domain.substr(domain.find("name =") + 7);
        }
    }
    else {
        domain = target;
        ip = trim(run_cmd("nslookup " + target + " | find \"Address:\""));
        if (ip.find("Address:") != std::string::npos) {
            ip = ip.substr(ip.find("Address:") + 9);
        }

        // Nameservers
        ns = run_cmd("nslookup -type=NS " + target);

        // Mail servers
        mx = run_cmd("nslookup -type=MX " + target);
    }

    // Reverse DNS
    if (ip != "N/A") {
        rdns = run_cmd("nslookup " + ip + " | find \"name =\"");
        if (rdns.find("name =") != std::string::npos)
            rdns = rdns.substr(rdns.find("name =") + 7);
    }

    // -------------------------
    // WHOIS (Using free API)
    // -------------------------
    whois = run_cmd("curl -s \"https://api.hackertarget.com/whois/?q=" + target + "\"");

    // -------------------------
    // GEOLOCATION (API)
    // -------------------------
    if (ip != "N/A") {
        geo = run_cmd("curl -s https://ipinfo.io/" + ip + "/json");
    }

    // -------------------------
    // PRINT RESULTS
    // -------------------------
    std::cout << GREEN << "\n==== Windows Domain/IP Report ====\n" << RESET;
    std::cout << CYAN << "Input:         " << RESET << target << "\n";
    std::cout << CYAN << "Is IP:         " << RESET << (isIP ? "Yes" : "No") << "\n";
    std::cout << CYAN << "Domain:        " << RESET << domain << "\n";
    std::cout << CYAN << "IP Address:    " << RESET << ip << "\n";
    std::cout << CYAN << "Reverse DNS:   " << RESET << rdns << "\n\n";

    std::cout << YELLOW << "Nameservers:\n" << RESET << ns << "\n";
    std::cout << YELLOW << "Mail Servers:\n" << RESET << mx << "\n";
    std::cout << YELLOW << "WHOIS:\n" << RESET << whois << "\n";
    std::cout << YELLOW << "Geolocation:\n" << RESET << geo << "\n";

    // -------------------------
    // SAVE JSON OUTPUT
    // -------------------------
    std::ofstream out("report.json");
    out << "{\n";
    out << "  \"input\": \"" << target << "\",\n";
    out << "  \"is_ip\": \"" << (isIP ? "true" : "false") << "\",\n";
    out << "  \"domain\": \"" << trim(domain) << "\",\n";
    out << "  \"ip\": \"" << trim(ip) << "\",\n";
    out << "  \"reverse_dns\": \"" << trim(rdns) << "\",\n";
    out << "  \"nameservers\": \"" << trim(ns) << "\",\n";
    out << "  \"mailservers\": \"" << trim(mx) << "\",\n";
    out << "  \"whois\": \"" << trim(whois) << "\",\n";
    out << "  \"geolocation\": " << geo << "\n";
    out << "}\n";
    out.close();

    std::cout << GREEN << "\nSaved JSON → report.json\n" << RESET;

    return 0;
}

