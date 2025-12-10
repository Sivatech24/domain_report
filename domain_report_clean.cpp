// domain_report_clean.cpp
// - Auto-detect domain vs IP
// - Uses: dig, whois, traceroute, nmap (optional), openssl, curl
// - Uses libcurl for RDAP JSON
// - Uses nlohmann::json (header-only) to build/save report.json
// - Prints colored, formatted terminal output
// Compile: g++ -std=c++17 -O2 -Wall -Wextra domain_report_clean.cpp -o domain_report_clean -lcurl -lssl -lcrypto

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;

// ---------- Terminal colors ----------
namespace term {
    constexpr const char* RESET = "\033[0m";
    constexpr const char* RED = "\033[31m";
    constexpr const char* GREEN = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* BLUE = "\033[34m";
    constexpr const char* MAGENTA = "\033[35m";
    constexpr const char* CYAN = "\033[36m";
    constexpr const char* BOLD = "\033[1m";
}

// ---------- Utility: trim ----------
static inline std::string trim(const std::string& s) {
    const char* ws = " \t\n\r\f\v";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

// ---------- Safe popen wrapper without template attribute warning ----------
using PipeCloser = int (*)(FILE*);
static std::string run_cmd(const std::string& cmd) {
    std::array<char, 4096> buffer;
    std::string result;
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return "ERROR: popen failed for: " + cmd + "\n";
    std::unique_ptr<FILE, PipeCloser> pipe{fp, pclose};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result.append(buffer.data());
    }
    return result;
}

// ---------- libcurl helper ----------
static size_t curl_writer(void* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* s = reinterpret_cast<std::string*>(userdata);
    size_t total = size * nmemb;
    s->append(reinterpret_cast<char*>(ptr), total);
    return total;
}

static std::string fetch_url(const std::string& url, long timeout_seconds = 12) {
    CURL* curl = curl_easy_init();
    if (!curl) return "ERROR: curl init failed";
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    // reduce verbose SSL output
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        std::string err = "ERROR: curl failed: ";
        err += curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return err;
    }
    curl_easy_cleanup(curl);
    return response;
}

// ---------- Detect if input is IPv4 or IPv6 ----------
static bool is_ipv4(const std::string& s) {
    sockaddr_in sa{};
    return inet_pton(AF_INET, s.c_str(), &sa.sin_addr) == 1;
}
static bool is_ipv6(const std::string& s) {
    sockaddr_in6 sa6{};
    return inet_pton(AF_INET6, s.c_str(), &sa6.sin6_addr) == 1;
}

// ---------- Reverse DNS via getnameinfo ----------
static std::string reverse_dns(const std::string& ip) {
    char host[NI_MAXHOST] = {0};
    if (is_ipv4(ip)) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
            return std::string(host);
    } else if (is_ipv6(ip)) {
        sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr);
        if (getnameinfo(reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
            return std::string(host);
    }
    // fallback to dig -x short
    std::string out = run_cmd("dig -x " + ip + " +short");
    return trim(out);
}

// ---------- DNS queries (dig) ----------
static std::vector<std::pair<std::string,std::string>> dig_records(const std::string& name, const std::vector<std::string>& types) {
    std::vector<std::pair<std::string,std::string>> results;
    for (const auto& t : types) {
        std::string cmd = "dig +nocmd " + name + " " + t + " +noall +answer";
        std::string out = run_cmd(cmd);
        out = trim(out);
        if (!out.empty()) results.emplace_back(t, out);
    }
    return results;
}

// ---------- Build JSON from sections helper ----------
struct Report {
    json root;
    void start(const std::string& key) { root[key] = json::object(); }
    void add(const std::string& section, const std::string& key, const json& val) {
        root[section][key] = val;
    }
    void add_raw(const std::string& section, const std::string& rawtext) {
        root[section]["raw"] = rawtext;
    }
    void save(const std::string& filename) const {
        std::ofstream ofs(filename);
        if (ofs) {
            ofs << root.dump(2);
        }
    }
};

// ---------- Pretty print helpers ----------
static void print_section_title(const std::string& title) {
    std::cout << "\n" << term::BOLD << term::CYAN << title << term::RESET << "\n";
    std::cout << std::string(title.size(), '-') << "\n";
}
static void print_kv(const std::string& k, const std::string& v, const char* color = term::YELLOW) {
    std::cout << term::GREEN << k << term::RESET << ": " << color << v << term::RESET << "\n";
}

// ---------- Main analysis routine ----------
int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    std::cout << term::BOLD << "Domain/IP Investigation Tool (clean, JSON output)" << term::RESET << "\n";
    std::cout << "Enter a domain or IP (e.g. dns.google or 8.8.8.8): ";
    std::string input;
    if (!(std::cin >> input)) return 0;
    input = trim(input);
    if (input.empty()) return 0;

    Report report;
    report.root["query"] = input;
    report.root["generated_at"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    bool input_is_ip = is_ipv4(input) || is_ipv6(input);

    // ---------- Address lookup ----------
    print_section_title("Address lookup");
    std::string cname = trim(run_cmd("dig +short CNAME " + input));
    std::string a_addrs = trim(run_cmd("dig +short A " + input));
    std::string aaaa_addrs = trim(run_cmd("dig +short AAAA " + input));
    std::vector<std::string> addrs;
    if (!a_addrs.empty()) {
        std::istringstream iss(a_addrs); std::string l;
        while (std::getline(iss, l)) if (!trim(l).empty()) addrs.push_back(trim(l));
    }
    if (!aaaa_addrs.empty()) {
        std::istringstream iss(aaaa_addrs); std::string l;
        while (std::getline(iss, l)) if (!trim(l).empty()) addrs.push_back(trim(l));
    }

    print_kv("canonical name", cname.empty() ? "-" : cname);
    print_kv("aliases", "-");
    if (!addrs.empty()) {
        std::string joined;
        for (size_t i=0;i<addrs.size();++i) {
            if (i) joined += ", ";
            joined += addrs[i];
        }
        print_kv("addresses", joined, term::BLUE);
        report.add("address_lookup", "addresses", addrs);
    } else {
        print_kv("addresses", "-", term::RED);
    }
    report.add("address_lookup", "canonical_name", cname.empty() ? nullptr : cname);

    // ---------- Domain RDAP & WHOIS ----------
    if (!input_is_ip) {
        print_section_title("Domain RDAP (rdap.org)");
        std::string rdap_url = "domain/" + input;
        std::string rdap_raw = fetch_url("https://rdap.org/" + rdap_url);
        // attempt to parse JSON
        try {
            json j = json::parse(rdap_raw);
            // print some relevant fields
            if (j.contains("ldhName")) print_kv("Domain", j["ldhName"].get<std::string>().c_str());
            if (j.contains("handle")) print_kv("Registry ID", j["handle"].get<std::string>().c_str());
            if (j.contains("events") && j["events"].is_array()) {
                for (const auto& ev : j["events"]) {
                    if (ev.contains("eventAction") && ev.contains("eventDate")) {
                        report.add("rdap", "event_" + ev["eventAction"].get<std::string>(), ev["eventDate"].get<std::string>());
                    }
                }
            }
            if (j.contains("nameservers") && j["nameservers"].is_array()) {
                std::vector<std::string> nslist;
                for (const auto& ns : j["nameservers"]) {
                    if (ns.is_object() && ns.contains("ldhName")) nslist.push_back(ns["ldhName"].get<std::string>());
                    else if (ns.is_string()) nslist.push_back(ns.get<std::string>());
                }
                if (!nslist.empty()) {
                    print_kv("Name servers", nslist.front().c_str());
                    report.add("rdap", "nameservers", nslist);
                }
            }
            report.add("rdap", "raw", j);
            std::cout << term::CYAN << "(RDAP JSON parsed; added to report.json)" << term::RESET << "\n";
        } catch (const std::exception& e) {
            print_kv("RDAP fetch", "failed to parse JSON; storing raw response", term::RED);
            report.add_raw("rdap", rdap_raw);
        }

        print_section_title("WHOIS (classic)");
        std::string who = run_cmd("whois " + input + " 2>/dev/null");
        std::cout << trim(who) << "\n";
        report.add_raw("whois", who);
    } else {
        print_section_title("Domain RDAP / WHOIS");
        print_kv("Info", "Input detected as IP; skipping domain RDAP/WHOIS", term::YELLOW);
    }

    // ---------- Network WHOIS (IP RDAP) ----------
    print_section_title("Network whois / IP RDAP");
    std::vector<std::string> ips_for_ip_whois;
    if (input_is_ip) ips_for_ip_whois.push_back(input);
    else ips_for_ip_whois = addrs;

    if (ips_for_ip_whois.empty()) {
        print_kv("IP RDAP", "No IP addresses found to query RDAP/whois.", term::RED);
    } else {
        for (const auto& ip : ips_for_ip_whois) {
            print_kv("Querying IP", ip, term::MAGENTA);
            std::string ip_rdap_raw = fetch_url("https://rdap.org/ip/" + ip);
            try {
                json j = json::parse(ip_rdap_raw);
                // print organization if present
                if (j.contains("name")) print_kv("NetName", j["name"].get<std::string>().c_str());
                report.add("ip_rdap", ip, j);
            } catch (...) {
                report.add_raw("ip_rdap", ip_rdap_raw);
            }
            std::string who_ip = run_cmd("whois " + ip + " 2>/dev/null");
            report.add_raw("whois_ip_" + ip, who_ip);
            // print a short snippet of whois
            std::istringstream iss(who_ip);
            std::string firstline;
            if (std::getline(iss, firstline)) {
                print_kv("whois snippet", trim(firstline), term::YELLOW);
            }
        }
    }

    // ---------- DNS records (detailed) ----------
    print_section_title("DNS Records (dig)");
    std::vector<std::string> dns_types = {"SOA","NS","A","AAAA","CNAME","MX","TXT","CAA","DNSKEY","RRSIG","NSEC","CDS","CDNSKEY"};
    auto dig_outs = dig_records(input, dns_types);
    for (const auto& [type, block] : dig_outs) {
        print_kv(("Type " + type).c_str(), "", term::CYAN);
        std::cout << block << "\n";
        report.add_raw("dig_" + type, block);
    }

    // ---------- Reverse DNS PTR ----------
    print_section_title("Reverse DNS (PTR)");
    if (!ips_for_ip_whois.empty()) {
        for (const auto& ip : ips_for_ip_whois) {
            std::string ptr = reverse_dns(ip);
            print_kv(ip + " PTR", ptr.empty() ? "No PTR" : ptr, term::BLUE);
            report.add("ptr", ip, ptr.empty() ? nullptr : ptr);
        }
    }

    // ---------- Traceroute ----------
    print_section_title("Traceroute (traceroute -n)");
    std::string target_for_trace = input_is_ip ? input : (!ips_for_ip_whois.empty() ? ips_for_ip_whois.front() : input);
    std::string trace_out = run_cmd("traceroute -n " + target_for_trace + " 2>/dev/null");
    if (trim(trace_out).empty()) trace_out = run_cmd("traceroute " + target_for_trace + " 2>/dev/null");
    if (trim(trace_out).empty()) {
        print_kv("traceroute", "failed or unavailable", term::RED);
    } else {
        std::cout << trace_out << "\n";
        report.add_raw("traceroute", trace_out);
    }

    // ---------- Service scan (nmap quick) ----------
    print_section_title("Service scan (nmap, top-100 ports) - optional");
    std::string which_nmap = trim(run_cmd("which nmap"));
    if (which_nmap.empty()) {
        print_kv("nmap", "not installed; skipping service scan", term::YELLOW);
    } else {
        std::string nmap_target = target_for_trace;
        std::string nmap_cmd = "nmap -Pn --top-ports 100 -sV " + nmap_target + " 2>/dev/null";
        std::string nmap_out = run_cmd(nmap_cmd);
        std::cout << nmap_out << "\n";
        report.add_raw("nmap", nmap_out);
    }

    // ---------- SSL certificate info (openssl) ----------
    print_section_title("SSL / TLS certificate (openssl)");
    std::string host_for_ssl = input_is_ip ? input : input;
    std::string openssl_cmd;
    if (!input_is_ip) {
        openssl_cmd = "timeout 6 openssl s_client -connect " + host_for_ssl + ":443 -servername " + input + " </dev/null 2>/dev/null | openssl x509 -noout -text";
    } else {
        openssl_cmd = "timeout 6 openssl s_client -connect " + host_for_ssl + ":443 </dev/null 2>/dev/null | openssl x509 -noout -text";
    }
    std::string cert = run_cmd(openssl_cmd);
    if (trim(cert).empty()) {
        print_kv("Certificate", "No certificate retrieved or connection timed out", term::YELLOW);
    } else {
        std::cout << cert << "\n";
        report.add_raw("certificate_text", cert);
    }

    // ---------- HTTP headers & redirect chain (curl) ----------
    print_section_title("HTTP headers / redirect chain (curl -I -L)");
    std::string curl_out = run_cmd("curl -I -L --max-redirs 10 -s -S https://" + input + " 2>/dev/null");
    if (trim(curl_out).empty()) {
        curl_out = run_cmd("curl -I -L --max-redirs 10 -s -S http://" + input + " 2>/dev/null");
    }
    if (trim(curl_out).empty()) {
        print_kv("HTTP", "No HTTP response or host blocking HEAD requests", term::YELLOW);
    } else {
        std::cout << curl_out << "\n";
        report.add_raw("http_headers", curl_out);
    }

    // ---------- Final notes & save JSON ----------
    print_section_title("Summary & Save");
    std::string outfile = "report.json";
    report.save(outfile);
    print_kv("Saved report", outfile, term::GREEN);
    std::cout << term::BOLD << term::MAGENTA << "Note: Some info (registrant contact) may be REDACTED by registrars." << term::RESET << "\n\n";
    std::cout << "Tip: Redirect output to file for full record: ./domain_report_clean > full_report.txt\n";

    return 0;
}
