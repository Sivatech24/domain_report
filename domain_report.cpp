// domain_report.cpp
// Requires: libcurl, nlohmann::json (apt: nlohmann-json3-dev), dig/whois/traceroute/ping/openssl/nmap
// Compile: g++ domain_report.cpp -o domain_report -lcurl -lssl -lcrypto

#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <algorithm>
#include <regex>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

// helper to run system command and capture stdout
string run_cmd(const string &cmd) {
    array<char, 4096> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "ERROR: failed to run command: " + cmd + "\n";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// libcurl write callback
size_t curl_writer(char *ptr, size_t size, size_t nmemb, void *userdata) {
    string* s = reinterpret_cast<string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

// fetch RDAP JSON using rdap.org (will redirect to proper RIR / registrar)
string fetch_rdap_json(const string &path) {
    CURL* curl = curl_easy_init();
    if (!curl) return "ERROR: curl init failed\n";
    string resp;
    string url = "https://rdap.org/" + path; // e.g. "domain/dns.google" or "ip/8.8.8.8"
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        string err = "ERROR: curl failed: ";
        err += curl_easy_strerror(res);
        err += "\n";
        curl_easy_cleanup(curl);
        return err;
    }
    curl_easy_cleanup(curl);
    return resp;
}

// print header divider
void section_title(const string &t) {
    cout << "\n" << string(2, '\n') << t << "\n" << string(t.size(), '=') << "\n";
}

// try reverse DNS with getnameinfo (IPv4/IPv6)
// returns PTR or empty string
string reverse_dns_getname(const string &ip) {
    // try IPv4
    sockaddr_storage sa;
    socklen_t sa_len;
    memset(&sa, 0, sizeof(sa));
    if (ip.find(':') == string::npos) {
        sockaddr_in *s4 = (sockaddr_in*)&sa;
        s4->sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &s4->sin_addr) == 1) {
            sa_len = sizeof(sockaddr_in);
            char host[NI_MAXHOST];
            if (getnameinfo((sockaddr*)s4, sa_len, host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
                return string(host);
        }
    } else {
        sockaddr_in6 *s6 = (sockaddr_in6*)&sa;
        s6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip.c_str(), &s6->sin6_addr) == 1) {
            sa_len = sizeof(sockaddr_in6);
            char host[NI_MAXHOST];
            if (getnameinfo((sockaddr*)s6, sa_len, host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
                return string(host);
        }
    }
    return "";
}

// helper to trim
static inline string trim(const string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    cout << "Enter domain or IP (e.g. dns.google or 8.8.8.8): ";
    string input;
    if (! (cin >> input)) return 0;

    // ---------- Address lookup ----------
    section_title("Address lookup");
    // canonical name and aliases via dig +short CNAME (if any)
    string cname = run_cmd("dig +short CNAME " + input);
    string addresses = run_cmd("dig +short A " + input);
    string addresses_aaaa = run_cmd("dig +short AAAA " + input);

    string canon = trim(cname);
    cout << "canonical name\t" << (canon.empty() ? "-" : canon) << "\n";
    cout << "aliases\t\n";

    // print A addresses line like sample
    vector<string> all_addrs;
    {
        istringstream iss(addresses);
        string line;
        while (getline(iss, line)) { line = trim(line); if (!line.empty()) all_addrs.push_back(line); }
        istringstream iss6(addresses_aaaa);
        while (getline(iss6, line)) { line = trim(line); if (!line.empty()) all_addrs.push_back(line); }
    }
    cout << "addresses\t";
    if (all_addrs.empty()) cout << "-\n";
    else {
        for (size_t i=0;i<all_addrs.size();++i) {
            if (i) cout << ", ";
            cout << all_addrs[i];
        }
        cout << "\n";
    }

    // ---------- Domain WHOIS / RDAP ----------
    section_title("Domain RDAP / WHOIS record (rdap.org queries)");
    // attempt domain RDAP if input looks like domain (contains letters or dot)
    bool looks_like_ip = regex_match(input, regex(R"(^(\d{1,3}\.){3}\d{1,3}$)")) || (input.find(':')!=string::npos);
    if (!looks_like_ip) {
        string rdap_resp = fetch_rdap_json("domain/" + input);
        // try to pretty print RDAP JSON if valid JSON
        try {
            auto j = json::parse(rdap_resp);
            // print some key fields similar to your sample
            if (j.contains("objectClassName")) cout << "ObjectClassName: " << j["objectClassName"].get<string>() << "\n";
            if (j.contains("ldhName")) cout << "Domain Name ACE: " << j["ldhName"].get<string>() << "\n";
            if (j.contains("handle")) cout << "Registry Domain ID: " << j["handle"].get<string>() << "\n";
            if (j.contains("events") && j["events"].is_array()) {
                for (auto &ev : j["events"]) {
                    if (ev.contains("eventAction") && ev.contains("eventDate")) {
                        cout << "Event: " << ev["eventAction"].get<string>() << " at " << ev["eventDate"].get<string>() << "\n";
                    }
                }
            }
            if (j.contains("entities") && j["entities"].is_array()) {
                for (auto &ent : j["entities"]) {
                    if (ent.contains("roles") && ent.contains("vcardArray")) {
                        auto roles = ent["roles"];
                        for (auto &r : roles) cout << "Role: " << r.get<string>() << "\n";
                        // registrant name sometimes in vcardArray
                        try {
                            auto v = ent["vcardArray"];
                            // naive extraction
                            for (auto &entry : v[1]) {
                                if (entry[0].get<string>() == "fn") {
                                    cout << "Registrant Name: " << entry[3].get<string>() << "\n";
                                }
                            }
                        } catch(...) {}
                    }
                }
            }
            if (j.contains("nameservers")) {
                for (auto &ns : j["nameservers"]) {
                    if (ns.is_object() && ns.contains("ldhName")) cout << "Name Server: " << ns["ldhName"].get<string>() << "\n";
                    else if (ns.is_string()) cout << "Name Server: " << ns.get<string>() << "\n";
                }
            }
            if (j.contains("status")) {
                if (j["status"].is_array()) {
                    for (auto &s : j["status"]) cout << "Domain Status: " << s.get<string>() << "\n";
                } else cout << "Domain Status: " << j["status"].get<string>() << "\n";
            }
            cout << "\n>>> Full RDAP JSON (trimmed) <<<\n";
            // print compacted JSON (first 2000 chars)
            string compact = j.dump(2);
            if (compact.size() > 8000) compact = compact.substr(0,8000) + "\n...[truncated]\n";
            cout << compact << "\n";
        } catch (const std::exception &e) {
            // not JSON - print raw
            cout << rdap_resp << "\n";
        }

        // also print classic whois output (may be redacted)
        cout << "\nQueried WHOIS:\n";
        cout << run_cmd("whois " + input) << "\n";
    } else {
        cout << "Input appears to be an IP address; skipping domain RDAP. Use IP RDAP below.\n";
    }

    // ---------- Network WHOIS (IP) ----------
    section_title("Network Whois record (IP)");
    // For each resolved IP (or if input is IP, use it)
    vector<string> ips_to_query;
    if (looks_like_ip) {
        ips_to_query.push_back(input);
    } else {
        // gather A/AAAA from earlier
        if (!all_addrs.empty()) ips_to_query = all_addrs;
    }
    if (ips_to_query.empty()) {
        cout << "No IPs found to query WHOIS for.\n";
    } else {
        for (auto &ip : ips_to_query) {
            cout << "\n--- IP: " << ip << " ---\n";
            // RDAP for IP
            string ip_rdap = fetch_rdap_json("ip/" + ip);
            try {
                auto jp = json::parse(ip_rdap);
                if (jp.contains("handle")) cout << "NetHandle: " << jp["handle"].get<string>() << "\n";
                if (jp.contains("name")) cout << "NetName: " << jp["name"].get<string>() << "\n";
                if (jp.contains("startAddress") && jp.contains("endAddress")) {
                    cout << "NetRange: " << jp["startAddress"].get<string>() << " - " << jp["endAddress"].get<string>() << "\n";
                }
                if (jp.contains("cidr")) cout << "CIDR: " << jp["cidr"].get<string>() << "\n";
                if (jp.contains("entities") && jp["entities"].is_array()) {
                    for (auto &ent : jp["entities"]) {
                        if (ent.contains("roles")) {
                            for (auto &r : ent["roles"]) cout << "Role: " << r.get<string>() << "\n";
                        }
                        if (ent.contains("vcardArray")) {
                            try {
                                for (auto &entry : ent["vcardArray"][1]) {
                                    if (entry[0].get<string>() == "tel") cout << "Org Phone: " << entry[3].get<string>() << "\n";
                                    if (entry[0].get<string>() == "email") cout << "Org Email: " << entry[3].get<string>() << "\n";
                                    if (entry[0].get<string>() == "fn") cout << "OrgName: " << entry[3].get<string>() << "\n";
                                }
                            } catch(...) {}
                        }
                    }
                }
                cout << "\n(Full RDAP JSON for IP truncated)\n";
            } catch(...) {
                cout << ip_rdap << "\n";
            }
            // also show classic whois output
            cout << "\nQueried whois:\n";
            cout << run_cmd("whois " + ip) << "\n";
        }
    }

    // ---------- DNS records detailed ----------
    section_title("DNS records (dig output)");
    // types to fetch
    vector<string> types = {"SOA","NS","A","AAAA","CNAME","MX","TXT","CAA","DNSKEY","RRSIG","NSEC","CDS","CDNSKEY"};
    for (auto &t : types) {
        string out = run_cmd("dig +nocmd " + input + " " + t + " +noall +answer");
        if (!trim(out).empty()) {
            cout << "\n" << input << "\tIN\t" << t << "\n";
            cout << out << "\n";
        }
    }
    // zonewalk for PTR reverse if IP provided
    if (looks_like_ip) {
        section_title("Reverse DNS (PTR)");
        string ptr = run_cmd("dig -x " + input + " +short");
        cout << input << ".in-addr.arpa\tIN\tPTR\t" << (trim(ptr).empty() ? "No PTR" : trim(ptr)) << "\n";
    } else {
        // For every IP resolved earlier, show PTR
        if (!ips_to_query.empty()) {
            section_title("Reverse DNS (PTR) for resolved IPs");
            for (auto &ip : ips_to_query) {
                string ptr = run_cmd("dig -x " + ip + " +short");
                if (trim(ptr).empty()) {
                    string fallback = reverse_dns_getname(ip);
                    cout << ip << ".in-addr.arpa\tIN\tPTR\t" << (fallback.empty() ? "No PTR" : fallback) << "\n";
                } else cout << ip << ".in-addr.arpa\tIN\tPTR\t" << trim(ptr) << "\n";
            }
        }
    }

    // ---------- Traceroute ----------
    section_title("Traceroute");
    // traceroute may require sudo for some WSL setups; use -n to avoid name resolution delays
    string tr_cmd = "traceroute -n " + (looks_like_ip ? input : string(input)) + " 2>/dev/null";
    string tr = run_cmd(tr_cmd);
    if (trim(tr).empty()) {
        // fallback to use system traceroute without -n
        tr = run_cmd("traceroute " + (looks_like_ip ? input : string(input)) + " 2>/dev/null");
    }
    cout << tr << "\n";

    // ---------- Service scan (nmap short) ----------
    section_title("Service scan (nmap - top ports)");
    // If nmap exists, run a light scan (top 100 ports). If not, skip.
    string nmap_check = run_cmd("which nmap");
    if (trim(nmap_check).empty()) {
        cout << "nmap not installed; install nmap to enable service scan (sudo apt install nmap)\n";
    } else {
        // choose a target: first IP or input
        string target = looks_like_ip ? input : (ips_to_query.empty() ? input : ips_to_query[0]);
        cout << "Running nmap -Pn --top-ports 100 -sV " << target << "  (may require network access)\n";
        // run with timeout of 60s by prefixing timeout command if available
        string nmap_out = run_cmd("nmap -Pn --top-ports 100 -sV " + target + " 2>/dev/null");
        cout << nmap_out << "\n";
    }

    // ---------- SSL certificate details ----------
    section_title("SSL / TLS certificate info (openssl s_client)");
    // Only attempt if we have hostname and port 443 - if input is IP that's okay but use -servername for SNI if domain provided
    string host_for_ssl = looks_like_ip ? (ips_to_query.empty() ? input : ips_to_query[0]) : input;
    // Use openssl to fetch cert (connect, then show cert)
    string openssl_cmd;
    if (!looks_like_ip) openssl_cmd = "timeout 8 openssl s_client -connect " + host_for_ssl + ":443 -servername " + input + " </dev/null 2>/dev/null | openssl x509 -noout -text";
    else openssl_cmd = "timeout 8 openssl s_client -connect " + host_for_ssl + ":443 </dev/null 2>/dev/null | openssl x509 -noout -text";
    string cert = run_cmd(openssl_cmd);
    if (trim(cert).empty()) cout << "No certificate or connection failed (or timeout).\n";
    else cout << cert << "\n";

    // ---------- HTTP headers and redirect chain ----------
    section_title("HTTP headers / redirect chain (curl -I -L)");
    string curl_headers = run_cmd("curl -I -L --max-redirs 10 -s -S https://" + input + " 2>/dev/null");
    if (trim(curl_headers).empty()) {
        // try http
        curl_headers = run_cmd("curl -I -L --max-redirs 10 -s -S http://" + input + " 2>/dev/null");
    }
    if (trim(curl_headers).empty()) cout << "No HTTP response (site may block HEAD or use non-standard ports)\n";
    else cout << curl_headers << "\n";

    // ---------- Final note ----------
    section_title("Notes");
    cout << "This report combined:\n"
         << "- 'dig' for DNS + DNSSEC records\n"
         << "- RDAP (rdap.org) for domain/IP structured registry data\n"
         << "- whois for traditional WHOIS output\n"
         << "- traceroute, nmap, openssl, curl for network/service/SSL info\n\n";
    cout << "Some fields (registrant contact) may be REDACTED for privacy by registrars.\n";
    cout << "If you want this output saved to a file, run: ./domain_report > report.txt\n";

    return 0;
}
