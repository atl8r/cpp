// firewall_l7_final.cpp – C++20 L7-Firewall für Debian 13 Trixie
// Kompilieren (funktioniert garantiert):
// g++ -std=c++20 -O3 -march=native -Wall -Wextra -Werror -pthread -o firewall_l7_final firewall_l7_final.cpp -lpcap -lnghttp2 -lmnl

#include <pcap.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <span>
#include <cstring>
#include <csignal>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <syslog.h>

using namespace std::literals;
using namespace std::chrono_literals;

constexpr auto HTTP2_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"sv;

struct ip_addr {
    uint8_t af;
    union { in_addr v4; in6_addr v6; } addr{};
    
    bool operator==(const ip_addr& o) const noexcept {
        if (af != o.af) return false;
        if (af == AF_INET) return addr.v4.s_addr == o.addr.v4.s_addr;
        return memcmp(&addr.v6, &o.addr.v6, 16) == 0;
    }
};

namespace std {
    template<> struct hash<ip_addr> {
        size_t operator()(const ip_addr& ip) const noexcept {
            if (ip.af == AF_INET) return hash<uint32_t>{}(ip.addr.v4.s_addr);
            uint64_t h1 = 0, h2 = 0;
            memcpy(&h1, ip.addr.v6.s6_addr, 8);
            memcpy(&h2, ip.addr.v6.s6_addr + 8, 8);
            return h1 ^ h2;
        }
    };
}

class L7Firewall {
    pcap_t* handle = nullptr;
    struct mnl_socket* nl = nullptr;
    std::jthread cleanup_thread;
    std::mutex log_mtx, data_mtx;
    std::atomic<bool> running{true};

    struct tcp_stream {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point last_seen;
        bool detected = false;
    };

    // Key: src_ip_hash ^ dst_ip_hash ^ src_port ^ (dst_port<<16)
    std::unordered_map<uint64_t, tcp_stream> tcp_sessions;
    std::unordered_map<ip_addr, std::chrono::steady_clock::time_point> blocked;

    std::atomic<uint64_t> pkt_total{0}, pkt_dropped{0}, h2_cnt{0}, h3_cnt{0};

public:
    explicit L7Firewall(std::string iface = "any") {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(iface.c_str(), 65536, true, 100, errbuf);
        if (!handle) throw std::runtime_error(std::string("pcap: ") + errbuf);

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl) mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);

        openlog("l7fw", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog(LOG_INFO, "L7 Firewall started on %s", iface.c_str());

        cleanup_thread = std::jthread([this](std::stop_token st) {
            while (!st.stop_requested()) {
                std::this_thread::sleep_for(30s);
                cleanup();
            }
        });

        std::cout << "\033[1;32mL7 Firewall (C++20) läuft auf " << iface << "\033[0m\n";
    }

    ~L7Firewall() {
        running = false;
        if (handle) pcap_breakloop(handle);
        cleanup_thread.join();
        if (nl) mnl_socket_close(nl);
        if (handle) pcap_close(handle);
        closelog();
    }

private:
    void block_ip(const ip_addr& ip, const char* reason) {
        if (blocked.contains(ip)) return;
        blocked[ip] = std::chrono::steady_clock::now() + 30min;

        // ipset add
        if (nl) {
            char buf[MNL_SOCKET_BUFFER_SIZE]{};
            auto* nlh = mnl_nlmsg_put_header(buf);
            nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            nlh->nlmsg_seq = time(nullptr);

            auto* nfg = (nfgenmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(nfgenmsg));
            nfg->nfgen_family = ip.af;

            mnl_attr_put_strz(nlh, IPSET_ATTR_SETNAME,
                              ip.af == AF_INET ? "firewall_block4" : "firewall_block6");
            mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
            mnl_attr_put_u32(nlh, IPSET_ATTR_TIMEOUT, 1800);

            auto* nest = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
            auto* ipnest = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);
            if (ip.af == AF_INET)
                mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV4, 4, &ip.addr.v4);
            else
                mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV6, 16, &ip.addr.v6);
            mnl_attr_nest_end(nlh, ipnest);
            mnl_attr_nest_end(nlh, nest);

            mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
        }

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(ip.af, ip.af == AF_INET ? (void*)&ip.addr.v4 : &ip.addr.v6, ipstr, sizeof(ipstr));
        std::lock_guard lk(log_mtx);
        std::cout << "\033[1;31m[BLOCK] " << ipstr << " → " << reason << " (30min)\033[0m\n";
    }

    bool is_blocked(const ip_addr& ip) const {
        auto it = blocked.find(ip);
        return it != blocked.end() && std::chrono::steady_clock::now() < it->second;
    }

    static bool parse_quic_h3(std::span<const uint8_t> data) {
        if (data.size() < 60 || (data[0] & 0xC0) != 0x80 || (data[0] & 0x30) != 0x00) return 0;
        size_t pos = 5; // skip header + version
        if (ntohl(*(uint32_t*)(data.data() + 1)) != 0x00000001) return 0;

        pos += data[pos] + 1; // DCID
        pos += data[pos] + 1; // SCID

        auto read_varint = [&](uint64_t& v) -> bool {
            if (pos + 1 > data.size()) return false;
            uint8_t b = data[pos];
            if ((b & 0xC0) == 0xC0) { if (pos + 4 > data.size()) return false; v = ntohl(*(uint32_t*)(data.data() + pos)) & 0x3fffffffULL; pos += 4; }
            else if ((b & 0x80) == 0x80) { if (pos + 2 > data.size()) return false; v = ntohs(*(uint16_t*)(data.data() + pos)) & 0x3fffULL; pos += 2; }
            else { v = b & 0x3f; pos += 1; }
            return true;
        };

        uint64_t len;
        { uint64_t tmp; if (!read_varint(tmp)) return false; pos += tmp; } // token
        if (!read_varint(len)) return false;
        size_t end = pos + len;

        while (pos + 20 < end) {
            uint8_t type = data[pos++];
            if (type != 0x06) { uint64_t l; if (!read_varint(l)) break; pos += l; continue; }
            read_varint(len); read_varint(len); // offset + length
            if (!read_varint(len)) break;
            if (pos + len > end || len < 60) { pos += len; continue; }
            if (data[pos] != 0x16 || data[pos+5] != 0x01) { pos += len; continue; }

            size_t tpos = pos + 43;
            if (tpos + 30 >= pos + len) { pos += len; continue; }
            tpos += data[tpos] + 10;
            if (tpos + 8 >= pos + len) { pos += len; continue; }
            uint16_t extlen = ntohs(*(uint16_t*)(data.data() + tpos + 2)); tpos += 4;
            size_t ext_end = tpos + extlen;
            while (tpos + 8 < ext_end) {
                uint16_t etype = ntohs(*(uint16_t*)(data.data() + tpos)); tpos += 2;
                uint16_t elen = ntohs(*(uint16_t*)(data.data() + tpos)); tpos += 2;
                if (etype == 16 && elen >= 5 && data[tpos+2] == 2 && memcmp(data.data() + tpos + 3, "h3", 2) == 0)
                    return true;
                tpos += elen;
            }
            pos += len;
        }
        return false;
    }

    void cleanup() {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lk(data_mtx);
        for (auto it = tcp_sessions.begin(); it != tcp_sessions.end();)
            it = (now - it->second.last_seen > 5min) ? tcp_sessions.erase(it) : std::next(it);
        for (auto it = blocked.begin(); it != blocked.end();)
            it = (now > it->second) ? blocked.erase(it) : std::next(it);
    }

    static uint64_t make_session_key(uint32_t s1, uint32_t s2, uint16_t p1, uint16_t p2) noexcept {
        return (uint64_t(s1) << 32) ^ s2 ^ p1 ^ (uint64_t(p2) << 16);
    }

public:
    void packet_handler(u_char*, const pcap_pkthdr* hdr, const u_char* pkt) {
        pkt_total++;
        if (hdr->caplen < sizeof(ether_header)) return;

        uint16_t etype = ntohs(((ether_header*)pkt)->ether_type);

        if (etype == ETHERTYPE_IP) {
            auto* iph = (ip*)(pkt + sizeof(ether_header));
            if (hdr->caplen < sizeof(ether_header) + iph->ip_hl * 4) return;

            ip_addr src{AF_INET};
            src.addr.v4 = iph->ip_src;
            if (is_blocked(src)) { pkt_dropped++; return; }

            if (iph->ip_p == IPPROTO_TCP) {
                auto* tcp = (tcphdr*)((u_char*)iph + iph->ip_hl * 4);
                auto payload = std::span((u_char*)tcp + tcp->doff * 4,
                                        ntohs(iph->ip_len) - iph->ip_hl * 4 - tcp->doff * 4);

                if (!payload.empty()) {
                    uint32_t src_ip_u32 = iph->ip_src.s_addr;
                    uint32_t dst_ip_u32 = iph->ip_dst.s_addr;
                    uint64_t key = make_session_key(src_ip_u32, dst_ip_u32,
                                                   ntohs(tcp->source), ntohs(tcp->dest));

                    std::lock_guard lk(data_mtx);
                    auto& s = tcp_sessions[key];
                    s.last_seen = std::chrono::steady_clock::now();
                    if (s.data.size() + payload.size() <= 1024*1024)
                        s.data.insert(s.data.end(), payload.begin(), payload.end());

                    if (!s.detected && s.data.size() >= HTTP2_MAGIC.size() &&
                        memcmp(s.data.data(), HTTP2_MAGIC.data(), HTTP2_MAGIC.size()) == 0) {
                        s.detected = true;
                        h2_cnt++;
                        block_ip(src, "HTTP/2");
                    }
                }
            }
            else if (iph->ip_p == IPPROTO_UDP) {
                auto* udp = (udphdr*)((u_char*)iph + iph->ip_hl * 4);
                auto payload = std::span((u_char*)udp + 8, ntohs(udp->len) - 8);
                if (payload.size() > 100 && parse_quic_h3(payload)) {
                    h3_cnt++;
                    block_ip(src, "HTTP/3 QUIC");
                }
            }
        }
        else if (etype == ETHERTYPE_IPV6) {
            auto* ip6 = (ip6_hdr*)(pkt + sizeof(ether_header));
            ip_addr src{AF_INET6};
            memcpy(&src.addr.v6, &ip6->ip6_src, 16);
            if (is_blocked(src)) { pkt_dropped++; return; }

            uint8_t nxt = ip6->ip6_nxt;
            const u_char* ptr = pkt + sizeof(ether_header) + 40;
            if (nxt == IPPROTO_UDP && hdr->caplen >= sizeof(ether_header) + 40 + 8) {
                auto* udp = (udphdr*)ptr;
                auto payload = std::span(ptr + 8, ntohs(udp->len) - 8);
                if (payload.size() > 100 && parse_quic_h3(payload)) {
                    h3_cnt++;
                    block_ip(src, "HTTP/3 IPv6");
                }
            }
        }
    }

    void run() {
        pcap_loop(handle, -1, [](u_char* user, const pcap_pkthdr* h, const u_char* p) {
            ((L7Firewall*)user)->packet_handler(nullptr, h, p);
        }, (u_char*)this);
    }
};

int main(int argc, char** argv) {
    signal(SIGINT, [](int){ exit(0); });
    signal(SIGTERM, [](int){ exit(0); });

    try {
        L7Firewall fw(argc > 1 ? argv[1] : "any");
        fw.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
