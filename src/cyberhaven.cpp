// CyberHaven – C++17 minimal NDR/IDS skeleton (final polished draft)
// Mission: free, simple, precise defense for small businesses.
// Pipeline: ingest (pcap/json) → analyze (windows/heuristics) → notify (console/webhook)
// License: MIT (c) 2025 Eddie Ocon

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

// OpenSSL for MD5 (JA3 hashing if enabled later)
#include <openssl/md5.h>

// ========================= CONFIG =========================
struct Config {
    std::string iface = "any";
    size_t      batch_max = 256;
    int         batch_timeout_ms = 250;            // ms
    std::chrono::milliseconds cooldown{5000};      // alert dedupe

    // Detection windows / thresholds
    std::chrono::seconds window_bruteforce{60};
    std::chrono::seconds window_portscan{60};
    int bruteforce_threshold = 8;   // failed auths / window
    int portscan_threshold   = 15;  // unique dst ports / window

    // Capture filter (tcpdump syntax)
    std::string bpf;                 // e.g. "tcp port 22 or 3389 or 443"
    std::string bpf_file;            // long filter from file (optional)

    // JA3 blocklist file (one MD5 per line)
    std::string ja3_file;            // e.g. "./config/bad_ja3.txt"

    // Optional simple config (KEY=VALUE)
    std::string config_file;         // e.g. "./config/cyberhaven.conf"
} CFG;

// ========================= EVENTS =========================
struct Event {
    enum class Kind { Packet, SuricataAlert, HoneypotLog } kind{Kind::Packet};

    // Common 5-tuple (IPv4 numerics retained for simplicity)
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  proto{0};  // 6=tcp, 17=udp

    // Canonical textual addresses (IPv4/IPv6 safe if used later)
    std::string src_addr; // "10.0.0.1" or "2001:db8::1"
    std::string dst_addr;

    // Timestamps
    std::chrono::steady_clock::time_point ts = std::chrono::steady_clock::now();

    // Optional
    std::string signature;  // e.g., Suricata SID or tag
    bool        auth_fail{false};

    // TLS metadata (for HTTPS heuristics)
    std::string tls_sni;   // if parsed
    std::string tls_alpn;  // if parsed
    std::string ja3;       // if computed
};

struct Alert {
    enum class Severity { Low, Medium, High, Critical } sev{Severity::Low};
    std::string rule_id;   // e.g., PORT_SCAN, SSH_BRUTE, JA3_MATCH

    // Legacy IPv4 numerics (optional)
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t dst_port{0};

    // Canonical text
    std::string src_addr;
    std::string dst_addr;

    // Optional TLS context
    std::string tls_sni;
    std::string ja3;

    std::string why;       // human explanation
    std::chrono::steady_clock::time_point ts = std::chrono::steady_clock::now();
};

// =================== UTILS ===================
static std::string ip_to_string(uint32_t ip_h){
    uint8_t b1=(ip_h>>24)&0xFF, b2=(ip_h>>16)&0xFF, b3=(ip_h>>8)&0xFF, b4=ip_h&0xFF;
    std::ostringstream o; o<<int(b1)<<"."<<int(b2)<<"."<<int(b3)<<"."<<int(b4); return o.str();
}

// ============ BOUNDED QUEUE ============
template<class T>
class BoundedQueue{
public:
    explicit BoundedQueue(size_t cap):cap_(cap){}
    bool try_push(T&& v){ std::unique_lock<std::mutex> lk(m_); if(q_.size()>=cap_) return false; q_.emplace_back(std::move(v)); cv_.notify_one(); return true; }
    std::vector<T> pop_batch(size_t max_items, std::chrono::milliseconds to){ std::vector<T> out; out.reserve(max_items); std::unique_lock<std::mutex> lk(m_); if(q_.empty()) cv_.wait_for(lk,to,[&]{return !q_.empty()||stop_;}); while(!q_.empty()&&out.size()<max_items){ out.emplace_back(std::move(q_.front())); q_.pop_front(); } return out; }
    bool pop_one(T& out, std::chrono::milliseconds to){ std::unique_lock<std::mutex> lk(m_); if(q_.empty()) cv_.wait_for(lk,to,[&]{return !q_.empty()||stop_;}); if(q_.empty()) return false; out=std::move(q_.front()); q_.pop_front(); return true; }
    void stop(){ {std::lock_guard<std::mutex> lk(m_); stop_=true;} cv_.notify_all(); }
private:
    std::mutex m_; std::condition_variable cv_; std::deque<T> q_; size_t cap_; bool stop_{false};
};

// ===================== INGEST: PCAP =======================
extern "C" { #include <pcap/pcap.h> }

namespace net{ 
#pragma pack(push,1)
struct EthHdr{ uint8_t dst[6]; uint8_t src[6]; uint16_t ethertype; };
struct IPv4Hdr{ uint8_t ver_ihl; uint8_t tos; uint16_t tot_len; uint16_t id; uint16_t frag_off; uint8_t ttl; uint8_t proto; uint16_t check; uint32_t saddr; uint32_t daddr; };
struct TCPHdr{ uint16_t sport; uint16_t dport; uint32_t seq; uint32_t ack_seq; uint8_t doff_res; uint8_t flags; uint16_t window; uint16_t check; uint16_t urg_ptr; };
#pragma pack(pop)
static inline uint16_t ntoh16(uint16_t v){ return (v>>8)|(v<<8);} 
static inline uint32_t ntoh32(uint32_t v){ return ((v&0xFF)<<24)|((v&0xFF00)<<8)|((v&0xFF0000)>>8)|((v>>24)&0xFF);} 
}

class PcapIngestor{
public:
    explicit PcapIngestor(BoundedQueue<Event>& out):out_(out){}
    void start(){ thr_=std::thread([this]{run();}); }
    void stop(){ stop_.store(true); if(pcap_) pcap_breakloop(pcap_); if(thr_.joinable()) thr_.join(); }
private:
    static void pcap_cb(u_char* user, const pcap_pkthdr* h, const u_char* bytes){ auto* self=reinterpret_cast<PcapIngestor*>(user); self->handle(*h,bytes); }

    void handle(const pcap_pkthdr& hdr, const u_char* bytes){
        using namespace net;
        if(hdr.caplen < sizeof(net::EthHdr)) return;
        const auto* eth=reinterpret_cast<const EthHdr*>(bytes);
        uint16_t et=(eth->ethertype>>8)|(eth->ethertype<<8);
        const u_char* p=bytes+sizeof(EthHdr); size_t left=hdr.caplen-sizeof(EthHdr);
        Event e; e.ts=std::chrono::steady_clock::now(); e.kind=Event::Kind::Packet;
        if(et==0x0800 /*IPv4*/){
            if(left<sizeof(IPv4Hdr)) return; auto* ip=reinterpret_cast<const IPv4Hdr*>(p);
            uint8_t ihl=(ip->ver_ihl & 0x0F)*4; if(ihl<20 || left<ihl) return; e.proto=ip->proto;
            e.src_ip=ntoh32(ip->saddr); e.dst_ip=ntoh32(ip->daddr); e.src_addr=ip_to_string(e.src_ip); e.dst_addr=ip_to_string(e.dst_ip);
            const u_char* l4=p+ihl; size_t l4left=left-ihl;
            if(e.proto==6 /*TCP*/){ if(l4left<sizeof(net::TCPHdr)) return; auto* th=reinterpret_cast<const TCPHdr*>(l4); e.src_port=net::ntoh16(th->sport); e.dst_port=net::ntoh16(th->dport); /* TLS parse could be added here */ }
            else if(e.proto==17 /*UDP*/){ if(l4left<4) return; e.src_port=(l4[0]<<8)|l4[1]; e.dst_port=(l4[2]<<8)|l4[3]; }
            else { /* ignore */ }
        } else { return; }
        out_.try_push(std::move(e));
    }

    void run(){
        char err[PCAP_ERRBUF_SIZE] = {0};
        pcap_=pcap_open_live(CFG.iface.c_str(), 65535, 1 /*promisc*/, 10 /*ms*/, err);
        if(!pcap_){ std::cerr<<"[pcap] open_live failed: "<<err<<"\n"; return; }
        // BPF from file takes precedence
        std::string filter = CFG.bpf;
        if(!CFG.bpf_file.empty()){
            std::ifstream f(CFG.bpf_file); if(f){ std::ostringstream ss; ss<<f.rdbuf(); filter=ss.str(); }
        }
        if(!filter.empty()){
            bpf_program fp{}; 
            if(pcap_compile(pcap_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN)==-1){
                std::cerr<<"[pcap] compile failed: "<<pcap_geterr(pcap_)<<" (expr='"<<filter<<"')\n";
            } else { 
                if(pcap_setfilter(pcap_, &fp)==-1) std::cerr<<"[pcap] setfilter failed: "<<pcap_geterr(pcap_)<<"\n"; 
                else std::cout<<"[pcap] BPF active: '"<<filter<<"'\n";
                pcap_freecode(&fp);
            }
        }
        while(!stop_.load()){
            int rc=pcap_dispatch(pcap_, 64, &PcapIngestor::pcap_cb, reinterpret_cast<u_char*>(this));
            if(rc==-1){ std::cerr<<"[pcap] dispatch error: "<<pcap_geterr(pcap_)<<"\n"; break; }
            if(rc==0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if(pcap_){ pcap_close(pcap_); pcap_=nullptr; }
    }

    std::atomic<bool> stop_{false};
    std::thread thr_{}; pcap_t* pcap_{nullptr}; BoundedQueue<Event>& out_;
};

// =================== INGEST: JSON TAILER (stub) ===================
class JsonTailer{
public: explicit JsonTailer(BoundedQueue<Event>& out):out_(out){}
    void start(){ thr_=std::thread([this]{ run(); }); }
    void stop(){ stop_.store(true); if(thr_.joinable()) thr_.join(); }
private:
    void run(){ using namespace std::chrono_literals; while(!stop_.load()){
        // Simulate a failed SSH login every 1.5s
        Event e; e.kind=Event::Kind::HoneypotLog; e.src_ip=0xC0A80164; e.dst_ip=0x0A000002; e.dst_port=22; e.proto=6; e.auth_fail=true; e.ts=std::chrono::steady_clock::now(); out_.try_push(std::move(e)); std::this_thread::sleep_for(1500ms);} }
    std::atomic<bool> stop_{false}; std::thread thr_{}; BoundedQueue<Event>& out_;
};

// =================== ANALYZER ===================
struct SlidingStats{
    std::deque<std::chrono::steady_clock::time_point> auth_fail_ts; // overall count in window
    std::unordered_map<uint32_t, std::unordered_set<uint16_t>> ports_by_src; // src_ip → unique dst ports

    struct Key{ std::string src, ja3, sni; bool operator==(Key const& o) const { return src==o.src && ja3==o.ja3 && sni==o.sni; } };
    struct KeyHash{ size_t operator()(Key const& k) const noexcept { return std::hash<std::string>()(k.src+"|"+k.ja3+"|"+k.sni); } };
    std::unordered_map<Key, std::deque<std::chrono::steady_clock::time_point>, KeyHash> https_hits;

    std::unordered_set<std::string> bad_ja3; // loaded at startup
};

class Analyzer{
public:
    Analyzer(BoundedQueue<Event>& in, BoundedQueue<Alert>& out):in_(in),out_(out){ if(!CFG.ja3_file.empty()){ size_t n=load_bad_ja3(CFG.ja3_file, stats_.bad_ja3); std::cout<<"[ja3] loaded "<<n<<" hash(es) from '"<<CFG.ja3_file<<"'\n"; } }
    void start(){ thr_=std::thread([this]{ run(); }); }
    void stop(){ stop_.store(true); if(thr_.joinable()) thr_.join(); }
private:
    static size_t load_bad_ja3(const std::string& path, std::unordered_set<std::string>& out){ std::ifstream f(path); if(!f){ std::cerr<<"[ja3] could not open blocklist: "<<path<<"\n"; return 0; } size_t c=0; std::string line; auto trim=[](std::string& s){ auto sp=[](unsigned char c){return std::isspace(c);}; while(!s.empty()&&sp(s.front())) s.erase(s.begin()); while(!s.empty()&&sp(s.back())) s.pop_back();}; while(std::getline(f,line)){ trim(line); if(line.empty()||line[0]=='#') continue; if(line.size()==32){ out.insert(line); ++c; } } return c; }

    template<typename Deque>
    static void evict_old(Deque& dq, std::chrono::steady_clock::time_point cutoff){ while(!dq.empty() && dq.front()<cutoff) dq.pop_front(); }
    static void evict_old_ports(std::unordered_map<uint32_t, std::unordered_set<uint16_t>>&, std::chrono::steady_clock::time_point){ /* TODO: track per-port timestamps */ }

    void run(){ while(!stop_.load()){
        auto batch=in_.pop_batch(CFG.batch_max, std::chrono::milliseconds(CFG.batch_timeout_ms)); if(batch.empty()) continue; auto now=std::chrono::steady_clock::now();
        for(auto& e: batch){
            if(e.auth_fail) stats_.auth_fail_ts.push_back(e.ts);
            stats_.ports_by_src[e.src_ip].insert(e.dst_port);
            evict_old(stats_.auth_fail_ts, now - CFG.window_bruteforce);
            evict_old_ports(stats_.ports_by_src, now - CFG.window_portscan);

            if(e.auth_fail && int(stats_.auth_fail_ts.size())>=CFG.bruteforce_threshold){ Alert a; a.sev=Alert::Severity::High; a.rule_id="SSH_BRUTE"; a.src_ip=e.src_ip; a.dst_ip=e.dst_ip; a.dst_port=e.dst_port; a.src_addr=e.src_addr; a.dst_addr=e.dst_addr; a.why="auth_failures >= threshold in sliding window"; out_.try_push(std::move(a)); }

            if(int(stats_.ports_by_src[e.src_ip].size())>=CFG.portscan_threshold){ Alert a; a.sev=Alert::Severity::High; a.rule_id="PORT_SCAN"; a.src_ip=e.src_ip; a.dst_ip=e.dst_ip; a.dst_port=e.dst_port; a.src_addr=e.src_addr; a.dst_addr=e.dst_addr; a.why="unique destination ports >= threshold in sliding window"; out_.try_push(std::move(a)); }

            if(!e.ja3.empty() && stats_.bad_ja3.count(e.ja3)){ Alert a; a.sev=Alert::Severity::High; a.rule_id="JA3_MATCH"; a.src_addr=e.src_addr; a.dst_addr=e.dst_addr; a.dst_port=e.dst_port; a.tls_sni=e.tls_sni; a.ja3=e.ja3; a.why=std::string("JA3 fingerprint matched blocklist: ")+e.ja3; out_.try_push(std::move(a)); }

            if(e.dst_port==443 && !e.ja3.empty()){
                SlidingStats::Key k{ e.src_addr.empty()? ip_to_string(e.src_ip): e.src_addr, e.ja3, e.tls_sni };
                auto& dq=stats_.https_hits[k]; dq.push_back(e.ts); evict_old(dq, now - std::chrono::seconds(90));
                if(dq.size()>=6){ std::vector<double> deltas; deltas.reserve(dq.size()-1); for(size_t i=1;i<dq.size();++i){ auto d=std::chrono::duration_cast<std::chrono::milliseconds>(dq[i]-dq[i-1]).count()/1000.0; deltas.push_back(d);} auto mm=std::minmax_element(deltas.begin(), deltas.end()); if(*mm.second - *mm.first < 0.5){ Alert a; a.sev=Alert::Severity::High; a.rule_id="TLS_BEACON"; a.src_addr=e.src_addr; a.dst_addr=e.dst_addr; a.dst_port=e.dst_port; a.tls_sni=e.tls_sni; a.ja3=e.ja3; a.why="Regular interval TLS traffic on 443 with same JA3/SNI (possible C2 beacon)."; out_.try_push(std::move(a)); dq.clear(); } }
            }
        }
    } }

    std::atomic<bool> stop_{false}; std::thread thr_{}; BoundedQueue<Event>& in_; BoundedQueue<Alert>& out_; SlidingStats stats_{};
};

// =================== NOTIFIER ===================
class Notifier{
public:
    explicit Notifier(BoundedQueue<Alert>& in):in_(in){}
    void set_webhook(std::string url){ std::lock_guard<std::mutex> lk(hook_m_); webhook_url_=std::move(url);} 
    void start(){ thr_=std::thread([this]{ run(); }); }
    void stop(){ stop_.store(true); if(thr_.joinable()) thr_.join(); }
private:
    using Key=std::tuple<std::string,std::string>; // rule_id + src

    static const char* sev_to_str(Alert::Severity s){ switch(s){ case Alert::Severity::Low:return "LOW"; case Alert::Severity::Medium:return "MED"; case Alert::Severity::High:return "HIGH"; case Alert::Severity::Critical:return "CRIT"; } return "?"; }

    static std::string escape_json(const std::string& s){ std::ostringstream o; for(char c: s){ switch(c){ case '"': o<<"\\\""; break; case '\\': o<<"\\\\"; break; case '\n': o<<"\\n"; break; case '\r': o<<"\\r"; break; case '\t': o<<"\\t"; break; default: o<<c; } } return o.str(); }

    void send_webhook(const std::string& url, const Alert& a, const std::string& src_show, const std::string& dst_show){
#ifdef USE_LIBCURL
        std::ostringstream body; body<<"{\"rule\":\""<<a.rule_id<<"\",";
        body<<"\"severity\":\""<<sev_to_str(a.sev)<<"\",";
        body<<"\"src\":\""<<escape_json(src_show)<<"\",";
        body<<"\"dst\":\""<<escape_json(dst_show+":"+std::to_string(a.dst_port))<<"\",";
        if(!a.tls_sni.empty()) body<<"\"sni\":\""<<escape_json(a.tls_sni)<<"\",";
        if(!a.ja3.empty())     body<<"\"ja3\":\""<<escape_json(a.ja3)<<"\",";
        body<<"\"why\":\""<<escape_json(a.why)<<"\"}";
        CURL* curl=curl_easy_init(); if(!curl) return; struct curl_slist* headers=nullptr; headers=curl_slist_append(headers, "Content-Type: application/json"); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); auto payload=body.str(); curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str()); curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L); curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); CURLcode rc=curl_easy_perform(curl); if(rc!=CURLE_OK){ std::cerr<<"[webhook] curl error: "<<curl_easy_strerror(rc)<<"\n"; } curl_slist_free_all(headers); curl_easy_cleanup(curl);
#else
        (void)url; (void)a; (void)src_show; (void)dst_show;
#endif
    }

    void run(){ while(!stop_.load()){
        Alert a; if(!in_.pop_one(a, std::chrono::milliseconds(200))) continue; auto now=std::chrono::steady_clock::now();
        std::string src_key=!a.src_addr.empty()? a.src_addr : (a.src_ip? ip_to_string(a.src_ip) : std::string("-"));
        Key k{a.rule_id, src_key}; auto it=last_alert_.find(k); if(it!=last_alert_.end()){ if(now - it->second < CFG.cooldown) continue; }
        last_alert_[k]=now;
        const std::string src_show = !a.src_addr.empty()? a.src_addr : (a.src_ip? ip_to_string(a.src_ip) : std::string("-"));
        const std::string dst_show = !a.dst_addr.empty()? a.dst_addr : (a.dst_ip? ip_to_string(a.dst_ip) : std::string("-"));
        std::cout<<"[ALERT] rule="<<a.rule_id<<" sev="<<sev_to_str(a.sev)<<" src="<<src_show<<" dst="<<dst_show<<":"<<a.dst_port;
        if(!a.tls_sni.empty()) std::cout<<" sni="<<a.tls_sni;
        if(!a.ja3.empty())     std::cout<<" ja3="<<a.ja3;
        std::cout<<" why="<<a.why<<"\n";
        std::string url; { std::lock_guard<std::mutex> lk(hook_m_); url=webhook_url_; } if(!url.empty()) send_webhook(url, a, src_show, dst_show);
    } }

    std::atomic<bool> stop_{false}; std::thread thr_{}; BoundedQueue<Alert>& in_; std::map<Key, std::chrono::steady_clock::time_point> last_alert_{}; std::mutex hook_m_{}; std::string webhook_url_{};
};

// ========================= MAIN =========================
static std::atomic<bool> g_stop{false};
static void handle_sig(int){ g_stop.store(true); }

static void trim(std::string& s){ auto sp=[](unsigned char c){return std::isspace(c);}; while(!s.empty()&&sp(s.front())) s.erase(s.begin()); while(!s.empty()&&sp(s.back())) s.pop_back(); }

static void load_kv_file(const std::string& path){ std::ifstream f(path); if(!f){ std::cerr<<"[conf] could not open "<<path<<"\n"; return;} std::string line; while(std::getline(f,line)){ trim(line); if(line.empty()||line[0]=='#'||line[0]==';') continue; auto eq=line.find('='); if(eq==std::string::npos) continue; std::string k=line.substr(0,eq), v=line.substr(eq+1); trim(k); trim(v); if(k=="IFACE") CFG.iface=v; else if(k=="BPF") CFG.bpf=v; else if(k=="BPF_FILE") CFG.bpf_file=v; else if(k=="JA3_FILE") CFG.ja3_file=v; else if(k=="WEBHOOK") setenv("CYBERHAVEN_WEBHOOK", v.c_str(), 1); } std::cout<<"[conf] loaded "<<path<<"\n"; }

int main(int argc, char** argv){
    // CLI
    for(int i=1;i<argc;++i){ std::string a=argv[i]; auto need=[&](int idx){ if(idx+1>=argc){ std::cerr<<"missing value for "<<a<<"\n"; std::exit(2);} return std::string(argv[idx+1]); };
        if(a=="--iface" && i+1<argc){ CFG.iface=need(i); ++i; }
        else if(a=="--bpf" && i+1<argc){ CFG.bpf=need(i); ++i; }
        else if(a=="--bpf-file" && i+1<argc){ CFG.bpf_file=need(i); ++i; }
        else if(a=="--ja3-file" && i+1<argc){ CFG.ja3_file=need(i); ++i; }
        else if(a=="--config" && i+1<argc){ CFG.config_file=need(i); load_kv_file(CFG.config_file); ++i; }
        else if(a=="--help"){ std::cout<<"Usage: "<<argv[0]<<" [--iface IFACE] [--bpf \"expr\"] [--bpf-file path] [--ja3-file path] [--config path]\n"; return 0; }
    }

    // Startup summary
    std::cout<<"[cyberhaven-guardian] start\n"
             <<"  iface     : "<<CFG.iface<<"\n"
             <<"  bpf       : "<<(CFG.bpf.empty()&&CFG.bpf_file.empty()? "(none)" : (!CFG.bpf_file.empty()? (std::string("file:")+CFG.bpf_file) : CFG.bpf))<<"\n"
             <<"  ja3 file  : "<<(CFG.ja3_file.empty()?"(none)":CFG.ja3_file)<<"\n";

    // Components & threads
    BoundedQueue<Event> ingestQ(4096); BoundedQueue<Alert> alertQ(1024);
    PcapIngestor pcap(ingestQ); JsonTailer tail(ingestQ); Analyzer analyzer(ingestQ, alertQ); Notifier notifier(alertQ);
    if(const char* wh=getenv("CYBERHAVEN_WEBHOOK")) notifier.set_webhook(wh);

    std::signal(SIGINT, handle_sig); #ifdef SIGTERM
    std::signal(SIGTERM, handle_sig); #endif

    pcap.start(); tail.start(); analyzer.start(); notifier.start();

    std::cout<<"[cyberhaven-guardian] running — press Ctrl+C to stop\n";
    while(!g_stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Shutdown
    ingestQ.stop(); alertQ.stop();
    notifier.stop(); analyzer.stop(); tail.stop(); pcap.stop();
    std::cout<<"[cyberhaven-guardian] stopped\n";
    return 0;
}

/* ========================= BUILD ===========================

Install deps (Debian/Ubuntu):
  sudo apt-get install -y build-essential libpcap-dev libcurl4-openssl-dev libssl-dev

Build (one-liner):
  g++ -std=c++17 -O2 -pthread -DUSE_LIBCURL \
      -o cyberhaven-guardian src/cyberhaven.cpp -lpcap -lcurl -lssl -lcrypto

Run:
  export CYBERHAVEN_WEBHOOK="https://your.webhook.url"   # optional
  sudo ./cyberhaven-guardian --iface eth0 --bpf "tcp port 22 or 3389 or 443" --ja3-file ./config/bad_ja3.txt
  # or
  sudo ./cyberhaven-guardian --config ./config/cyberhaven.conf

Sample config (config/cyberhaven.conf):
  IFACE=eth0
  BPF=tcp port 22 or 3389 or 443
  # or BPF_FILE=./config/filter.bpf
  JA3_FILE=./config/bad_ja3.txt
  WEBHOOK=https://your.webhook.url

JA3 blocklist format (config/bad_ja3.txt):
  # one 32-char MD5 per line, comments allowed
  72a589da586844d7f0818ce684948eea
  d4f5f5c43b8a3e3e1234567890abcdef

================================================================ */
