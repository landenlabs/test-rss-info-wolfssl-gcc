//
//  HTTPRequest
//

#ifndef HTTPSREQUEST_HPP
#define HTTPSREQUEST_HPP

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#define DEBUG_WOLFSSL 1
#define HAVE_SNI
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#if 0
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef _WIN32
#  pragma push_macro("WIN32_LEAN_AND_MEAN")
#  pragma push_macro("NOMINMAX")
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  if _WIN32_WINNT < _WIN32_WINNT_WINXP
char* strdup(const char* src)
{
    std::size_t length = 0;
    while (src[length]) ++length;
    char* result = static_cast<char*>(malloc(length + 1));
    char* p = result;
    while (*src) *p++ = *src++;
    *p = '\0';
    return result;
}
#    include <wspiapi.h>
#  endif
#  include <ws2tcpip.h>
#  pragma pop_macro("WIN32_LEAN_AND_MEAN")
#  pragma pop_macro("NOMINMAX")
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <errno.h>
#  include <arpa/inet.h>
#endif


namespace https
{
    class RequestError final: public std::logic_error
    {
    public:
        explicit RequestError(const char* str): std::logic_error(str) {}
        explicit RequestError(const std::string& str): std::logic_error(str) {}
    };

    class ResponseError final: public std::runtime_error
    {
    public:
        explicit ResponseError(const char* str): std::runtime_error(str) {}
        explicit ResponseError(const std::string& str): std::runtime_error(str) {}
    };

    enum class InternetProtocol: std::uint8_t
    {
        V4,
        V6
    };

    inline namespace detail
    {
#ifdef _WIN32
        class WinSock final
        {
        public:
            WinSock();
            ~WinSock();
            WinSock(WinSock&& other) noexcept;
            WinSock& operator=(WinSock&& other) noexcept;

        private:
            bool started = false;
        };
#endif

        // int getLastError() noexcept;

        // constexpr int getAddressFamily(InternetProtocol internetProtocol);

#ifdef _WIN32
        constexpr auto closeSocket = closesocket;
#else
        constexpr auto closeSocket = close;
#endif

#if defined(__APPLE__) || defined(_WIN32)
        constexpr int noSignal = 0;
#else
        constexpr int noSignal = MSG_NOSIGNAL;
#endif

        class Socket final
        {
        public:
#ifdef _WIN32
            using Type = SOCKET;
            static constexpr Type invalid = INVALID_SOCKET;
#else
            using Type = int;
            static constexpr Type invalid = -1;
#endif

            explicit Socket(InternetProtocol internetProtocol);

            ~Socket();

            Socket(Socket&& other) noexcept;

            Socket& operator=(Socket&& other) noexcept;

            void connect(const struct sockaddr* address, socklen_t addressSize);

            void setupSSL( bool initSSL = true);
            size_t send(const void* buffer, size_t length, int flags);
            size_t recv(void* buffer, size_t length, int flags);

            operator Type() const noexcept { return endpoint; }
            
            void close();

        private:
            Type endpoint = invalid;
#if 0
            SSL_CTX *ctx;
            // SSL* ssl;
 #else
            WOLFSSL_CTX* ctx;
            // WOLFSSL* ssl;
#endif
        public:
              std::string domain;   // DEBUG
        };
    }

    std::string urlEncode(const std::string& str);

    struct Response final
    {
        enum Status
        {
            Continue = 100,
            SwitchingProtocol = 101,
            Processing = 102,
            EarlyHints = 103,

            Ok = 200,
            Created = 201,
            Accepted = 202,
            NonAuthoritativeInformation = 203,
            NoContent = 204,
            ResetContent = 205,
            PartialContent = 206,
            MultiStatus = 207,
            AlreadyReported = 208,
            ImUsed = 226,

            MultipleChoice = 300,
            MovedPermanently = 301,
            Found = 302,
            SeeOther = 303,
            NotModified = 304,
            UseProxy = 305,
            TemporaryRedirect = 307,
            PermanentRedirect = 308,

            BadRequest = 400,
            Unauthorized = 401,
            PaymentRequired = 402,
            Forbidden = 403,
            NotFound = 404,
            MethodNotAllowed = 405,
            NotAcceptable = 406,
            ProxyAuthenticationRequired = 407,
            RequestTimeout = 408,
            Conflict = 409,
            Gone = 410,
            LengthRequired = 411,
            PreconditionFailed = 412,
            PayloadTooLarge = 413,
            UriTooLong = 414,
            UnsupportedMediaType = 415,
            RangeNotSatisfiable = 416,
            ExpectationFailed = 417,
            ImaTeapot = 418,
            MisdirectedRequest = 421,
            UnprocessableEntity = 422,
            Locked = 423,
            FailedDependency = 424,
            TooEarly = 425,
            UpgradeRequired = 426,
            PreconditionRequired = 428,
            TooManyRequests = 429,
            RequestHeaderFieldsTooLarge = 431,
            UnavailableForLegalReasons = 451,

            InternalServerError = 500,
            NotImplemented = 501,
            BadGateway = 502,
            ServiceUnavailable = 503,
            GatewayTimeout = 504,
            HttpVersionNotSupported = 505,
            VariantAlsoNegotiates = 506,
            InsufficientStorage = 507,
            LoopDetected = 508,
            NotExtended = 510,
            NetworkAuthenticationRequired = 511
        };

        int status = 0;
        std::vector<std::string> headers;
        std::vector<std::uint8_t> body;
    };

    class Request final
    {
    public:
        explicit Request(const std::string& url,
                         InternetProtocol protocol = InternetProtocol::V4);
        ~Request();

        Response send(const std::string& method,
                      const std::map<std::string, std::string>& parameters,
                      const std::vector<std::string>& headers = {});

        Response send(const std::string& method = "GET",
                      const std::string& body = "",
                      const std::vector<std::string>& headers = {})
        {
            return send(method,
                        std::vector<uint8_t>(body.begin(), body.end()),
                        headers);
        }

        Response send(const std::string& method,
                      const std::vector<uint8_t>& body,
                      const std::vector<std::string>& headers);

    private:
#ifdef _WIN32
        WinSock winSock;
#endif
        InternetProtocol internetProtocol;
        std::string scheme;
        std::string domain;
        std::string port;
        std::string path;
    };
}

#endif
