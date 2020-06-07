#include "pugixml.hpp"
#include <iostream>
#include <fstream>

// Segv fault handler
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "util/fileutils.hpp"
typedef FileUtils<size_t> FileUtils_t;

const lstring sep = ", ";
struct ParseOptions {
    std::string rssFilterStr;
    std::regex rssFilter;
    unsigned detailRows = 10;
    lstring name;           // directory name of xml
    lstring nameSection;    // dirName_xmlParent
    bool saveWebResponse = false;
};

// Forward
int loadRSSFromURL(const lstring& url, ParseOptions& parseOptions);

/*
<rss xmlns:media="http://search.yahoo.com/mrss/" xmlns:creativeCommons="http://backend.userland.com/creativeCommonsRssModule" xmlns:mcp="http://schema.anvato.com/mcp/" version="2.0">
  <channel>
    <link>https://ep-fox.storage.googleapis.com/l/feeds/xml/26.xml</link>
    <item>
      <media:group>
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_074E3E63D819465AB987B861C16B4B20_200524_687485_May_24_Forecast_350.m3u8?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=pQaOW7Nkx5harcmvSK%2FasCVtmacssKH0LQep3hSjru5Qsi54qgL26ZXHFV5LIZ40de95%2FOzLNA08JxoRDSqdhkxWprGOKoRrfLrP83H3js1U9m0WjmqPEjOTxPNbXAj46MJPl8Y1R3hQQLPOgqMxIC8oYJhcgNoDHCIYyXaB1fFKsYmPkPblNRItWZax9PDtQoFOOd%2BbKmcYWrTrkFUp9KrMb6L4wesm81Y%2FaPXpMIoSicLMfWI4zpZUppAU%2BpHGen08ikN4IMY5lDnUY7bgj8sIT1r6b9s7iteIcdNInR5%2FvhahS%2B4vWBVYWfYrD37rTjdUatikvArfr%2FCIq%2FF9Gw%3D%3D" duration="202" type="video/m3u8" format="m3u8-hp-v3" medium="video" bitrate="414000" width="448" height="252" />
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_A1E0EEE1B62D4E1FA8E6F061D9EA5B6E_200524_687485_May_24_Forecast_700.m3u8?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=WYj0gU5w%2FoxhLjN%2B9sYhqbj%2FAkRQISrJ5DHwDcHjsrzFS%2BAN6wzX2YSYZaSBdBQ9soSi2HUHTr1MZUBXZJYPdlCFtisgdeEVzkLKZJF1CAic%2FeQnxm98I5J7azfP9Tf0Oe9sgZfYVK3knLdY6NFk3CP4zDGLB9WdgsNPa%2BjbKO5szmEzQTW1vQml1l%2B%2BpUM8dk8AhFw4KWdMt4%2FR4CWzIK8V3Rz9ahbOSFwvGZ%2BHlgWks%2F9ilt1ndm44chCPL2xjqqCDojjNLsq9f5SS2n7sJjeVLEcgszEsEXyDujbp%2FrAQQL9O9ll9jZsicnXlmpaY0pFN%2BwDh74mzIAy0YG%2B1Lw%3D%3D" duration="202" type="video/m3u8" format="m3u8-hp-v3" medium="video" bitrate="764000" width="640" height="360" />
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_A1C0C12F43C34F2D8B698ECD0269E9F8_200524_687485_May_24_Forecast_1100.m3u8?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=NeMa7pEu3yFMbcuqEgdbpHcZXQDqyPfMMCIwnFgVTHlXHS9twMQLzow%2BAWct1Kpw7Y7l0g5G%2F3c0yzsRJL%2BUyDq%2F9k69yobNkZndOvAZg80tQ8773KjSqYGFn8rfozcU79rQKh0%2F6fIZ9flegcAS7NLyf13H%2FLgJjqZSKkqMPuogR5y4%2BCH5DoC6%2B5Ng0zUQ6rZPLSUauRPMg3cI8zPDGwSO734ujpI1zjw3x3TDy8ve2WVJQiGkyhjSFh%2FhrrQEsxxYw5CJyCyvKiJOxWzoYLJte%2BZ9CNYAVAlSV2budyRFBUwnl7jCxe0lPChZr5l0ZacC%2BAh3NwGHUh%2FE3WhLwA%3D%3D" duration="202" type="video/m3u8" format="m3u8-hp-v3" medium="video" bitrate="1196000" width="768" height="432" />
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_E6CEB1C9FEF6434B84D7168536666FAF_200524_687485_May_24_Forecast_1800.m3u8?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=X54NbaenUu3Gajmhu2MWiAtwTjsP4THXyurErBEE3WftYNsIXXH%2FCd1jsLLMvR3oWyOvKHHfoTyjuODa%2BRBHc%2FbpbcHqf7%2B%2FX%2FiC7Tf1NU%2B73QiFDuq2yRyoiK5FllMhC9Ih0G2JEXOAM7cSu7temyQek6EZojGkp%2FmIMV2%2BoeH5a6XQAtM6SaCzm7tz6RR%2Fh7ROHNjJFqBw7GOFJx9jrIt%2BEUChODlpt86GSM%2BV4nzMsbxG9DSJhe2Lu4z1n2IGnLOJrH%2Bik1xcoaNGdN2S9Lr8W628KnF%2B90cEyhiIK5BtJT86tjMNEF8kMbwAfSztuwVwHIrorGMrieDL53QZjA%3D%3D" duration="202" type="video/m3u8" format="m3u8-hp-v3" medium="video" bitrate="1896000" width="960" height="540" />
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_8822995845254CEBA9BC45CB2E2A4FF2_200524_687485_May_24_Forecast_2000.mp4?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=ri%2BfQGN8QdTiI8buvhejSKC%2FlaNi%2B01jBP5JrScrJp0anvru82P2n4l%2BIVol8nmSXnpfmqjwh2MGmPPo3ir8NBcdScQsFONMPBoZ8lmxsHRrbdPtbOXPKyLMysdlVR1Muqy4Lg5kuZxwK%2F2APd3dAUTJ3w0R90Vzq2aHH4NfMjCAbBzbWG6x7XcyzQ8rUnC9OTv%2BzPe5mTck2Nm80vXx%2BImiJeFkjO6qvrE19Quk0dzP4Hl0Vjay6eLKdumE8YvZTwnFOmA4JOrYFvxtcIqvPUir03mx%2BaO3dGuFT1Vh48wy9Le3Dg6GioFKuc23mSa81ZMjKPSAcXk%2FJR0jir%2F7jg%3D%3D" duration="202" type="video/mp4" format="mp4-h264-aac" medium="video" bitrate="2128000" width="1280" height="720" />
        <media:content url="https://mcp-cdn-foxlocal-kdfw.storage.googleapis.com/video/video_studio/497/20/05/24/687485/687485_27D2319685F04D10AE8D14DB928164F7_200524_687485_May_24_Forecast_3000.m3u8?GoogleAccessId=onemcpadmin@anvato-mcp-apps.iam.gserviceaccount.com&Expires=1684945016&Signature=Ig3KJNgDUzEuP3KDvnXL7ZTNfgQ313BWYaGu7b8foQbxPJngjIYtQdXVkVxZCVUyJ7lb10ByRZvaAAeekXVntaSyG43PCCaLfy4KNj%2Bqjol3nIvWTfL7jTOvnq6cLBJZq9QSrYycVXbAh1DJTrjprKeM58%2Fig3bi3WlSIr19Anj23%2BA4pdwp9rx3wWRnq%2BVHuOjkYtcir9tBdj5rr1PSj26H370OGWFa9%2BabcAUgGDGAhsGL83DKFMGUdMib0UQiT%2B2akd92mj5CgMxl1gchNO69J5AMRneWQtPkgcH88e5Ep9dk83rx7eK8SJNBZ%2BRajR6sufqXPsBvF5I1LDasRw%3D%3D" duration="202" type="video/m3u8" format="m3u8-hp-v3" medium="video" bitrate="3128000" width="1280" height="720" />
        <media:content url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/videos/variant/687485.m3u8?Expires=1684945016&KeyName=mcpkey1&Signature=kVnQjnKXc4dTv1o00D8aR9P8Zok" duration="202" type="video/m3u8" format="m3u8-variant" medium="video" bitrate="0" width="Variant" height="Variant" />
      </media:group>
      <media:thumbnail url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/iupl/770/097/7700975C967E4344B5F18964928F06C6.jpg?Expires=1684945016&KeyName=mcpkey1&Signature=mxxGdYgeBDOBypoTpXvUiAiql4U" />
      <guid>687485</guid>
      <description>Rain is in the forecast every day this week.</description>
      <title>May 24 Forecast</title>
      <duration>202</duration>
      <pubDate>Sun, 24 May 2020 12:14:21 -0400</pubDate>
      <mcp:captions>
        <mcp:caption_file language="en" format="DFXP" url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/captionupl/866/C44/866C44126F7946D586F4584423F5C96D.dfxp?Expires=1684945016&KeyName=mcpkey1&Signature=z9W-eCigzFtO2H12ESSJVSgQfcM" />
        <mcp:caption_file language="en" format="JSON" url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/captionupl/5DF/4D9/5DF4D9141B6549969EA9866C00A6E767.json?Expires=1684945016&KeyName=mcpkey1&Signature=X8GYkYdr_4Wgai1_0JhJzlbk_B0" />
        <mcp:caption_file language="en" format="SCC" url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/captionupl/320/242/32024258C5A04272A7EEEE26DEB71B1B.scc?Expires=1684945016&KeyName=mcpkey1&Signature=_LOFygpaN05cUQ22xfs-JDGFRHg" />
        <mcp:caption_file language="en" format="SMPTE-TT" url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/captionupl/A05/E9D/A05E9D85DC834B409A1B6B5721E5EFF4.xml?Expires=1684945016&KeyName=mcpkey1&Signature=Qfj7y8DpkkQV_7eFgKbbE_On9jc" />
        <mcp:caption_file language="en" format="VTT" url="https://nmvxdvra2muiv2amejorzkvqgg.gcdn.anvato.net/captionupl/520/68F/52068F8B26354BABADCBC608292D6D6F.vtt?Expires=1684945016&KeyName=mcpkey1&Signature=ktJ5pfs-6rmi07Enov163UCYjq4" />
      </mcp:captions>
    </item>
  </channel>
</rss>
*/

const char* ERROR_PREFIX = "#Error ";
const char* XML_URL_PREFIX  = "-- ";
const char* RSS_ROW1_PREFIX = "\t";
const char* RSS_ROW2_PREFIX = "\t\t";
// -------------------------------------------------------------------------------------------------
void parseRssXml(std::vector<std::uint8_t> xml, const lstring& url, ParseOptions& parseOptions) {
    pugi::xml_document doc;

    pugi::xml_parse_result result = doc.load_buffer(xml.data(), xml.size());
    if (!result) {
        std::cerr << ERROR_PREFIX << "parsing xml " << parseOptions.nameSection
            << " " << result.description() << " error at " << result.offset
            << " length=" << xml.size() << std::endl;
        // std::cerr << "----BEGIN XML---\n";
        // std::cerr << (char*)xml.data();
        // std::cerr << "\n----END XML---\n";
        std::ofstream out(parseOptions.nameSection+"_error.xml", out.trunc);
        out.write((char*)xml.data(), xml.size());
        out.close();
        return;
    }
    
    pugi::xpath_node_set items = doc.select_nodes("//item");
    std::cout << RSS_ROW1_PREFIX << parseOptions.name << "  Items=" << items.size() << std::endl;
    
    unsigned idx = 0;
    for (pugi::xpath_node item : items)  {
        if (idx++ > parseOptions.detailRows) {
           break;
        }
        
        pugi::xpath_node duration = item.node().select_node("/duration");
        //  my @captions = $dom2->findnodes('//*[local-name()="caption_file"]');
        pugi::xpath_node_set mediaContents = item.node().select_nodes("//media:content");
        pugi::xpath_node_set captions = item.node().select_nodes("//mcp:caption_file");
        std::cout << RSS_ROW2_PREFIX << parseOptions.name
                << " " << std::to_string(idx) << ":"
                << " Content=" << mediaContents.size()
                << " Captions=" << captions.size();
        if (!duration.node().empty()) {
            std::cout << " Duration=" << duration.node().text().get();
        }
        
        if (!mediaContents.empty()) {
            for (pugi::xpath_node mediaContent : mediaContents) {
                if (!mediaContent.node().attribute("duration").empty()) {
                    std::cout << " MediaDur=" << mediaContent.node().attribute("duration").value();
                    break;
                }
            }
        }
        
        std::cout << std::endl;
       
    }
}

#if 1
// -------------------------------------------------------------------------------------------------
#include <map>
typedef  std::map<std::string, std::string> ParameterMap;

std::string& extractUrlParameters(lstring& outClean, const std::string inUrl, ParameterMap& outParameters) {
    outClean = inUrl;
#if 0
    size_t optPos = inUrl.find("?");
    if (optPos != std::string::npos) {
        outClean = inUrl.substr(0, optPos);
        Split params(inUrl.substr(optPos+1), "&");
        for (unsigned idx=0; idx < params.size(); idx++) {
            Split tokenValue(params[idx], "=");
            outParameters[tokenValue[0]] = tokenValue.size()==2 ? tokenValue[1] : "";
        }
    }
#endif
    return outClean;
}

// -------------------------------------------------------------------------------------------------
typedef std::vector<std::string> HeaderList;
// Location: https://cbslocal-download.storage.googleapis.com/anv-playlists/feeds/xml/310.xml
std::string getHeader(const HeaderList& headerList, const lstring findHdr) {
    for (const std::string& header : headerList) {
        Split parts(header, ":", 2);
        if (strncasecmp(parts[0].c_str(), findHdr, findHdr.length()) == 0) {
            return parts[1].trim();
        }
    }
    return "";
}


void  addHttpHeaders(HeaderList& headers) {
    headers.push_back("User-Agent: WSIRSS/1.1");
    headers.push_back("Accept: *");     // or */*
    headers.push_back("Accept-Encoding: gzip, deflate, br");
}

#include <fstream>
#include "HTTPSRequest.hpp"
// -------------------------------------------------------------------------------------------------
int loadRSSFromHTTPS(const lstring& url, ParseOptions& parseOptions) {
    std::string arguments;
    // https::InternetProtocol protocol = https::InternetProtocol::V4;

    try  {
        ParameterMap parameters;
        std::vector<std::string> headers;
        addHttpHeaders(headers);
        
        lstring urlClean;
        extractUrlParameters(urlClean, url, parameters);
        
        // You can pass http::InternetProtocol::V6 to Request to make an IPv6 request
        https::Request request(urlClean);
        const https::Response response = request.send("GET", parameters, headers);

        if (response.status == https::Response::Ok) {
            if (parseOptions.saveWebResponse)  {
                std::ofstream outfile(parseOptions.nameSection+".xml", std::ofstream::binary);
                outfile.write(reinterpret_cast<const char*>(response.body.data()),
                                static_cast<std::streamsize>(response.body.size()));
            }
            parseRssXml(response.body, url, parseOptions);
        } else {
            switch (response.status) {
                case https::Response::MovedPermanently:   // 301
                case https::Response::Found:              // 302,    redirect
                case https::Response::TemporaryRedirect:  // 307,
                case https::Response::PermanentRedirect:  // 308,
                    // use header "location" and reload
                    //
                    // Location: https://cbslocal-download.storage.googleapis.com/anv-playlists/feeds/xml/310.xml
                    return loadRSSFromURL(getHeader(response.headers, "Location"), parseOptions);
                    break;
            }
            std::cerr << ERROR_PREFIX << parseOptions.nameSection << " status=" << response.status
                << " url=" << url
                << std::endl;
            std::cerr << "Response Header:\n";
            for (std::string header : response.headers) {
                std::cerr << header << std::endl;
            }
            // std::cerr << std::string(response.body.begin(), response.body.end()) << std::endl;
            return EXIT_FAILURE;
        }
 
    }  catch (const std::exception& e)   {
        std::cerr << ERROR_PREFIX << parseOptions.nameSection << " " << e.what()
             << " url=" << url
             << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

#include "HTTPRequest.hpp"
// -------------------------------------------------------------------------------------------------
int loadRSSFromHTTP(const lstring& url, ParseOptions& parseOptions) {
    std::string arguments;
    // http::InternetProtocol protocol = http::InternetProtocol::V4;

    try  {
        ParameterMap parameters;
        std::vector<std::string> headers;
        addHttpHeaders(headers);
        
        lstring urlClean;
        extractUrlParameters(urlClean, url, parameters);
        
        // You can pass http::InternetProtocol::V6 to Request to make an IPv6 request
        http::Request request(urlClean);
        const http::Response response = request.send("GET", parameters, headers);

        if (response.status == http::Response::Ok) {
            if (parseOptions.saveWebResponse)  {
                std::ofstream outfile(parseOptions.nameSection+".xml", std::ofstream::binary);
                outfile.write(reinterpret_cast<const char*>(response.body.data()),
                                static_cast<std::streamsize>(response.body.size()));
            }
            parseRssXml(response.body, url, parseOptions);
        } else {
            switch (response.status) {
                case http::Response::MovedPermanently:   // 301
                case http::Response::Found:              // 302,    redirect
                case http::Response::TemporaryRedirect:  // 307,
                case http::Response::PermanentRedirect:  // 308,
                    // use header "location" and reload
                    //
                    // Location: https://cbslocal-download.storage.googleapis.com/anv-playlists/feeds/xml/310.xml
                    return loadRSSFromURL(getHeader(response.headers, "Location"), parseOptions);
                    break;
            }
            std::cerr << ERROR_PREFIX << parseOptions.nameSection << " status=" << response.status
                << " url=" << url
                << std::endl;
            std::cerr << "Response Header:\n";
            for (std::string header : response.headers) {
                std::cerr << header << std::endl;
            }
            // std::cerr << std::string(response.body.begin(), response.body.end()) << std::endl;
            return EXIT_FAILURE;
        }
 
    }  catch (const std::exception& e)   {
        std::cerr << ERROR_PREFIX << parseOptions.nameSection << " " << e.what()
             << " url=" << url
             << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// -------------------------------------------------------------------------------------------------
int loadRSSFromURL(const lstring& url, ParseOptions& parseOptions) {
    std::cout << XML_URL_PREFIX << parseOptions.nameSection << sep << url << std::endl;
    if (url.find("https:") != std::string::npos) {
        return loadRSSFromHTTPS(url, parseOptions);
    } else {
        return loadRSSFromHTTP(url, parseOptions);
    }
}
#endif

/* OpenSSL headers */

#if 0
extern "C" {
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
# include  "openssl/bio.h"
# include  "openssl/ssl.h"
# include  "openssl/err.h"

/* Initializing OpenSSL */
SSL_CTX* ctx;

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX* create_context()
{
    const SSL_METHOD* method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configureContext(SSL_CTX* ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }
}

bool doInit = true;
// -------------------------------------------------------------------------------------------------
int loadRSSFromURL(const lstring& url, const lstring& id)
{
    if (doInit) {
        init_openssl();
        ctx = create_context();
        configureContext(ctx);
    }
}

#if 0
// -------------------------------------------------------------------------------------------------
int loadRSSFromURL(const lstring& url, const lstring& id)
{
#if 1
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (! SSL_CTX_load_verify_locations(ctx, "/path/to/TrustStore.pem", NULL))
    {
         // Handle failed load here 
    }

    // Use this at the command line 
    // /usr/local/Cellar/openssl@1.1/1.1.1g/bin/c_rehash /path/to/certfolder
    // Then call this from within the application 
    if (! SSL_CTX_load_verify_locations(ctx, NULL, "/path/to/certfolder"))
    {
        // Handle error here 
    }
#endif
    // ---------

    BIO* bio;
#if 1
    bio = BIO_new_ssl_connect(ctx);
    SSL*  ssl;
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    // Attempt to connect 
    BIO_set_conn_hostname(bio, "hostname:port");
    // Verify the connection opened and perform the handshake  
#else
    bio = BIO_new_connect("hostname:port");
        if (bio == NULL)   {
        // Handle the failure  
    }
#endif

    if (BIO_do_connect(bio) <= 0)  {
        // Handle failed connection  
    } else {
#if 1
        if (SSL_get_verify_result(ssl) != X509_V_OK)
        {
            // Handle the failed verification 
        }
#endif
        char buf[1024];
        int x = BIO_read(bio, buf, sizeof(buf));
        if (x == 0)
        {
            // Handle closed connection  
        }
        else if (x < 0)
        {
            if (! BIO_should_retry(bio))
            {
                // Handle failed read here 
            }

            // Do something to handle the retry 
        }

        // To reuse the connection, use this line 
        BIO_reset(bio);

        // To free it from memory, use this line
        BIO_free_all(bio);
    }
#if 1
    SSL_CTX_free(ctx);
#endif
}
#endif
}
#endif

// -------------------------------------------------------------------------------------------------
size_t onFile(const lstring& fullname, FileUtils_t& fileUtils) {
    fileUtils.fileDirList.push(fullname);
    std::cerr << "Files " << fileUtils.fileDirList.size() << "\t " << fullname << "\r";
    return fileUtils.fileDirList.size();
}
FileUtils_t fileUtils(&onFile, NULL);

// -------------------------------------------------------------------------------------------------
bool getRssUrlFromFile(const lstring& xmlFile, ParseOptions& parseOptions) {
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file(xmlFile.c_str());
    if (!result) {
        std::cerr << ERROR_PREFIX << "parsing xml file " << xmlFile << std::endl;
        return false;
    }
        
    // std::cerr << "Parsed xml file " << xmlFile << std::endl;
    
    // pugi::xpath_node_set tools_with_timeout = doc.select_nodes("//RSS/URL[@Timeout > 0]");
    pugi::xpath_node_set rssList = doc.select_nodes("//RSS");
    
    for (pugi::xpath_node rss : rssList)
    {
        pugi::xml_node url = rss.node().child("URL");
        pugi::xml_node parent = rss.parent();
        lstring urlStr = url.text().get();
        // std::cout << XML_URL_PREFIX << parseOptions.name << sep << parent.name()  << sep << urlStr << std::endl;
        // std::cout << "Tool " << tool.attribute("Filename").value() <<
        //     " has timeout " << tool.attribute("Timeout").as_int() << "\n";
        parseOptions.nameSection = parseOptions.name + "_" + parent.name();
        
        std::smatch smatch;
        if (parseOptions.rssFilterStr.empty() || regex_search(parseOptions.nameSection, smatch, parseOptions.rssFilter)) {
            loadRSSFromURL(urlStr, parseOptions);
        }
    }

#if 0
    for (pugi::xml_node rss2 : doc.child("Configuration").child("Videos").children("RSS"))
    {
        // int timeout = tool.attribute("Timeout").as_int();
        
        // std::cout << "Tool " << tool.attribute("Filename").value() << " has timeout " << timeout << "\n";
        std::cout << "URL2=" << rss2.child("URL").text().get() << std::endl;
    }
#endif
    return true;
}

// =================================================================================================
void showHelp(const char* arg0) {
    cerr << "\n" << arg0 << "  Dennis Lang v1.1 (LandenLabs.com) " __DATE__ << "\n"
    << "\nDes: Load RSS feeds from B2B app_config.xml files.  \n"
    "Use:  [options] directories..|file \n"
    "\n"
    " Options:\n"
    "  -rssFilter  filterPattern   ; Optional RSS filter pattern \n"
    "  -detailRows=nnn             ; Default 20 rows \n"
    "  -saveWebResponse            ; Default not saving \n"
    "\n"
    " Example:\n"
    "   " << arg0 << "TargetResources/*/app_config.xml\n"
    "   " << arg0 << "TargetResources/KDFW/app_config.xml \n"
    "   " << arg0 << "-rss video TargetResources/WCBS/app_config.xml \n"
    "   " << arg0 << "-rss=video TargetResources/WCBS/app_config.xml \n"
    "\n"
    "\n";
}

// -------------------------------------------------------------------------------------------------
void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}

static unsigned optionErrCnt = 0;
// ---------------------------------------------------------------------------
// Validate option matchs and optionally report problem to user.
static
bool ValidOption(const char* validCmd, const char* possibleCmd, bool reportErr = true)
{
    // Starts with validCmd else mark error
    size_t validLen = strlen(validCmd);
    size_t possibleLen = strlen(possibleCmd);
    
    if ( strncasecmp(validCmd, possibleCmd, std::min(validLen, possibleLen)) == 0)
        return true;
    
    if (reportErr)
    {
        std::cerr << "Unknown option:'" << possibleCmd << "', expect:'" << validCmd << "'\n";
        optionErrCnt++;
    }
    return false;
}

// "/Users/ldennis/android/wxapp/5000/WxApp/src/WxApp/TargetResources/*/app_config.xml";
// =================================================================================================
int main(int argc, char* argv[])
{
    signal(SIGSEGV, handler);   // install our handler
 
    if (argc == 1) {
        showHelp(Directory_files::parts(argv[0], false, true, true));
        return -1;
    }
    
    ParseOptions parseOptions;
   
    // ---- Parse runtime arguments (parameters)
    bool doParseCmds = true;
    string endCmds = "--";
    for (int argn = 1; argn < argc; argn++)
    {
        if (*argv[argn] == '-' && doParseCmds)
        {
            lstring argStr(argv[argn]);
            lstring cmd = argv[argn]+1;
            lstring value;
            
            doParseCmds = !(argStr == endCmds);
           
            Split cmdValue(argStr, "=", 2);
            if (cmdValue.size() == 2)
            {
                cmd = cmdValue[0].replaceStr("--", "-");
                value = cmdValue[1];
            }

            switch (cmd[1]) {
            case 'r':   // rssFilter
                if (ValidOption("rssFilter", cmd+1)) {
                    parseOptions.rssFilter = std::regex(value, std::regex_constants::icase);
                    parseOptions.rssFilterStr = value;
                }
                break;
            case 'd':   // detailRows=10
                if (ValidOption("detailRows", cmd+1)) {
                    parseOptions.detailRows = (unsigned)strtol(value, NULL, 10);
                }
                break;
            case 's':   // saveWebResponse
                if (ValidOption("saveWebResponse", cmd+1)) {
                    parseOptions.saveWebResponse = true;
                }
                break;
            default:
                 std::cerr << "Unknown command " << cmd << std::endl;
                 optionErrCnt++;
                 break;
            }
            
        } else {
            const char* scanDir = argv[argn];
            fileUtils.ScanFiles(scanDir);
            std::cerr << std::endl;
        }
    }

    if (optionErrCnt == 0) {
        if (fileUtils.fileDirList.empty()) {
            std::cerr << "No directories or xml files specified\n\n";
            showHelp(argv[0]);
            return -1;
        } else {
            while (!fileUtils.fileDirList.empty()) {
                lstring file = fileUtils.fileDirList.front();
                fileUtils.fileDirList.pop();
              
                PartDirList list = Directory_files::getPartDirs(file);
                parseOptions.name = list.back();
                getRssUrlFromFile(file, parseOptions);
            }
            return 1;
        }
    } else {
        showHelp(argv[0]);
        return -1;
    }
}
