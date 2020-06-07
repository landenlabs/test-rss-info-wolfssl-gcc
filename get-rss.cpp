//
//  HTTPRequest
//

#include <iostream>
#include <fstream>
#include "HTTPRequest.hpp"

int main(int argc, const char* argv[])
{
    std::string url;
    std::string method = "GET";
    std::string arguments;
    std::string output;
    // http::InternetProtocol protocol = http::InternetProtocol::V4;

    try  {
        // you can pass http::InternetProtocol::V6 to Request to make an IPv6 request
        http::Request request("http://landenlabs.com");

        // send a get request
        const http::Response response = request.send("GET");
        std::cout << std::string(response.body.begin(), response.body.end()) << '\n'; // print the result

        if (response.status == http::Response::Ok &&
            !output.empty())  {
            std::ofstream outfile(output, std::ofstream::binary);
            outfile.write(reinterpret_cast<const char*>(response.body.data()),
                            static_cast<std::streamsize>(response.body.size()));
        } else {
            std::cout << std::string(response.body.begin(), response.body.end()) << '\n';
        }  
    }  catch (const std::exception& e)   {
        std::cerr << "Request failed, error: " << e.what() << '\n';
    }
    return EXIT_SUCCESS;
}