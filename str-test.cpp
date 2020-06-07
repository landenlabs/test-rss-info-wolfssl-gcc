

#include <string>
#include <iostream>
#include <vector>

std::vector<std::string> list;


int main() {
    
    std::string s1 = "/Users/ldennis/android/wxapp/5000/WxApp/src/WxApp/TargetResources/KDFW/app_config.xml";
    list.push_back(s1);
    
    const std::string& s2 = list.front();
    list.erase(0);
    
    std::string s3 = s2;
    s3.erase(0, 10);
    
    std::cout << "s1=" << s1 << std::endl;
    std::cout << "s2=" << s2 << std::endl;
    return 0;
}
