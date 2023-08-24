#include "argus.h"
#include "ladon.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include "argus.pb.h"
#include <google/protobuf/stubs/common.h>
using namespace std;

vector<string> split_string_by_newline(const string& input) {
    vector<string> lines;
    stringstream ss(input);
    string line;

    while (getline(ss, line, '\n')) {
        // 清除行首尾的空白字符
        line.erase(line.begin(), find_if(line.begin(), line.end(), [](int ch) {
            return !isspace(ch);
        }));
        line.erase(find_if(line.rbegin(), line.rend(), [](int ch) {
            return !isspace(ch);
        }).base(), line.end());

        // 如果行不为空，则将其添加到结果中
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    return lines;
}

int test_decrypt_argus() {
    std::string x_argus_list = R"(
            wni3DJwEiI+HxHUBV7pRPrlbBVHGWB0RLrn7nDZpkgT/7b7yUnNoVRYNacd+enlrqS/1/SJZ5peIWg8VIVaXj0mgYHLjK0rGwozg+11YG1QIFo8ABvRjVgo19d2zk2s8Kl8Tuvw5xpScKcTRHW9KpX5IiCTxo/YVdDXipJFgiI/41XgVLQ6Xeb6idXWLtCyt7k/Qt54B50bT1hQ5VcVy0pZufF/4/4Ehd1+L7sHBBHQQsA==
//            VlMKbTQsAIy4ORbvTJviXPX7vhiGcmQPBKnlyYShf0cwJ4voq++9uwan82uPkQ/I6NhvUA5jCq5QVddN0gEIcTIpKicQVVTHQVwDv33Inn1RFCpK3/DA8TRhaeF4hFSrtlFMb4DFMOqA976S6yrPxgeSdWr9DI9EwYhbyNSGX9RHRW5YKSckBS0JrDK/B2Iv2R4WcIt5WkVwu8a+3WmQHaxXMXvpzAZiVtzuXxI8SNJZ6gIk62MIXOOIZEA3BHxFUQJNyIuG5UETTukp2HieOFc8
//            cQKgXKGLXaNm/ndNh695cdi3aUj4rh9roQZXJw6iNO1RD7//sNmsFNCOgiGPwu2qMxDbPvb7NNnrQbEah2KUY2O+wGivO6C32EIvkyY1WR0BfCv4KEMukqyK+ieWcltN5P2+D+k/nq8tAkSLDObOIcCxCti9NfATJUeezKfxNF4ws0cKn0RRtjjNfEaeOg33Cdze/3SeVhS4cWSyb31PYpdzMh5ldkUd55VFhbDSGRuboL75Q+SDOprXeqqIkYXMLo3W/TASHS1gBkuM1UUcJBka
//            +FT5llXVSaCkCWpbSkokeJ77sKJDGjWb8jH6nvzUot7LDDbLJWWTvZHju4fAqI2iaO/yKmfwXGgnJIQIU4yzkbSPsqOwdMXPkq67KJoLuWAcI4ZcU158OuHSG8aBkrk5uJ9wmhNpSX5wl9sUO5/+TC2kwn10F4LohAO/vCCrzApbTkrkEmSBMLloTtugU6lXOpBOwyGri8Q0o1ZGmgtd2r26qo0i24cPW+1WnbyvyMDB7kgn5oNx+4jsj1EzUr+ONjVcwFJeDnuFpiSEfqk5+2v6
)";

    vector<string> lines = split_string_by_newline(x_argus_list);
    for (const string& line : lines) {
        // 注释
        if (line.starts_with("//") || line.starts_with("#")) {
            continue;
        }
        std::string result = decrypt_argus(line.c_str());
        if (result.empty()) {
            cout << "Failed to decrypt " << line << endl;
            continue;
        }

        Argus argus;
        if (!argus.ParseFromArray(result.data(), result.size())) {
            cout << "Failed to deserialization " << line << endl;
        }
        cout << argus.DebugString() << endl;
    }
    return 0;
}

int test_ladon() {
    uint32_t khronos = 1670385975;
    uint32_t random_num = 0x4ec5e0ea;
    const char *success_result = "6uDFTgAFgHqrawu7xugc8VuWS16SZJGK7nl6eXPoq7EltIrf";
    std::string ladon = make_ladon(khronos, random_num);
    if (strcmp(ladon.c_str(), success_result) != 0) {
        printf("计算 ladon 出错\n");
        return -1;
    }
    printf("ladon: %s\n", ladon.c_str());
    return 0;
}

int main() {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    // 生成 ladon
    test_ladon();

    // 解密 argus
    test_decrypt_argus();
    google::protobuf::ShutdownProtobufLibrary();
    return 0;
}
