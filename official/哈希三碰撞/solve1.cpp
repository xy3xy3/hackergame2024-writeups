#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <openssl/sha.h> // 需要安装 OpenSSL 库

int main() {
    uint64_t counter = 0;
    std::unordered_map<uint32_t, std::vector<std::string>> hash_map;

    while (true) {
        // 将计数器转换为 8 字节字符串
        char str[8];
        for (int i = 0; i < 8; ++i) {
            str[7 - i] = (counter >> (8 * i)) & 0xFF;
        }
        // 计算 SHA256 哈希
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)str, 8, hash);
        // 提取哈希值的后 4 个字节
        uint32_t last4bytes = 0;
        for (int i = 0; i < 4; ++i) {
            last4bytes = (last4bytes << 8) | hash[SHA256_DIGEST_LENGTH - 4 + i];
        }
        // 存入映射表
        std::string s(str, 8);
        hash_map[last4bytes].push_back(s);
        // 如果找到三个字符串，输出结果
        if (hash_map[last4bytes].size() == 3) {
            std::cout << "在尝试了 " << counter + 1 << " 次后找到三个字符串，它们的 SHA256 哈希值的后 4 个字节相同：" << std::endl;
            for (const auto& val : hash_map[last4bytes]) {
                // 以十六进制输出字符串
                for (unsigned char c : val) {
                    printf("%02x", (unsigned char)c);
                }
                std::cout << std::endl;
            }
            break;
        }
        counter++;
        if (counter % 1000000 == 0) {
            std::cout << "已尝试了 " << counter << " 个字符串。" << std::endl;
        }
    }

    return 0;
}
