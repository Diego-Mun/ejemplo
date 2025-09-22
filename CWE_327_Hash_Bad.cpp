#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

void printHex(const std::vector<unsigned char>& data) {
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(c);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::string input = "hello world";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        return 1;
    }

    // Initialize for MD5
    //Error CWE-327 use of insegure hash algorithm md5. Error CWE-328, weak hash
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
        std::cerr << "Error initializing MD5" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
        std::cerr << "Error updating digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    std::vector<unsigned char> hash(EVP_MD_size(EVP_md5()));
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
        std::cerr << "Error finalizing digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    EVP_MD_CTX_free(ctx);

    std::cout << "MD5(\"" << input << "\") = ";
    printHex(hash);

    return 0;
}
