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

    // Create a digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        return 1;
    }

    // Fixed CWE-327, use robust hash algorithm
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error initializing SHA-256" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    // Feed the data
    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
        std::cerr << "Error updating digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    // Finalize
    std::vector<unsigned char> hash(EVP_MD_size(EVP_sha256()));
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
        std::cerr << "Error finalizing digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    EVP_MD_CTX_free(ctx);

    std::cout << "SHA-256(\"" << input << "\") = ";
    printHex(hash);

    return 0;
}
