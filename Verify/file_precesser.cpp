#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include <iomanip> // 添加这个头文件

namespace fs = std::filesystem;

// 派生AES密钥（128位）
std::vector<unsigned char> derive_key(const std::string& password) {
    unsigned char key[16] = {0}; // 128-bit key
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 现在已定义
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    
    if (1 != EVP_DigestUpdate(mdctx, password.data(), password.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    
    unsigned int len = SHA256_DIGEST_LENGTH;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(mdctx);
    
    std::memcpy(key, hash, 16);
    return std::vector<unsigned char>(key, key + 16);
}

// 使用AES-128-CFB加密数据
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key, 
                                      const std::vector<unsigned char>& data) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    
    std::vector<unsigned char> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0, final_len = 0;
    unsigned char iv[16] = {0}; // 固定IV
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    
    if (1 != EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, data.data(), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    encrypted.resize(out_len + final_len);
    return encrypted;
}

// 计算文件的SHA256
std::vector<unsigned char> calculate_sha256(const fs::path& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) throw std::runtime_error("无法打开文件: " + file_path.string());

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, file.gcount())) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }
    if (!file.eof() || file.gcount() > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, file.gcount())) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    unsigned int len = SHA256_DIGEST_LENGTH;
    if (1 != EVP_DigestFinal_ex(mdctx, hash.data(), &len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(mdctx);
    
    return hash;
}

// 将二进制数据转换为十六进制字符串
std::string to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0] << " <密钥> [目录路径]" << std::endl;
        return 1;
    }

    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();

    try {
        // 获取密钥和路径
        std::string key_str(argv[1]);
        fs::path base_path = (argc > 2) ? fs::path(argv[2]) : fs::current_path();
        fs::path self_path = fs::absolute(argv[0]);

        // 派生AES密钥
        auto aes_key = derive_key(key_str);

        // 创建总哈希上下文 - 这次是直接计算所有文件内容的总哈希
        EVP_MD_CTX* total_ctx = EVP_MD_CTX_new();
        if (!total_ctx) throw std::runtime_error("EVP_MD_CTX_new for total hash failed");
        
        if (1 != EVP_DigestInit_ex(total_ctx, EVP_sha256(), nullptr)) {
            EVP_MD_CTX_free(total_ctx);
            throw std::runtime_error("EVP_DigestInit_ex for total hash failed");
        }

        // 处理特定架构文件
        const std::vector<std::string> arch_exts = {".arm32", ".arm64", ".x86", ".x86_64"};
        std::vector<fs::path> arch_files;

        // 收集所有文件路径并按路径排序（确保顺序一致）
        std::vector<fs::path> file_paths;
        for (const auto& entry : fs::recursive_directory_iterator(base_path)) {
            if (!entry.is_regular_file()) continue;
            
            fs::path file_path = fs::absolute(entry.path()); // 使用绝对路径
            
            // 排除程序自身
            try {
                if (fs::equivalent(file_path, self_path)) continue;
            } catch (...) {
                continue;
            }
            
            file_paths.push_back(file_path);
        }
        
        // 按路径排序
        std::sort(file_paths.begin(), file_paths.end());

        // 处理每个文件
        for (const auto& file_path : file_paths) {
            // 收集架构文件
            std::string ext = file_path.extension().string();
            if (std::find(arch_exts.begin(), arch_exts.end(), ext) != arch_exts.end()) {
                arch_files.push_back(file_path);
            }

            // 读取文件内容并更新总哈希
            std::ifstream file(file_path, std::ios::binary);
            if (!file) throw std::runtime_error("无法打开文件: " + file_path.string());

            char buffer[4096];
            while (file.read(buffer, sizeof(buffer))) {
                if (1 != EVP_DigestUpdate(total_ctx, buffer, file.gcount())) {
                    EVP_MD_CTX_free(total_ctx);
                    throw std::runtime_error("EVP_DigestUpdate for total hash failed");
                }
            }
            if (!file.eof() || file.gcount() > 0) {
                if (1 != EVP_DigestUpdate(total_ctx, buffer, file.gcount())) {
                    EVP_MD_CTX_free(total_ctx);
                    throw std::runtime_error("EVP_DigestUpdate for total hash failed");
                }
            }
        }

        // 完成总哈希计算
        std::vector<unsigned char> total_hash(SHA256_DIGEST_LENGTH);
        unsigned int len = SHA256_DIGEST_LENGTH;
        if (1 != EVP_DigestFinal_ex(total_ctx, total_hash.data(), &len)) {
            EVP_MD_CTX_free(total_ctx);
            throw std::runtime_error("EVP_DigestFinal_ex for total hash failed");
        }
        EVP_MD_CTX_free(total_ctx);

        // 加密并保存总哈希
        auto encrypted_total = aes_encrypt(aes_key, total_hash);
        std::ofstream("sakura", std::ios::binary).write(
            reinterpret_cast<const char*>(encrypted_total.data()), encrypted_total.size());
        std::cout << "生成的总哈希：" << to_hex(total_hash) << std::endl;
        
        // 处理架构文件
        for (const auto& file : arch_files) {
            auto hash = calculate_sha256(file);
            auto encrypted = aes_encrypt(aes_key, hash);
            
            std::string out_name = "hans" + file.extension().string();
            std::ofstream(out_name, std::ios::binary).write(
                reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        }

        std::cout << "处理完成!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}