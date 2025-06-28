#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <cstring>
#include <set>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

// 派生AES密钥（128位）
std::vector<unsigned char> derive_key(const std::string& password) {
    unsigned char key[16] = {0};
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
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

// 使用AES-128-CFB解密数据
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key, 
                                      const std::vector<unsigned char>& encrypted_data) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    
    std::vector<unsigned char> decrypted(encrypted_data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0, final_len = 0;
    unsigned char iv[16] = {0}; // 固定IV
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    
    if (1 != EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, encrypted_data.data(), encrypted_data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    decrypted.resize(out_len + final_len);
    return decrypted;
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

// 读取整个文件到内存
std::vector<unsigned char> read_file(const fs::path& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("无法打开文件: " + file_path.string());
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("读取文件失败: " + file_path.string());
    }
    return buffer;
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
        base_path = fs::absolute(base_path); // 确保是绝对路径
        fs::path self_path = fs::absolute(argv[0]);

        // 派生AES密钥
        auto aes_key = derive_key(key_str);

        // 创建总哈希上下文
        EVP_MD_CTX* total_ctx = EVP_MD_CTX_new();
        if (!total_ctx) throw std::runtime_error("EVP_MD_CTX_new for total hash failed");
        
        if (1 != EVP_DigestInit_ex(total_ctx, EVP_sha256(), nullptr)) {
            EVP_MD_CTX_free(total_ctx);
            throw std::runtime_error("EVP_DigestInit_ex for total hash failed");
        }

        // 处理特定架构文件
        const std::vector<std::string> arch_exts = {".arm32", ".arm64", ".x86", ".x86_64"};
        std::vector<fs::path> arch_files;

        // 需要排除的特殊文件集合
        std::set<std::string> excluded_files = {
            "sakura",
            "hans.arm32", "hans.arm64", "hans.x86", "hans.x86_64"
        };

        // 收集所有文件路径并按路径排序（确保顺序一致）
        std::vector<fs::path> file_paths;
        for (const auto& entry : fs::recursive_directory_iterator(base_path)) {
            if (!entry.is_regular_file()) continue;
            
            fs::path file_path = fs::absolute(entry.path()); // 使用绝对路径
            std::string filename = file_path.filename().string();
            
            // 排除程序自身
            try {
                if (fs::equivalent(file_path, self_path)) continue;
            } catch (...) {
                continue;
            }
            
            // 排除特殊文件 - 关键修复点
            if (excluded_files.find(filename) != excluded_files.end()) {
                continue;
            }
            
            file_paths.push_back(file_path);
        }
        
        // 按路径排序
        std::sort(file_paths.begin(), file_paths.end());

        // 处理文件
        for (const auto& file_path : file_paths) {
            // 收集架构文件
            std::string ext = file_path.extension().string();
            if (std::find(arch_exts.begin(), arch_exts.end(), ext) != arch_exts.end()) {
                arch_files.push_back(file_path);
            }

            // 更新总哈希 - 使用文件内容更新
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

        // 验证sakura文件
        fs::path sakura_file = base_path / "sakura";
        if (!fs::exists(sakura_file)) {
            throw std::runtime_error("sakura文件不存在");
        }

        auto encrypted_total = read_file(sakura_file);
        auto decrypted_total = aes_decrypt(aes_key, encrypted_total);
        
        // 检查解密后的长度
        if (decrypted_total.size() != SHA256_DIGEST_LENGTH) {
            std::cerr << "警告: 解密后的总哈希长度不正确 (" << decrypted_total.size() 
                      << " != " << SHA256_DIGEST_LENGTH << ")" << std::endl;
        }
        
        bool total_valid = (decrypted_total == total_hash);
        std::cout << "总哈希验证: " << (total_valid ? "成功" : "失败") << std::endl;
        
        // 如果验证失败，输出详细信息
        if (!total_valid) {
            std::cout << "计算的总哈希: " << to_hex(total_hash) << std::endl;
            std::cout << "从sakura解密的总哈希: " << to_hex(decrypted_total) << std::endl;
        }

        // 验证架构文件
        for (const auto& file : arch_files) {
            std::string ext = file.extension().string();
            fs::path hans_file = base_path / ("hans" + ext);
            
            if (!fs::exists(hans_file)) {
                std::cerr << "警告: " << hans_file << " 文件不存在" << std::endl;
                continue;
            }

            // 计算当前文件的哈希
            auto file_hash = calculate_sha256(file);
            
            // 解密存储的哈希
            auto encrypted_hans = read_file(hans_file);
            auto decrypted_hans = aes_decrypt(aes_key, encrypted_hans);
            
            // 检查解密后的长度
            if (decrypted_hans.size() != SHA256_DIGEST_LENGTH) {
                std::cerr << "警告: " << hans_file << " 解密后长度不正确 (" 
                          << decrypted_hans.size() << " != " << SHA256_DIGEST_LENGTH << ")" << std::endl;
            }
            
            bool valid = (decrypted_hans == file_hash);
            std::cout << "文件 " << file.filename() << " 验证: "
                      << (valid ? "成功" : "失败") << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}