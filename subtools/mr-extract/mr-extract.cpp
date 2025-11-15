#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>

/* SGXSDKのフォルダパスはここで指定。自身の環境に合わせて変更する */
std::string sdk_path_default = "/opt/intel/sgxsdk/";

/* 署名済みEnclaveイメージファイル名はここで指定。
 * 自身の環境に合わせて変更する */
std::string image_path_default = "../../enclave.signed.so";


void print_usage(const char* progname)
{
    std::cerr
        << "Usage: " << progname << " [options]\n"
        << "\n"
        << "Options:\n"
        << "  -t, --tool <path>       Path to sgx_sign executable\n"
        << "  -e, --enclave <path>    Path to enclave signed image (.signed.so)\n"
        << "  -h, --help              Show this help and exit\n"
        << "\n"
        << "Behavior:\n"
        << "  * If no options are provided, defaults are used.\n"
        << "    - sgx_sign: <SDK>/bin/x64/sgx_sign  (SDK default: " << sdk_path_default << ")\n"
        << "    - enclave: " << image_path_default << "\n";
}


// 安全にexecvへ渡すargv配列を作るユーティリティ
std::vector<char*> make_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& s : args) {
        argv.push_back(const_cast<char*>(s.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}


int main(int argc, char* argv[])
{
    std::string signing_tool_path;
    std::string image_path = image_path_default;

    static struct option long_opts[] = {
        {"tool",    required_argument, nullptr, 't'},
        {"enclave", required_argument, nullptr, 'e'},
        {"help",    no_argument,       nullptr, 'h'},
        {nullptr,   0,                 nullptr,  0 }
    };

    int opt;
    int opt_index = 0;
    bool image_path_updated = false;

    while ((opt = getopt_long(argc, argv, "t:e:h", long_opts, &opt_index)) != -1) {
        switch (opt) {
            case 't':
                signing_tool_path = optarg;
                break;
            case 'e':
                image_path = optarg;
                image_path_updated = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // 未指定ならデフォルト（SDKパスから組み立て）
    if (signing_tool_path.empty()) {
        std::cout << "Use default sgx_sign path: " << sdk_path_default + std::string("bin/x64/sgx_sign") << std::endl;
        signing_tool_path = sdk_path_default + std::string("bin/x64/sgx_sign");
    }

    if(!image_path_updated)
        std::cout << "Use default Enclave image path: " << image_path_default << std::endl;
    
    pid_t pid;
    int status;

    pid = fork();

    if(pid == -1)
    {
        std::cerr << "Failed to fork process for sgx_sign." << std::endl;
        exit(1);
    }
    else if(pid == 0)
    {
        char *cmd[] = {
            (char*)"sgx_sign",
            (char*)"dump",
            (char*)"-enclave",
            (char*)image_path.c_str(),
            (char*)"-dumpfile",
            (char*)"tmp.txt",
            NULL
        };

        std::cout << "-------- message from sgx_sign tool --------" << std::endl;
        execv(signing_tool_path.c_str(), cmd);

        std::cerr << "Failed to exec sgx_sign." << std::endl;
        exit(1);
    }

    waitpid(pid, &status, 0);
    std::cout << "--------------------------------------------" << std::endl;

    if(!WIFEXITED(status))
    {
        std::cerr << "Failed to exit sgx_sign successfully." << std::endl;
        exit(1); 
    }

    /* ここまで来ればsgx_signの実行は正常に完了している */
    std::ifstream ifs("tmp.txt");

    if(!ifs)
    {
        std::cerr << "Failed to open dump file." << std::endl;
        exit(1);
    }

    std::string line;
    std::string mrenclave, mrsigner;

    while(getline(ifs, line))
    {
        if(line.find("enclave_css.body.enclave_hash.m") != std::string::npos)
        {
            /* MRENCLAVE値を示す2行を読み取る */
            getline(ifs, line);
            mrenclave += line;
            getline(ifs, line);
            mrenclave += line;
        }
        else if(line.find("mrsigner->value") != std::string::npos)
        {
            /* MRSIGNER値を示す2行を読み取る */
            getline(ifs, line);
            mrsigner += line;
            mrsigner += " ";
            getline(ifs, line);
            mrsigner += line;
        }
    }

    //std::cout << mrenclave << std::endl;
    //std::cout << mrsigner << std::endl;

    ifs.close();

    if(0 != std::remove("tmp.txt"))
    {
        std::cerr << "Failed to delete temporary dump file." << std::endl;
        return 1;
    }

    /* 連続的なHexバイト列に変換 */
    std::stringstream mre_ss, mrs_ss;
    std::string byte_hex;

    mre_ss << mrenclave;
    mrs_ss << mrsigner;

    std::cout << "\nCopy and paste following measurement values into settings.ini." << std::endl;
    std::cout << "\033[32mMRENCLAVE value -> \033[m";

    while(getline(mre_ss, byte_hex, ' '))
    {
        byte_hex.erase(0, 2); //"0x"を削除
        std::cout << byte_hex;
    }

    std::cout << "\n\033[32mMRSIGNER value  -> \033[m";

    while(getline(mrs_ss, byte_hex, ' '))
    {
        byte_hex.erase(0, 2); //"0x"を削除
        std::cout << byte_hex;
    }

    std::cout << "\n" << std::endl;

    return 0;
}