#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <algorithm>
#include <string.h>
#include <sstream>
#include <time.h>
#include <unordered_set>
#include <ctype.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"
#include "../common/base64.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../common/crypto.hpp"
#include "../common/jwt_util.hpp"
#include "../common/error_print.hpp"

/* SGX related headers */
#include <sgx_uae_launch.h>
#include <sgx_urts.h>
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

using namespace httplib;


/* 双方のセッション公開鍵の連結に対する署名に使用するための
 * 256bit ECDSA秘密鍵。RA中に生成するセッション鍵とは別物。 */
static const uint8_t g_client_signature_private_key[32] = {
    0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
    0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
    0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
    0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18
};


/* settingsファイルからロードした値を格納する構造体 */
typedef struct client_settings_struct
{
    uint32_t client_id;
    uint16_t min_isv_svn;
    uint16_t req_isv_prod_id;
    std::string req_mrenclave;
    std::string req_mrsigner;
    bool skip_mrenclave_check;
    bool allow_sw_hardening_needed;
    bool allow_config_needed;
    bool allow_out_of_date;
    bool allow_debug;
    bool allow_collateral_expiration;
    bool allow_smt_enabled;
    std::string allowed_sa_list;
    uint32_t min_tcb_eval_ds_num;
    std::string req_isv_ext_prod_id;
    std::string req_isv_family_id;
    std::string req_config_id;
    uint16_t min_config_svn;
    uint16_t min_qe_svn;
    uint16_t min_pce_svn;
    std::string req_qe_prod_id;
    std::string req_qe_mrenclave;
    std::string req_qe_mrsigner;
} settings_t;

settings_t g_settings;

/* RAセッション中に発生する鍵関係コンテキスト用構造体 */
typedef struct ra_session_struct
{
    uint8_t g_a[64];
    uint8_t g_b[64];
    uint8_t kdk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} ra_session_t;


/* クライアント向けのsgx_ec256_signature_tの定義 */
typedef struct _client_sgx_ec256_signature_t
{
    uint32_t x[8];
    uint32_t y[8];
} client_sgx_ec256_signature_t;

/* Supplemental Dataのバージョン情報用型定義 */
typedef union _supp_ver_t
{
    uint32_t version;
    struct
    {
        uint16_t major_version;
        uint16_t minor_version;
    };
} supp_ver_t;


/* iniファイルから読み込み、失敗時にはプログラムを即時終了する */
std::string load_from_ini(std::string section, std::string key)
{
    mINI::INIFile file("settings_client.ini");
    mINI::INIStructure ini;

    if(!file.read(ini))
    {
        std::string message = "file read error";
        print_debug_message(message, ERROR);
        exit(1);
    }
    std::string ret = ini.get(section).get(key);

    if(ret.length() == 0)
    {
        std::string message = "Failed to load setting " 
            + key + " from settings_client.ini.";
        print_debug_message(message, ERROR);
        exit(1); 
    }

    return ret;
}


/* 0/1値の読み取りを行いbool値に変換する補助関数 */
bool load_binary_value_to_bool(std::string section, std::string field, std::string flag_name)
{
    uint32_t flag_tmp = 0;

    try
    {
        flag_tmp = std::stoi(load_from_ini(section, field));
    }
    catch(...)
    {
        print_debug_message(
            "Invalid setting. Probably non-integer value was set illegally.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }

    if(!(flag_tmp == 0 || flag_tmp == 1))
    {
        std::string message = flag_name + std::string(" must be 0 or 1.");
        print_debug_message("", ERROR);

        exit(1);
    }

    if(flag_tmp == 0) return false;

    return true;
}


/* 指定が任意な値のロードを行う補助関数 */
std::string load_optional_value(std::string section, std::string field, bool is_int)
{
    std::string tmp_str = load_from_ini(section, field);

    if((is_int == true) && tmp_str != std::string("none"))
    {
        try
        {
            uint32_t int_tmp = std::stoi(tmp_str);
        }
        catch(...)
        {
            print_debug_message(
                "Invalid setting. Probably non-integer value was set illegally.", ERROR);
            print_debug_message("", ERROR);

            exit(1);
        }
    }

    return tmp_str;
}


/* 設定情報の読み込み */
void load_settings()
{
    try
    {
        g_settings.client_id = std::stoi(load_from_ini("client", "CLIENT_ID"));
        g_settings.min_isv_svn = std::stoi(load_from_ini("client", "MINIMUM_ISVSVN"));
        g_settings.req_isv_prod_id = std::stoi(load_from_ini("client", "REQUIRED_ISV_PROD_ID"));
        g_settings.req_mrenclave = load_from_ini("client", "REQUIRED_MRENCLAVE");
        g_settings.req_mrsigner = load_from_ini("client", "REQUIRED_MRSIGNER");
        g_settings.min_tcb_eval_ds_num = std::stoi(load_from_ini("client", "MINIMUM_TCB_EVAL_DATASET_NUM"));
        g_settings.min_config_svn = std::stoi(load_from_ini("client", "MINIMUM_CONFIG_SVN"));
        g_settings.min_pce_svn = std::stoi(load_from_ini("client", "MINIMUM_PCE_SVN"));
        g_settings.min_qe_svn = std::stoi(load_from_ini("client", "MINIMUM_QE_SVN"));
    }
    catch(...)
    {
        print_debug_message(
            "Invalid setting. Probably non-integer value was set illegally.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }
    
    g_settings.skip_mrenclave_check 
        = load_binary_value_to_bool("client", "SKIP_MRENCLAVE_CHECK", "Skip MRENCLAVE check flag");
    g_settings.allow_sw_hardening_needed
        = load_binary_value_to_bool("client", "ALLOW_SW_HARDENING_NEEDED", "SW_HARDENING_NEEDED allowing flag");
    g_settings.allow_config_needed
        = load_binary_value_to_bool("client", "ALLOW_CONFIGURATION_NEEDED", "CONFIGURATION_NEEDED allowing flag");
    g_settings.allow_out_of_date
        = load_binary_value_to_bool("client", "ALLOW_OUT_OF_DATE", "OUT_OF_DATE allowing flag");
    g_settings.allow_debug
        = load_binary_value_to_bool("client", "ALLOW_DEBUG_ENCLAVE", "Debug Enclave allowing flag");
    g_settings.allow_collateral_expiration
        = load_binary_value_to_bool("client", "ALLOW_COLLATERAL_EXPIRATION", "Collateral expiration allowing flag");
    g_settings.allow_smt_enabled
        = load_binary_value_to_bool("client", "ALLOW_SMT_ENABLED", "SMT Enabled allowing flag");

    g_settings.allowed_sa_list = load_from_ini("client", "ALLOWED_SA_LIST");

    g_settings.req_isv_ext_prod_id = load_optional_value("client", "REQUIRED_ISV_EXT_PROD_ID", false);
    g_settings.req_isv_family_id = load_optional_value("client", "REQUIRED_ISV_FAMILY_ID", false);
    g_settings.req_config_id = load_optional_value("client", "REQUIRED_CONFIG_ID", false);
    g_settings.req_qe_prod_id = load_optional_value("client", "REQUIRED_QE_PROD_ID", true);
    g_settings.req_qe_mrenclave = load_optional_value("client", "REQUIRED_QE_MRENCLAVE", false);
    g_settings.req_qe_mrsigner = load_optional_value("client", "REQUIRED_QE_MRSIGNER", false);
}


/* Quote等の整数メンバ表示用関数 */
uint64_t read_uint_from_bin(const uint8_t *p, size_t nbytes)
{
    uint64_t v = 0;
    
    for(size_t i = 0; i < nbytes; ++i)
    {
        v |= (uint64_t)p[i] << (8 * i);
    }

    return v;
}


/* time_tからstringに変換する補助関数 */
std::string time_to_string(time_t t)
{
    std::tm* tm_ptr = std::localtime(&t);
    if(!tm_ptr) return "";

    std::stringstream ss;
    ss << std::put_time(tm_ptr, "%Y/%m/%d %H:%M:%S");

    return ss.str();
}


/* RAの初期化 */
int initialize_ra(std::string server_url, 
    std::string &ra_ctx_b64, ra_session_t &ra_keys)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Initialize RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj;

    std::string client_id_str = std::to_string(g_settings.client_id);

    std::string client_id_b64 = std::string(
        base64_encode<char, char>((char*)client_id_str.c_str(), 
            client_id_str.length()));
    
    req_json_obj["client_id"] = client_id_b64;
    std::string request_json = req_json_obj.dump();

    Client client(server_url);
    auto res = client.Post("/init-ra", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;
    json::JSON res_json_obj;

    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        char *ra_ctx_char;
        size_t ra_ctx_size;

        /* base64形式のRAコンテキストを取得 */
        ra_ctx_b64 = res_json_obj["ra_context"].ToString();

        /* Base64デコード */
        ra_ctx_char = base64_decode<char, char>(
            (char*)res_json_obj["ra_context"].ToString().c_str(), ra_ctx_size);
        
        uint32_t ra_ctx = (uint32_t)std::stoi(ra_ctx_char);

        std::string message_ra_ctx =
            "Received RA context number -> " + std::to_string(ra_ctx);
        print_debug_message(message_ra_ctx, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        /* サーバ側のセッション公開鍵を取得 */
        uint8_t *ga_x, *ga_y;
        size_t tmpsz;

        ga_x = base64_decode<uint8_t, char>(
            (char*)res_json_obj["g_a"]["gx"].ToString().c_str(), tmpsz);

        if(tmpsz != 32)
        {
            print_debug_message("Corrupted server pubkey Ga.g_x.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        ga_y = base64_decode<uint8_t, char>(
            (char*)res_json_obj["g_a"]["gy"].ToString().c_str(), tmpsz);

        if(tmpsz != 32)
        {
            print_debug_message("Corrupted server pubkey Ga.g_y.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        memcpy(ra_keys.g_a, ga_x, 32);
        memcpy(&ra_keys.g_a[32], ga_y, 32);

        print_debug_message("Base64-encoded x-coordinate of Ga ->", DEBUG_LOG);
        print_debug_message(res_json_obj["g_a"]["gx"].ToString(), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
        print_debug_message("Base64-encoded y-coordinate of Ga ->", DEBUG_LOG);
        print_debug_message(res_json_obj["g_a"]["gy"].ToString(), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_binary("x-coordinate of Ga", ra_keys.g_a, 32, DEBUG_LOG);
        print_debug_binary("y-coordinate of Ga", &ra_keys.g_a[32], 32, DEBUG_LOG);

        free(ga_x);
        free(ga_y);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while initializing RA.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* KDK（鍵導出鍵）の導出 */
int generate_kdk(EVP_PKEY *Gb, ra_session_t &ra_keys)
{
    EVP_PKEY *Ga; //ISV側のキーペア（EVP形式）
    uint8_t *Gab_x; //共有秘密
    uint8_t *cmac_key = new uint8_t[16](); //0埋めしてCMACの鍵として使用する
    size_t secret_len;

    /* ISVの鍵をsgx_ec256_public_tからEVP_PKEYに変換 */
    client_sgx_ec256_public_t ga_sgx;
    memcpy(ga_sgx.gx, ra_keys.g_a, 32);
    memcpy(ga_sgx.gy, &ra_keys.g_a[32], 32);

    Ga = evp_pubkey_from_sgx_ec256(&ga_sgx);

    if(Ga == NULL)
    {
        std::string message = "Failed to convert Ga from sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 共有秘密を導出する */
    Gab_x = derive_shared_secret(Ga, Gb, secret_len);

    if(Gab_x == NULL)
    {
        std::string message = "Failed to derive shared secret.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_binary("shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);


    /* 共有秘密をリトルエンディアン化 */
    std::reverse(Gab_x, Gab_x + secret_len);

    print_debug_binary(
        "reversed shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);

    /* CMAC処理を実行してKDKを導出 */
    aes_128bit_cmac(cmac_key, Gab_x, secret_len, ra_keys.kdk);

    print_debug_binary("KDK", ra_keys.kdk, 16, DEBUG_LOG);

    delete[] cmac_key;

    return 0;
}


/* セッションキーペア、共有秘密、SigSPの生成 */
int process_session_keys(ra_session_t &ra_keys, 
    client_sgx_ec256_signature_t &sigsp)
{
    /* クライアント側セッションキーペアの生成 */
    EVP_PKEY *Gb;
    Gb = evp_pkey_generate();

    if(Gb == NULL)
    {
        std::string message = "Failed to generate SP's key pair.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);
        
        return -1;
    }

    int ret = generate_kdk(Gb, ra_keys);

    if(ret)
    {
        std::string message = "Failed to derive KDK.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    /* SPのキーペア公開鍵Gbをsgx_ec256_public_tに変換 */
    client_sgx_ec256_public_t gb_sgx;
    ret = evp_pubkey_to_sgx_ec256(&gb_sgx, Gb);

    if(ret)
    {
        std::string message = "Failed to convert Gb to sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    memcpy(ra_keys.g_b, gb_sgx.gx, 32);
    memcpy(&ra_keys.g_b[32], gb_sgx.gy, 32);

    print_debug_binary("x-coordinate of Gb", ra_keys.g_b, 32, DEBUG_LOG);
    print_debug_binary("y-coordinate of Gb", &ra_keys.g_b[32], 32, DEBUG_LOG);

    /* SigSPの元となる公開鍵の連結を格納する変数 */
    uint8_t gb_ga[128];

    memcpy(gb_ga, ra_keys.g_b, 64);
    memcpy(&gb_ga[64], ra_keys.g_a, 64);

    print_debug_binary("Gb_Ga", gb_ga, 128, DEBUG_LOG);

    /* SigSP（Gb_Gaのハッシュに対するECDSA署名）の生成 */
    uint8_t r[32], s[32];

    EVP_PKEY *sig_priv_key = 
        evp_private_key_from_bytes(g_client_signature_private_key);

    ret = ecdsa_sign(gb_ga, 128, sig_priv_key, r, s);

    if(ret)
    {
        print_debug_message("Failed to sign to Gb_Ga.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("signature r", r, 32, DEBUG_LOG);
    print_debug_binary("signature s", s, 32, DEBUG_LOG);
    
    /* ECDSA署名r, sをリトルエンディアン化 */
    std::reverse(r, r + 32);
    std::reverse(s, s + 32);

    /* sgx_ec256_signature_tがuint32_t[8]で署名を格納する仕様なので、
     * 強引だがuint8_tポインタで参照し1バイトごとに流し込む */
    uint8_t *p_sigsp_r = (uint8_t*)sigsp.x;
    uint8_t *p_sigsp_s = (uint8_t*)sigsp.y;

    for(int i = 0; i < 32; i++)
    {
        p_sigsp_r[i] = r[i];
        p_sigsp_s[i] = s[i];
    }

    print_debug_binary("reversed signature r",
        (uint8_t*)sigsp.x, 32, DEBUG_LOG);
    print_debug_binary("reversed signature s",
        (uint8_t*)sigsp.y, 32, DEBUG_LOG);

    return 0; 
}


/* Quoteの取得 */
int get_quote(std::string server_url, std::string ra_ctx_b64, 
    ra_session_t ra_keys, client_sgx_ec256_signature_t sigsp, 
    uint8_t *&quote_u8, size_t &quote_size)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Get Quote", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(server_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    std::string gb_x_b64, gb_y_b64, sigsp_x_b64, sigsp_y_b64;

    gb_x_b64 = std::string(
        base64_encode<char, uint8_t>(ra_keys.g_b, 32));
    gb_y_b64 = std::string(
        base64_encode<char, uint8_t>(&ra_keys.g_b[32], 32));

    sigsp_x_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)sigsp.x, 32));
    sigsp_y_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)sigsp.y, 32));

    print_debug_message("Base64-encoded Gb and SigSP:", DEBUG_LOG);
    print_debug_message("Gb_x -> " + gb_x_b64, DEBUG_LOG);
    print_debug_message("Gb_y -> " + gb_y_b64, DEBUG_LOG);
    print_debug_message("SigSP_x -> " + sigsp_x_b64, DEBUG_LOG);
    print_debug_message("SigSP_y -> " + sigsp_y_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    std::string client_id_str = std::to_string(g_settings.client_id);

    std::string client_id_b64 = std::string(
        base64_encode<char, char>((char*)client_id_str.c_str(), 
            client_id_str.length()));
    
    req_json_obj["client_id"] = client_id_b64;
    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["g_b"]["gx"] = gb_x_b64;
    req_json_obj["g_b"]["gy"] = gb_y_b64;
    req_json_obj["sigsp"]["x"] = sigsp_x_b64;
    req_json_obj["sigsp"]["y"] = sigsp_y_b64;
    request_json = req_json_obj.dump();


    auto res = client.Post("/get-quote", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;

    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        //VKの生成
        aes_128bit_cmac(ra_keys.kdk, 
        (uint8_t*)("\x01VK\x00\x80\x00"), 6, ra_keys.vk);

        print_debug_binary("VK", ra_keys.vk, 16, DEBUG_LOG);

        uint8_t *ga_gb_vk = new uint8_t[144]();
        memcpy(ga_gb_vk, ra_keys.g_a, 64);
        memcpy(&ga_gb_vk[64], ra_keys.g_b, 64);
        memcpy(&ga_gb_vk[128], ra_keys.vk, 16);

        std::string original_data = 
            std::string(base64_encode<char, uint8_t>(ga_gb_vk, 144));

        print_debug_message("Ga_Gb_VK -> ", DEBUG_LOG);
        print_debug_message(original_data, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        // Report DataがGa、Gb、VKの連結に対するハッシュ値と一致するかを検証する

        // Quoteをバイナリで抽出
        response_json = res_json_obj.dump();

        print_debug_message("Received Quote JSON ->", DEBUG_LOG);
        print_debug_message(response_json, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        quote_u8 = base64_decode<uint8_t, char>
            ((char*)res_json_obj["quote"].ToString().c_str(), quote_size);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while getting quote.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* QvLによりQuoteを検証する */
int verify_quote(uint8_t *quote, size_t quote_size,
    sgx_ql_qv_result_t &quote_verification_result, 
    uint32_t &collateral_expiration_status,
    tee_supp_data_descriptor_t &supp_data)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Verify Quote", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    int ret = 0;
    time_t current_time = 0;
    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    supp_ver_t latest_ver;
    

    dcap_ret = tee_get_supplemental_data_version_and_size(
        quote,
        quote_size,
        &latest_ver.version,
        &supp_data.data_size
    );

    if(dcap_ret == TEE_SUCCESS
        && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t))
    {
        print_debug_message(
            "tee_get_quote_supplemental_data_version_and_size successfully returned.",
            DEBUG_LOG
        );

        print_debug_message("latest supplemental data major version ->", DEBUG_LOG);
        print_debug_message(std::to_string(latest_ver.major_version), DEBUG_LOG);
        print_debug_message("latest supplemental data minor version ->", DEBUG_LOG);
        print_debug_message(std::to_string(latest_ver.minor_version), DEBUG_LOG);
        print_debug_message("latest supplemental data minor size ->", DEBUG_LOG);
        print_debug_message(std::to_string(supp_data.data_size), DEBUG_LOG);

        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);

        if(supp_data.p_data != NULL)
        {
            memset(supp_data.p_data, 0, supp_data.data_size);
        }
        else
        {
            print_debug_message("Failed to allocate memory for supplemental data.", ERROR);
        }
    }
    else
    {
        if(dcap_ret != TEE_SUCCESS)
            print_debug_message("Failed to get size of supplemental data.", WARN);

        if(supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
        {
            print_debug_message("Supplemental data size mismatched.", WARN);
            print_debug_message("Please make sure that you installed QvL and QvE from same release.", WARN);
        }

        supp_data.data_size = 0;
    }

    // 本番環境ではTrusted Timeを用いるようにすべきとのIntelによる注記があるが、
    // ここでは実験用なので通常の時間情報を取得する
    current_time = time(NULL);
    
    // Quote検証の実行
    dcap_ret = tee_verify_quote(
        quote,
        (uint32_t)quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        &supp_data
    );

    if(dcap_ret == TEE_SUCCESS)
    {
        print_debug_message("Verified Quote successfully.", DEBUG_LOG);
    }
    else
    {
        print_ql_status(dcap_ret);
        return -1;
    }

    // Quote検証結果ステータスの確認
    switch(quote_verification_result)
    {
        case TEE_QV_RESULT_OK:
            if(collateral_expiration_status == 0)
            {
                print_debug_message("Quote is Trusted.", INFO);
                ret = 0;
            }
            else
            {
                std::string message = "Quote is Trusted, but collateral is expired";
                message += " based on 'expiration_check_date' you provided.";
                print_debug_message(message, WARN);
                ret = 1;
            }
            break;
        
        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            print_debug_message("Verification completed with non-terminal result.", WARN);
            print_ql_qv_result(quote_verification_result);
            ret = 1;
            break;

        //TDX系ステータスはSGXでは出現し得ないのでFatalエラーとする
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
        case TEE_QV_RESULT_INVALID_SIGNATURE:
        case TEE_QV_RESULT_REVOKED:
        case TEE_QV_RESULT_UNSPECIFIED:
        default:
            print_debug_message("Verification completed with terminal result.", ERROR);
            print_ql_qv_result(quote_verification_result);
            ret = -1;
            break;
    }

    return ret;
}


/* Quoteバッファの範囲外参照防止用 */
bool check_range(size_t offset, size_t length, size_t total_size)
{
    if(offset > total_size) return false;
    if(length > total_size - offset) return false;
    
    return true;
}


/* Quote及び補足情報の内容を表示する */
int display_quote_and_supplemental_data(uint8_t *quote, size_t quote_size,
    sgx_ql_qv_result_t quote_verification_result, 
    uint32_t collateral_expiration_status,
    tee_supp_data_descriptor_t supp_data)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Display Quote and Supplemental Data", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    if(quote_size < 1014)
    {
        print_debug_message("Invalid Quote format.", ERROR);
        return -1;
    }

    print_debug_message("[Quote Header]", DEBUG_LOG);
    print_debug_message("Quote Version ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("Attestation Key Type ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 2, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("TEE Type (must be 0 when using SGX) ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 4, 4)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("QE SVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 8, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);
    
    print_debug_message("PCE SVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 10, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);
    
    print_debug_binary("QE Vendor ID", quote + 12, 16, DEBUG_LOG);
    print_debug_binary("User Data", quote + 28, 20, DEBUG_LOG);

    print_debug_message("[Report Body]", DEBUG_LOG);
    print_debug_binary("CPUSVN", quote + 48, 16, DEBUG_LOG);
    print_debug_binary("MISCSELECT", quote + 64, 4, DEBUG_LOG);
    print_debug_binary("ISV Extended Product ID", quote + 80, 16, DEBUG_LOG);
    print_debug_binary("Attributes", quote + 96, 16, DEBUG_LOG);
    print_debug_binary("MRENCLAVE", quote + 112, 32, DEBUG_LOG);
    print_debug_binary("MRSIGNER", quote + 176, 32, DEBUG_LOG);
    print_debug_binary("Config ID", quote + 240, 64, DEBUG_LOG);

    print_debug_message("Is the Enclave in Debug Mode? ->", DEBUG_LOG);
    uint64_t attr_flags;
    memcpy(&attr_flags, quote + 96, sizeof(uint64_t));

    if((attr_flags & 0x02) != 0) print_debug_message("true", DEBUG_LOG);
    else print_debug_message("false", DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("ISV Product ID ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 304, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("ISV SVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 306, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("Config SVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 308, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_binary("ISV Family ID", quote + 352, 16, DEBUG_LOG);
    print_debug_binary("Report Data", quote + 368, 64, DEBUG_LOG);

    print_debug_message("[Quote Signature Data]", DEBUG_LOG);
    print_debug_message("Quote Signature Data length ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 432, 4)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_binary("Quote signature", quote + 436, 64, DEBUG_LOG);
    print_debug_binary("Public part of Attestation Key", quote + 500, 64, DEBUG_LOG);

    size_t qe_auth_size = (size_t)read_uint_from_bin(quote + 1012, 2);
    print_debug_message("Size of QE authentication data ->", DEBUG_LOG);
    print_debug_message(std::to_string(qe_auth_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    if(!check_range(1014, qe_auth_size, quote_size))
    {
        print_debug_message("Invalid Quote format: QE authentication data out of range.", ERROR);
        return -1;
    }
    print_debug_binary("QE authentication data", quote + 1014, qe_auth_size, DEBUG_LOG);

    size_t cert_type_offset = 1014 + qe_auth_size;

    if(!check_range(cert_type_offset, 6, quote_size))
    {
        print_debug_message("Invalid Quote format: cannot read cert data header.", ERROR);
        return -1;
    }

    int cert_data_type = (int)read_uint_from_bin(quote + cert_type_offset, 2);
    print_debug_message("Certification data type ->", DEBUG_LOG);
    print_debug_message(std::to_string(cert_data_type), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    size_t cert_size_offset = cert_type_offset + 2;
    size_t cert_data_size = (size_t)read_uint_from_bin(quote + cert_size_offset, 4);
    print_debug_message("Size of certification data ->", DEBUG_LOG);
    print_debug_message(std::to_string(cert_data_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    size_t cert_data_offset = cert_size_offset + 4;

    if(!check_range(cert_data_offset, cert_data_size, quote_size))
    {
        print_debug_message("Invalid Quote format: cert data out of range.", ERROR);
        return -1;
    }
    
    if (cert_data_type == 5){
        std::string cert_data(
            (const char*)(quote + cert_data_offset),
            cert_data_size
        );

        print_debug_message("PCK Cert in Quote ->", DEBUG_LOG);
        print_debug_message(cert_data, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else
    {
        print_debug_binary(
            "Certification data in Quote",
            quote + cert_data_offset,
            cert_data_size,
            DEBUG_LOG
        );
    }

    print_debug_message("[QE3 Report Body]", DEBUG_LOG);
    print_debug_binary("QE3 CPUSVN", quote + 564, 16, DEBUG_LOG);
    print_debug_binary("QE3 MISCSELECT", quote + 580, 4,  DEBUG_LOG);
    print_debug_binary("QE3 ISV Extended Product ID", quote + 596, 16, DEBUG_LOG);
    print_debug_binary("QE3 Attributes", quote + 612, 16, DEBUG_LOG);
    print_debug_binary("QE3 MRENCLAVE", quote + 628, 32, DEBUG_LOG);
    print_debug_binary("QE3 MRSIGNER", quote + 692, 32, DEBUG_LOG);
    print_debug_binary("QE3 Config ID", quote + 756, 64, DEBUG_LOG);

    print_debug_message("QE3 ISV Product ID ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 820, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("QE3 ISV SVN (QE SVN) ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 822, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("QE3 Config SVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(read_uint_from_bin(quote + 824, 2)), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_binary("QE3 ISV Family ID", quote + 868, 16, DEBUG_LOG);
    print_debug_binary("QE3 Report Data", quote + 884, 64, DEBUG_LOG);
    
    print_debug_message("[QE3 Report (AK Cert) Signature]", DEBUG_LOG);
    print_debug_binary("QE3 Report Signature", quote + 948, 64, DEBUG_LOG);

    print_debug_message("[Supplemental Data]", DEBUG_LOG);
    print_debug_message("Supplemental Data major version ->", DEBUG_LOG);
    print_debug_message(std::to_string(supp_data.major_version), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    // Supplemental Dataの処理
    if(supp_data.p_data != NULL && supp_data.data_size > 0)
    {
        sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t*)supp_data.p_data;
       
        std::string supp_ver = std::to_string(p->major_version) 
            + std::string(".") + std::to_string(p->minor_version);
        print_debug_message("Supplemental Data version (<major>.<minor>) ->", DEBUG_LOG);
        print_debug_message(supp_ver, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Earliest issue date of all the collateral ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->earliest_issue_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Latest issue date of all the collateral ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->latest_issue_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Earliest expiration date of all the collateral ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->earliest_expiration_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("TCB level date tag", DEBUG_LOG);
        print_debug_message("(meaning that it is not vulnerable to security advisories ", DEBUG_LOG);
        print_debug_message("affecting the SGX TCB published by this date) ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->tcb_level_date_tag), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("CRL number of PCK CRK ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->pck_crl_num), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("CRL number of Root CA CRL ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->root_ca_crl_num), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("The lower of the TCB evaluation dataset number among TCB Info and QE Identity ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->tcb_eval_ref_num), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_binary("Root key ID (SHA-384 hash of root CA's public key)",
            p->root_key_id, ROOT_KEY_ID_SIZE, DEBUG_LOG);

        print_debug_binary("PCK PPID", p->pck_ppid, 16, DEBUG_LOG);

        print_debug_binary("TCBSVN (CPUSVN)", p->tcb_cpusvn.svn, 16, DEBUG_LOG);

        print_debug_message("PCESVN ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->tcb_pce_isvsvn), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("PCEID ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->pce_id), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("TEE Type ->", DEBUG_LOG);
        
        if(p->tee_type == 0x00)
        {
            print_debug_message("0x00 (meaning Intel SGX)", DEBUG_LOG);
        }
        else if(p->tee_type == 0x81)
        {
            print_debug_message("0x81 (meaning Intel TDX)", DEBUG_LOG);
        }
        else
        {
            std::stringstream ss;
            ss << "Unknown TEE type: 0x"
                << std::hex << std::uppercase << p->tee_type;
            print_debug_message(ss.str(), DEBUG_LOG);
        }

        print_debug_message("", DEBUG_LOG);

        print_debug_message("SGX type ->", DEBUG_LOG);

        if(p->sgx_type == 0)
        {
            print_debug_message("Legacy-SGX", DEBUG_LOG);
        }
        else if(p->sgx_type == 1)
        {
            print_debug_message("Scalable-SGX", DEBUG_LOG);
        }
        else if(p->sgx_type == 2)
        {
            print_debug_message("Scalable-SGX with SW-based Cryptographic Integrity (Ci)", DEBUG_LOG);
        }
        else
        {
            std::stringstream ss;
            ss << "Unknown SGX type: 0x"
                << std::hex << std::uppercase << p->sgx_type;
            print_debug_message(ss.str(), DEBUG_LOG);
        }

        print_debug_message("", DEBUG_LOG);

        print_debug_binary("Platform instance ID", 
            p->platform_instance_id, PLATFORM_INSTANCE_ID_SIZE, DEBUG_LOG);
        
        print_debug_message("Is dynamic platform?", DEBUG_LOG);
        print_debug_message("(Indicate whether a platform can be extended with additional packages", DEBUG_LOG);
        print_debug_message(" via Package Add calls to SGX Registration Backend) ->", DEBUG_LOG);
        
        if(p->dynamic_platform == PCK_FLAG_FALSE) print_debug_message("false", DEBUG_LOG);
        else if(p->dynamic_platform == PCK_FLAG_TRUE) print_debug_message("true", DEBUG_LOG);
        else
        {
            std::stringstream ss;
            ss << "undefined or unknown flag: 0x"
                << std::hex << std::uppercase << p->dynamic_platform;
            print_debug_message(ss.str(), DEBUG_LOG);
        }
        
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Is platform root keys cached by SGX Registration Backend? ->", DEBUG_LOG);

        if(p->cached_keys == PCK_FLAG_FALSE) print_debug_message("false", DEBUG_LOG);
        else if(p->cached_keys == PCK_FLAG_TRUE) print_debug_message("true", DEBUG_LOG);
        else
        {
            std::stringstream ss;
            ss << "undefined or unknown flag: 0x"
                << std::hex << std::uppercase << p->cached_keys;
            print_debug_message(ss.str(), DEBUG_LOG);
        }

        print_debug_message("", DEBUG_LOG);

        print_debug_message("Is SMT (hyperthreading) enabled? ->", DEBUG_LOG);
        
        if(p->smt_enabled == PCK_FLAG_FALSE) print_debug_message("false", DEBUG_LOG);
        else if(p->smt_enabled == PCK_FLAG_TRUE) print_debug_message("true", DEBUG_LOG);
        else
        {
            std::stringstream ss;
            ss << "undefined or unknown flag: 0x"
                << std::hex << std::uppercase << p->smt_enabled;
            print_debug_message(ss.str(), DEBUG_LOG);
        }
        print_debug_message("", DEBUG_LOG);

        print_debug_message("List of Security Advisory IDs ->", DEBUG_LOG);

        if(strlen(p->sa_list) == 0) print_debug_message("none", DEBUG_LOG);
        else print_debug_message(std::string(p->sa_list), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Earliest issue date of QE Identity ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->qe_iden_earliest_issue_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Latest issue date of QE Identity ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->qe_iden_latest_issue_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("Earliest expiration date of QE Identity ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->qe_iden_earliest_expiration_date), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("TCB level date tag of QE Identity ->", DEBUG_LOG);
        print_debug_message(time_to_string(p->qe_iden_tcb_level_date_tag), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("TCB evaluation dataset number of QE Identity ->", DEBUG_LOG);
        print_debug_message(std::to_string(p->qe_iden_tcb_eval_ref_num), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_message("QE Identity status ->", DEBUG_LOG);
        print_ql_qv_result(p->qe_iden_status);

    }
    else
    {
        print_debug_message("Supplemental Data is not available.", INFO);
    }


    // print_debug_message(" ->", DEBUG_LOG);
    // print_debug_message(, DEBUG_LOG);
    // print_debug_message("", DEBUG_LOG);

    return 0;
}


static std::string trim(const std::string& s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
    {
        ++start;
    }

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
    {
        --end;
    }

    return s.substr(start, end - start);
}

// コンマ区切りの文字列をセットへ
static std::unordered_set<std::string> split_to_set(const std::string& csv)
{
    std::unordered_set<std::string> result;
    std::stringstream ss(csv);
    std::string item;

    while (std::getline(ss, item, ','))
    {
        item = trim(item);
        if (!item.empty())
        {
            result.insert(item);
        }
    }
    return result;
}


/* Attester Enclaveの各種同一性の検証を行う */
bool appraise_quote_and_supplemental_data(uint8_t *quote, size_t quote_size, 
            sgx_ql_qv_result_t quote_verification_result, 
            uint32_t collateral_expiration_status,
            tee_supp_data_descriptor_t supp_data, ra_session_t ra_keys)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Verify Enclave identity", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    /* 境界外参照の抑止 */
    if(1012 > quote_size) //QE3 Report Signatureまでのサイズ
    {
        print_debug_message("Corrupted Quote structure.", ERROR);
        print_debug_message("", ERROR);

        return false;
    }

    bool is_ra_trusted = false;    
    
    uint8_t *quote_mrenclave = new uint8_t[32]();
    uint8_t *quote_mrsigner = new uint8_t[32]();
    uint16_t quote_isvprodid = 0;
    uint16_t quote_isvsvn = 0;
    uint64_t quote_attr_flags = 0;
    uint8_t *quote_upper_data = new uint8_t[32]();
    uint8_t *quote_isv_ext_prod_id = new uint8_t[16]();
    uint8_t *quote_isv_family_id = new uint8_t[16]();
    uint8_t *quote_config_id = new uint8_t[64]();
    uint16_t quote_config_svn = 0;
    uint16_t quote_pce_svn = 0;
    uint16_t quote_qe_svn = 0;
    uint16_t quote_qe_prod_id = 0;
    uint8_t *quote_qe_mrenclave = new uint8_t[32]();
    uint8_t *quote_qe_mrsigner = new uint8_t[32]();

    bool supp_smt_enabled = false;
    std::string supp_sa_list = "";
    uint32_t supp_tcb_eval_ds_num = 0;
    
    uint8_t *ga_gb_vk = new uint8_t[144]();

    sgx_ql_qv_supplemental_t *supp_p = (sgx_ql_qv_supplemental_t*)supp_data.p_data;

    try
    {
        //112はsgx_quote3_t内のReport Body内MRENCLAVEまでのオフセット
        memcpy(quote_mrenclave, quote + 112, 32);
        memcpy(quote_mrsigner, quote + 176, 32);
        memcpy(&quote_isvprodid, quote + 304, 2);
        memcpy(&quote_isvsvn, quote + 306, 2);
        memcpy(&quote_attr_flags, quote + 96, sizeof(uint64_t));
        memcpy(quote_upper_data, quote + 368, 32);
        memcpy(&quote_config_svn, quote + 308, 2);
        memcpy(&quote_qe_svn, quote + 8, 2);
        memcpy(&quote_pce_svn, quote + 10, 2);

        supp_smt_enabled = supp_p->smt_enabled;
        supp_sa_list = std::string(supp_p->sa_list);
        supp_tcb_eval_ds_num = supp_p->tcb_eval_ref_num;

        /* MRENCLAVEのチェック */
        if(g_settings.skip_mrenclave_check == false)
        {
            std::string q_mrenclave_hex = std::string(to_hexstring(quote_mrenclave, 32));

            print_debug_message("Required MRENCLAVE ->", DEBUG_LOG);
            print_debug_message(g_settings.req_mrenclave, DEBUG_LOG);
            print_debug_message("MRENCLAVE from Quote ->", DEBUG_LOG);
            print_debug_message(q_mrenclave_hex, DEBUG_LOG);
            
            //要求値とQuote内の要素との比較
            if(g_settings.req_mrenclave != q_mrenclave_hex)
            {
                print_debug_message("", ERROR);
                print_debug_message("MRENCLAVE mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                is_ra_trusted = false;

                throw std::exception();
            }

            print_debug_message("MRENCLAVE matched.", INFO);
            print_debug_message("", INFO);
        }

        /* MRSIGNERのチェック */
        std::string q_mrsigner_hex = std::string(to_hexstring(quote_mrsigner, 32));

        print_debug_message("Required MRSIGNER ->", DEBUG_LOG);
        print_debug_message(g_settings.req_mrsigner, DEBUG_LOG);
        print_debug_message("MRSIGNER from Quote ->", DEBUG_LOG);
        print_debug_message(q_mrsigner_hex, DEBUG_LOG);

        if(g_settings.req_mrsigner != q_mrsigner_hex)
        {
            print_debug_message("", ERROR);
            print_debug_message("MRSIGNER mismatched. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_message("MRSIGNER matched.", INFO);
        print_debug_message("", INFO);

        /* ISVSVNのチェック */
        print_debug_message("Required ISVSVN ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.min_isv_svn), DEBUG_LOG);
        print_debug_message("ISVSVN from Quote ->", DEBUG_LOG);
        print_debug_message(std::to_string(quote_isvsvn), DEBUG_LOG);

        if(g_settings.min_isv_svn > quote_isvsvn)
        {
            print_debug_message("", ERROR);
            print_debug_message("Insufficient ISVSVN. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_message("ISVSVN validated.", INFO);
        print_debug_message("", INFO);

        /* ISV ProdIDのチェック */
        print_debug_message("Required ISV ProdID ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.req_isv_prod_id), DEBUG_LOG);
        print_debug_message("ISV ProdID from Quote ->", DEBUG_LOG);
        print_debug_message(std::to_string(quote_isvsvn), DEBUG_LOG);

        if(g_settings.req_isv_prod_id != quote_isvprodid)
        {
            print_debug_message("", ERROR);
            print_debug_message("ISV ProdID mismatched. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_message("ISV ProdID matched.", INFO);
        print_debug_message("", INFO);

        /* RAステータスのチェック */
        if(quote_verification_result == TEE_QV_RESULT_CONFIG_NEEDED
            || quote_verification_result == TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
            || quote_verification_result == TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED)
        {
            if(g_settings.allow_config_needed == true)
            {
                print_debug_message("The RA status includes CONFIGURATION_NEEDED, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("The RA status includes CONFIGURATION_NEEDED, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        if(quote_verification_result == TEE_QV_RESULT_SW_HARDENING_NEEDED
            || quote_verification_result == TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED)
        {
            if(g_settings.allow_sw_hardening_needed == true)
            {
                print_debug_message("The RA status includes SW_HARDENING_NEEDED, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("The RA status includes SW_HARDENING_NEEDED, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        if(quote_verification_result == TEE_QV_RESULT_OUT_OF_DATE
            || quote_verification_result == TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED)
        {
            if(g_settings.allow_out_of_date == true)
            {
                print_debug_message("The RA status includes OUT_OF_DATE, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("The RA status includes OUT_OF_DATE, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* DebugモードEnclaveであるかのチェック */
        if((quote_attr_flags & 0x02) != 0)
        {
            if(g_settings.allow_debug == true)
            {
                print_debug_message("The Enclave is run in Debug mode, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("The Enclave is run in Debug mode, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }
        else
        {
            print_debug_message("The Enclave is run in Production mode.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }

        /* コラテラルの期限切れのチェック */
        if(collateral_expiration_status)
        {
            if(g_settings.allow_collateral_expiration == true)
            {
                print_debug_message("One or more collaterals have expired, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("One or more collaterals have expired, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* ハイパースレッド有効化状況のチェック */
        if(supp_smt_enabled == true)
        {
            if(g_settings.allow_smt_enabled == true)
            {
                print_debug_message("SMT is enabled in attester's machine, ", WARN);
                print_debug_message("allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else
            {
                print_debug_message("SMT is enabled in attester's machine, ", ERROR);
                print_debug_message("disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }
        else
        {
            print_debug_message("SMT is disabled in attester's machine.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }

        /* 脆弱性セキュリティアドバイザリ（SA）リストのチェック */
        print_debug_message("Reported Security Advisory(SA) list ->", DEBUG_LOG);
        if(supp_sa_list.length() <= 0)
        {
            print_debug_message("none", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            print_debug_message(supp_sa_list, DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
            
            if(g_settings.allowed_sa_list == "ALL")
            {
                print_debug_message("Any of SA is allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
            else if(g_settings.allowed_sa_list.length() <= 0)
            {
                print_debug_message("Any of SA is disallowed by user's policy. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
            else
            {
                std::unordered_set<std::string> allowed = split_to_set(g_settings.allowed_sa_list);
                std::unordered_set<std::string> supp_set = split_to_set(supp_sa_list);

                for (std::unordered_set<std::string>::const_iterator it = supp_set.begin();
                    it != supp_set.end(); ++it)
                {
                    if (allowed.find(*it) == allowed.end())
                    {
                        print_debug_message("SA disallowed by user's policy is detected. Reject RA.", ERROR);
                        print_debug_message("", ERROR);

                        throw std::exception();
                    }
                }
                
                print_debug_message("All of reported SAs are allowed by user's policy.", WARN);
                print_debug_message("", WARN);
            }
        }

        /* TCB Evaluation Dataset Numberのチェック */
        print_debug_message("Required TCB evaluation dataset number ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.min_tcb_eval_ds_num), DEBUG_LOG);
        print_debug_message("TCB evaluation dataset number from Supplemental Data ->", DEBUG_LOG);
        print_debug_message(std::to_string(supp_tcb_eval_ds_num), DEBUG_LOG);

        if(supp_tcb_eval_ds_num < g_settings.min_tcb_eval_ds_num)
        {
            print_debug_message("Insufficient TCB evaluation dataset number. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_message("TCB evaluation dataset number validated.", DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        /* ISV拡張ProdIDのチェック */
        if(g_settings.req_isv_ext_prod_id == "none")
        {
            print_debug_message("Skip ISV Extended Product ID check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(quote_isv_ext_prod_id, quote + 80, 16);
            std::string q_isv_ext_prod_id_hex = std::string(to_hexstring(quote_isv_ext_prod_id, 16));

            print_debug_message("Required ISV Extended Product ID ->", DEBUG_LOG);
            print_debug_message(g_settings.req_isv_ext_prod_id, DEBUG_LOG);
            print_debug_message("ISV Extended Product ID from Quote ->", DEBUG_LOG);
            print_debug_message(q_isv_ext_prod_id_hex, DEBUG_LOG);

            if(g_settings.req_isv_ext_prod_id == q_isv_ext_prod_id_hex)
            {
                print_debug_message("ISV Extended Product ID matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("ISV Extended Product ID mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* ISV Family IDのチェック */
        if(g_settings.req_isv_family_id == "none")
        {
            print_debug_message("Skip ISV Family ID check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(quote_isv_family_id, quote + 352, 16);
            std::string q_isv_family_id_hex = std::string(to_hexstring(quote_isv_family_id, 16));

            print_debug_message("Required ISV Family ID ->", DEBUG_LOG);
            print_debug_message(g_settings.req_isv_family_id, DEBUG_LOG);
            print_debug_message("ISV Family ID from Quote ->", DEBUG_LOG);
            print_debug_message(q_isv_family_id_hex, DEBUG_LOG);

            if(g_settings.req_isv_family_id == q_isv_family_id_hex)
            {
                print_debug_message("ISV Family ID matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("ISV Family ID mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* Config IDのチェック */
        if(g_settings.req_config_id == "none")
        {
            print_debug_message("Skip Config ID check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(quote_config_id, quote + 240, 64);
            std::string q_config_id_hex = std::string(to_hexstring(quote_config_id, 64));

            print_debug_message("Required Config ID ->", DEBUG_LOG);
            print_debug_message(g_settings.req_config_id, DEBUG_LOG);
            print_debug_message("Config ID from Quote ->", DEBUG_LOG);
            print_debug_message(q_config_id_hex, DEBUG_LOG);

            if(g_settings.req_config_id == q_config_id_hex)
            {
                print_debug_message("Config ID matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("Config ID mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* Config SVNのチェック */
        print_debug_message("Required Config SVN ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.min_config_svn), DEBUG_LOG);
        print_debug_message("Config SVN from Quote ->", DEBUG_LOG);
        print_debug_message(std::to_string(quote_config_svn), DEBUG_LOG);

        if(quote_config_svn < g_settings.min_config_svn)
        {
            print_debug_message("Insufficient Config SVN. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        /* QE SVNのチェック */
        print_debug_message("Required QE SVN ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.min_qe_svn), DEBUG_LOG);
        print_debug_message("QE SVN from Quote ->", DEBUG_LOG);
        print_debug_message(std::to_string(quote_qe_svn), DEBUG_LOG);

        if(quote_qe_svn < g_settings.min_qe_svn)
        {
            print_debug_message("Insufficient QE SVN. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        /* PCE SVNのチェック */
        print_debug_message("Required PCE SVN ->", DEBUG_LOG);
        print_debug_message(std::to_string(g_settings.min_pce_svn), DEBUG_LOG);
        print_debug_message("PCE SVN from Quote ->", DEBUG_LOG);
        print_debug_message(std::to_string(quote_pce_svn), DEBUG_LOG);

        if(quote_pce_svn < g_settings.min_pce_svn)
        {
            print_debug_message("Insufficient PCE SVN. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        /* QE3 ProdIDのチェック */
        if(g_settings.req_qe_prod_id == "none")
        {
            print_debug_message("Skip QE3 Prod ID check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(&quote_qe_prod_id, quote + 820, 2);

            print_debug_message("Required Config ID ->", DEBUG_LOG);
            print_debug_message(g_settings.req_config_id, DEBUG_LOG);
            print_debug_message("Config ID from Quote ->", DEBUG_LOG);
            print_debug_message(std::to_string(quote_qe_prod_id), DEBUG_LOG);

            if(g_settings.req_qe_prod_id == std::to_string(quote_qe_prod_id))
            {
                print_debug_message("QE3 Prod ID matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("QE3 Prod ID mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* QE3 MRENCLAVEのチェック */
        if(g_settings.req_qe_mrenclave == "none")
        {
            print_debug_message("Skip QE3 MRENCLAVE check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(quote_qe_mrenclave, quote + 628, 32);
            std::string q_qe_mrenclave_hex = std::string(to_hexstring(quote_qe_mrenclave, 32));

            print_debug_message("Required QE3 MRENCLAVE ->", DEBUG_LOG);
            print_debug_message(g_settings.req_qe_mrenclave, DEBUG_LOG);
            print_debug_message("QE3 MRENCLAVE from Quote ->", DEBUG_LOG);
            print_debug_message(q_qe_mrenclave_hex, DEBUG_LOG);

            if(g_settings.req_qe_mrenclave == q_qe_mrenclave_hex)
            {
                print_debug_message("QE3 MRENCLAVE matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("QE3 MRENCLAVE mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* QE3 MRSIGNERのチェック */
        if(g_settings.req_qe_mrsigner == "none")
        {
            print_debug_message("Skip QE3 MRSIGNER check.", DEBUG_LOG);
            print_debug_message("", DEBUG_LOG);
        }
        else
        {
            memcpy(quote_qe_mrsigner, quote + 692, 32);
            std::string q_qe_mrsigner_hex = std::string(to_hexstring(quote_qe_mrsigner, 32));

            print_debug_message("Required QE3 MRSIGNER ->", DEBUG_LOG);
            print_debug_message(g_settings.req_qe_mrsigner, DEBUG_LOG);
            print_debug_message("QE3 MRSIGNER from Quote ->", DEBUG_LOG);
            print_debug_message(q_qe_mrsigner_hex, DEBUG_LOG);

            if(g_settings.req_qe_mrsigner == q_qe_mrsigner_hex)
            {
                print_debug_message("QE3 MRSIGNER matched.", DEBUG_LOG);
                print_debug_message("", DEBUG_LOG);
            }
            else
            {
                print_debug_message("QE3 MRSIGNER mismatched. Reject RA.", ERROR);
                print_debug_message("", ERROR);

                throw std::exception();
            }
        }

        /* Report DataがGa||Gb||VKに対するハッシュ値であるかを確認する。 */
        //VKの生成
        aes_128bit_cmac(ra_keys.kdk, 
        (uint8_t*)("\x01VK\x00\x80\x00"), 6, ra_keys.vk);

        print_debug_binary("VK", ra_keys.vk, 16, DEBUG_LOG);

        memcpy(ga_gb_vk, ra_keys.g_a, 64);
        memcpy(&ga_gb_vk[64], ra_keys.g_b, 64);
        memcpy(&ga_gb_vk[128], ra_keys.vk, 16);

        uint8_t data_hash[32] = {0};
        int ret = sha256_digest(ga_gb_vk, 144, data_hash);
        
        if(ret)
        {
            print_debug_message("Failed to obtain hash of ga_gb_vk.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_binary("Derived hash of Ga||Gb||VK", 
            data_hash, 32, DEBUG_LOG);
        print_debug_binary("Upper 32bits of Report Data in the Quote", 
            quote_upper_data, 32, DEBUG_LOG);

        if(memcmp(data_hash, quote_upper_data, 32))
        {
            print_debug_message("Report Data mismatched.", ERROR);
            print_debug_message("", ERROR);

            throw std::exception();
        }

        print_debug_message("Report Data matched.", INFO);
        print_debug_message("", INFO);

        is_ra_trusted = true;
    }
    catch(...)
    {
        memset(ga_gb_vk, 0, 144);

        free(quote_mrenclave);
        free(quote_mrsigner);
        free(quote_upper_data);
        free(quote_isv_ext_prod_id);
        free(quote_isv_family_id);
        free(quote_config_id);
        free(quote_qe_mrenclave);
        free(quote_qe_mrsigner);
        free(ga_gb_vk);
    }

    return is_ra_trusted;
}


int send_ra_result(std::string server_url, 
    std::string ra_ctx_b64, bool ra_result)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Send RA result to SGX server", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    std::string request_json;
    json::JSON req_json_obj, res_json_obj;

    req_json_obj["ra_context"] = ra_ctx_b64;
    
    if(ra_result == true)
        req_json_obj["ra_result"] = std::string("true");
    else
        req_json_obj["ra_result"] = std::string("false");

    request_json = req_json_obj.dump();

    Client client(server_url);
    auto res = client.Post("/ra-result", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        print_debug_message("Sent RA result successfully.", DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while sending RA result.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* RAを実行する関数 */
int do_RA(std::string server_url,
    std::string &ra_ctx_b64, uint8_t *&sk, uint8_t *&mk)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Remote Attestation Preparation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    /* 暗号処理関数向けの初期化（事前処理） */
    crypto_init();

    /* RAセッション鍵関連構造体の生成 */
    ra_session_t ra_keys;

    /* RAの初期化 */
    int ret = initialize_ra(server_url, ra_ctx_b64, ra_keys);
    if(ret) return -1;

    /* セッションキーペア、共有秘密、SigSPの生成 */
    client_sgx_ec256_signature_t sigsp;
    ret = process_session_keys(ra_keys, sigsp);
    if(ret) return -1;    

    /* Quoteの取得 */
    uint8_t *quote_u8;
    size_t quote_size = 0;
    ret = get_quote(server_url, ra_ctx_b64, ra_keys, 
        sigsp, quote_u8, quote_size);
    if(ret) return -1;

    /* QvLによりQuoteの検証を実施する */
    sgx_ql_qv_result_t quote_verification_result = TEE_QV_RESULT_UNSPECIFIED; 
    uint32_t collateral_expiration_status = 1;

    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));

    ret = verify_quote(quote_u8, quote_size, quote_verification_result,
        collateral_expiration_status, supp_data);

    if(ret < 0)
    {
        print_debug_message("Rejected RA.", ERROR);
        return -1;
    }

    
    /* Quote及び補足情報の内容を確認し、受理するかを判定する */
    ret = display_quote_and_supplemental_data(quote_u8, quote_size, 
        quote_verification_result, collateral_expiration_status, supp_data);

    /* Quoteや補足情報の中身について各種検証処理を実施しRAの受理判断を行う */
    bool ra_result = 1; //RA Accepted
    ra_result = appraise_quote_and_supplemental_data(quote_u8, quote_size, 
            quote_verification_result, collateral_expiration_status, 
            supp_data, ra_keys);
    if(ret) ra_result = 0; //RA failed

    if(supp_data.p_data != NULL) free(supp_data.p_data);

    /* RA受理判断結果の返信 */
    ret = send_ra_result(server_url, ra_ctx_b64, ra_result);
    if(!ra_result || ret) return -1;

    /* セッション共通鍵SKとMKの生成 */
    aes_128bit_cmac(ra_keys.kdk, (uint8_t*)("\x01SK\x00\x80\x00"),
        6, ra_keys.sk);
    aes_128bit_cmac(ra_keys.kdk, (uint8_t*)("\x01MK\x00\x80\x00"),
        6, ra_keys.mk);

    sk = new uint8_t[16]();
    mk = new uint8_t[16]();

    memcpy(sk, ra_keys.sk, 16);
    memcpy(mk, ra_keys.mk, 16);

    return 0;
}


/* RAコンテキストの破棄 */
void destruct_ra_context(std::string server_url, std::string ra_ctx_b64)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Destruct RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    
    json::JSON req_json_obj;
    std::string request_json;

    req_json_obj["ra_context"] = ra_ctx_b64;

    Client client(server_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/destruct-ra", request_json, "application/json");

    print_debug_message("Sent RA destruction request to ISV.", INFO);
    print_debug_message("", INFO);
}


/* CSPRNGにより、指定されたバイト数だけ乱数（nonce）を生成 */
int generate_nonce(uint8_t *buf, size_t size)
{
    int ret = RAND_bytes(buf, size);

    if(!ret)
    {
        print_debug_message("Failed to generate nonce.", ERROR);
        return -1;
    }
    else return 0;
}


/* 128bit AES/GCMで暗号化する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_encrypt(uint8_t *plaintext, size_t p_len,
    uint8_t *key, uint8_t *iv, uint8_t *ciphertext, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    size_t c_len;
    int len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM暗号化初期化処理 */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 暗号化する平文を供給する */
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len_tmp, plaintext, p_len))
    {
        message = "Failed to encrypt plain text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len = len_tmp;

    /* GCM暗号化の最終処理 */
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len_tmp, &len_tmp))
    {
        message = "Failed to finalize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len += len_tmp;

    /* 生成したGCM暗号文のMACタグを取得 */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        message = "Failed to obtain GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return c_len;
}


/* 128bit AES/GCMで復号する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_decrypt(uint8_t *ciphertext, size_t c_len,
    uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    size_t p_len;
    int ret, len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号初期化処理 */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM decryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 復号する暗号文を供給する */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len_tmp, ciphertext, c_len))
    {
        message = "Failed to decrypt cipher text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    p_len = len_tmp;

    /* 検証に用いるGCM MACタグをセット */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    {
        message = "Failed to set expected GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号の最終処理 */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len_tmp, &len_tmp);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        p_len += len_tmp;
        return p_len;
    }
    else
    {
        /* 復号または検証の失敗 */
        message = "Decryption verification failed.";
        print_debug_message(message, ERROR);
        return -1;
    }
}


/* TLS通信を通したリモート秘密計算のテスト */
int sample_remote_computation(std::string isv_url,
    std::string &ra_ctx_b64, uint8_t *&sk, uint8_t *&mk)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Remote Computation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    uint64_t secret_1 = 200;
    uint64_t secret_2 = 800;
    std::string secret_1_str = std::to_string(secret_1);
    std::string secret_2_str = std::to_string(secret_2);

    print_debug_message("First integer to send -> ", INFO);
    print_debug_message(secret_1_str, INFO);
    print_debug_message("", INFO);
    print_debug_message("Second integer to send -> ", INFO);
    print_debug_message(secret_2_str, INFO);
    print_debug_message("", INFO);

    uint8_t *plain_send_1 = (uint8_t*)secret_1_str.c_str();
    uint8_t *plain_send_2 = (uint8_t*)secret_2_str.c_str();

    size_t secret_1_len = secret_1_str.length();
    size_t secret_2_len = secret_2_str.length();

    uint8_t *iv_send = new uint8_t[12]();
    uint8_t *tag_send_1 = new uint8_t[16]();
    uint8_t *tag_send_2 = new uint8_t[16]();

    /* GCM方式は平文と暗号文の長さが同一 */
    uint8_t *cipher_send_1 = new uint8_t[secret_1_len]();
    uint8_t *cipher_send_2 = new uint8_t[secret_2_len]();

    if(generate_nonce(iv_send, 12)) return -1;

    /* SKで暗号化 */
    if(-1 == (aes_128_gcm_encrypt(plain_send_1,
        secret_1_len, sk, iv_send, cipher_send_1, tag_send_1)))
    {
        return -1;
    }

    if(-1 == (aes_128_gcm_encrypt(plain_send_2,
        secret_2_len, sk, iv_send, cipher_send_2, tag_send_2)))
    {
        return -1;
    }

    char *cs1_b64, *cs2_b64;
    char *ivs_b64;
    char *tags1_b64, *tags2_b64;

    cs1_b64 = base64_encode<char, uint8_t>(cipher_send_1, secret_1_len);
    cs2_b64 = base64_encode<char, uint8_t>(cipher_send_2, secret_2_len);
    ivs_b64 = base64_encode<char, uint8_t>(iv_send, 12);
    tags1_b64 = base64_encode<char, uint8_t>(tag_send_1, 16);
    tags2_b64 = base64_encode<char, uint8_t>(tag_send_2, 16);

    json::JSON req_json_obj, res_json_obj;
    std::string request_json, response_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["cipher1"] = cs1_b64;
    req_json_obj["cipher2"] = cs2_b64;
    req_json_obj["iv"] = ivs_b64;
    req_json_obj["tag1"] = tags1_b64;
    req_json_obj["tag2"] = tags2_b64;

    Client client(isv_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/sample-addition", request_json, "application/json");
    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else if(res->status != 200)
    {
        std::string message = "Unexpected error while processing msg0.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    /* 受信した計算結果暗号文の処理を開始 */
    uint8_t *cipher_result, *plain_result;
    uint8_t *iv_result, *tag_result;
    size_t cipher_result_len, tmpsz;

    cipher_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["cipher"].ToString().c_str(), cipher_result_len);
    
    /* GCMでは暗号文と平文の長さが同一 */
    plain_result = new uint8_t[cipher_result_len]();

    iv_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["iv"].ToString().c_str(), tmpsz);

    if(tmpsz != 12)
    {
        print_debug_message("Invalidly formatted IV received.", ERROR);
        return -1;
    }

    tag_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["tag"].ToString().c_str(), tmpsz);
    
    if(tmpsz != 16)
    {
        print_debug_message("Invalidly formatted MAC tag received.", ERROR);
        return -1;
    }

    if(-1 == (aes_128_gcm_decrypt(cipher_result,
        cipher_result_len, mk, iv_result, tag_result, plain_result)))
    {
        return -1;
    }

    uint64_t total = atol((const char*)plain_result);

    /* 受信した計算結果の表示 */
    print_debug_message("Received addition result -> ", INFO);
    print_debug_message(std::to_string(total), INFO);

    return 0;
}


void main_process()
{
    /* 設定ファイルからの設定の読み取り */
    load_settings();

    /* SGXサーバのURLを設定 */
    std::string server_url = "http://localhost:1234";

    /* SGXサーバはこの変数を用いてSP（厳密にはRA）の識別を行う。
     * SPは直接は使わないので、通信向けにbase64の形で保持 */
    std::string ra_ctx_b64 = "";
    
    /* RA後のTLS通信用のセッション鍵（共有秘密）。
     * do_RA関数内で取得され引数経由で返される。 */
    uint8_t *sk, *mk;

    int ret = -1;

    /* RAを実行 */
    ret = do_RA(server_url, ra_ctx_b64, sk, mk);

    if(ret)
    {
        std::string message = "RA failed. Clean up and exit program.";
        print_debug_message(message, ERROR);

        destruct_ra_context(server_url, ra_ctx_b64);
        
        exit(0);
    }

    print_debug_binary("SK", sk, 16, DEBUG_LOG);
    print_debug_binary("MK", mk, 16, DEBUG_LOG);

    /* TLS通信を通したリモート秘密計算のテスト */
    ret = sample_remote_computation(server_url, ra_ctx_b64, sk, mk);

    delete[] sk;
    delete[] mk;

    /* RAコンテキストの破棄 */
    destruct_ra_context(server_url, ra_ctx_b64);
}


int main()
{
    std::string message = "Launched SP's untrusted application.";
    print_debug_message(message, INFO);

    main_process();

    return 0;
}