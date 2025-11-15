#include "error_print.hpp"

void print_sgx_status(sgx_status_t status)
{
    print_debug_message("=============================================================================", INFO);
    print_debug_message("Error name: ", INFO);

    switch (status)
    {
        case 0x0000:
            print_debug_message("SGX_SUCCESS", INFO);
            print_debug_message("Exited SGX function successfully.", INFO);
            break;

        case 0x0001:
            print_debug_message("SGX_ERROR_UNEXPECTED", ERROR);
            print_debug_message("An unexpected error has occured.", ERROR);
            break;

        case 0x0002:
            print_debug_message("SGX_ERROR_INVALID_PARAMETER", ERROR);
            print_debug_message("The parameter is incorrect. Please check the argument of function.", ERROR);
            break;

        case 0x0003:
            print_debug_message("SGX_ERROR_OUT_OF_MEMORY", ERROR);
            print_debug_message("There is not enough memory available to complete this operation.", ERROR);
            break;

        case 0x0004:
            print_debug_message("SGX_ERROR_ENCLAVE_LOST", ERROR);
            print_debug_message("The enclave is lost after power transition.", ERROR);
            break;

        case 0x0005:
            print_debug_message("SGX_ERROR_INVALID_STATE", ERROR);
            print_debug_message("The API is invoked in incorrect order or state.", ERROR);
            break;

        case 0x0007:
            print_debug_message("SGX_ERROR_HYPERV_ENABLED", ERROR);
            print_debug_message("Incompatible versions of Windows* 10 OS and Hyper-V* are detected.", ERROR);
            print_debug_message("In this case, you need to disable Hyper-V on the target machine.", ERROR);
            break;

        case 0x0008:
            print_debug_message("SGX_ERROR_FEATURE_NOT_SUPPORTED", ERROR);
            print_debug_message("The feature has been deprecated and is no longer supported.", ERROR);
            break;

        case 0x1001:
            print_debug_message("SGX_ERROR_INVALID_FUNCTION", ERROR);
            print_debug_message("The ECALL/OCALL function index is incorrect.", ERROR);
            break;

        case 0x1003:
            print_debug_message("SGX_ERROR_OUT_OF_TCS", ERROR);
            print_debug_message("The enclave is out of Thread Control Structure.", ERROR);
            break;

        case 0x1006:
            print_debug_message("SGX_ERROR_ENCLAVE_CRASHED", ERROR);
            print_debug_message("The enclave has crashed.", ERROR);
            break;

        case 0x1007:
            print_debug_message("SGX_ERROR_ECALL_NOT_ALLOWED", ERROR);
            print_debug_message("ECALL is not allowed at this time. For example:", ERROR);
            print_debug_message("- ECALL is not public.", ERROR);
            print_debug_message("- ECALL is blocked by the dynamic entry table.", ERROR);
            print_debug_message("- A nested ECALL is not allowed during global initialization.", ERROR);
            break;

        case 0x1008:
            print_debug_message("SGX_ERROR_OCALL_NOT_ALLOWED", ERROR);
            print_debug_message("OCALL is not allowed during exception handling.", ERROR);
            break;

        case 0x2000:
            print_debug_message("SGX_ERROR_UNDEFINED_SYMBOL", ERROR);
            print_debug_message("The enclave image has undefined symbol.", ERROR);
            break;

        case 0x2001:
            print_debug_message("SGX_ERROR_INVALID_ENCLAVE", ERROR);
            print_debug_message("The enclave image is incorrect.", ERROR);
            break;

        case 0x2002:
            print_debug_message("SGX_ERROR_INVALID_ENCLAVE_ID", ERROR);
            print_debug_message("The enclave ID is invalid.", ERROR);
            break;

        case 0x2003:
            print_debug_message("SGX_ERROR_INVALID_SIGNATURE", ERROR);
            print_debug_message("The signature is invalid.", ERROR);
            break;

        case 0x2004:
            print_debug_message("SGX_ERROR_NDEBUG_ENCLAVE", ERROR);
            print_debug_message("The enclave is signed as product enclave and cannot be created", ERROR);
            print_debug_message("as a debuggable enclave.", ERROR);
            break;

        case 0x2005:
            print_debug_message("SGX_ERROR_OUT_OF_EPC", ERROR);
            print_debug_message("There is not enough EPC available to load the enclave", ERROR);
            print_debug_message("or one of the Architecture Enclave needed to complete", ERROR);
            print_debug_message("the operation requested.", ERROR);
            break;

        case 0x2006:
            print_debug_message("SGX_ERROR_NO_DEVICE", ERROR);
            print_debug_message("Cannot open device.", ERROR);
            break;

        case 0x2007:
            print_debug_message("SGX_ERROR_MEMORY_MAP_CONFLICT", ERROR);
            print_debug_message("Page mapping failed in driver.", ERROR);
            break;

        case 0x2009:
            print_debug_message("SGX_ERROR_INVALID_METADATA", ERROR);
            print_debug_message("The metadata is incorrect.", ERROR);
            break;

        case 0x200C:
            print_debug_message("SGX_ERROR_DEVICE_BUSY", ERROR);
            print_debug_message("Device is busy.", ERROR);
            break;

        case 0x200D:
            print_debug_message("SGX_ERROR_INVALID_VERSION", ERROR);
            print_debug_message("Metadata version is inconsistent between uRTS and sgx_sign", ERROR);
            print_debug_message("or the uRTS is incompatible with the current platform.", ERROR);
            break;

        case 0x200E:
            print_debug_message("SGX_ERROR_MODE_INCOMPATIBLE", ERROR);
            print_debug_message("The target enclave (32/64 bit or HS/Sim) mode is incompatible", ERROR);
            print_debug_message("with the uRTS mode.", ERROR);
            break;

        case 0x200F:
            print_debug_message("SGX_ERROR_ENCLAVE_FILE_ACCESS", ERROR);
            print_debug_message("Cannot open enclave file.", ERROR);
            break;

        case 0x2010:
            print_debug_message("SGX_ERROR_INVALID_MISC", ERROR);
            print_debug_message("The MiscSelect/MiscMask settings are incorrect.", ERROR);
            break;

        case 0x2012:
            print_debug_message("SGX_ERROR_MEMORY_LOCKED", ERROR);
            print_debug_message("Attempt to change system memory that should not be modified.", ERROR);
            break;

        case 0x3001:
            print_debug_message("SGX_ERROR_MAC_MISMATCH", ERROR);
            print_debug_message("Indicates report verification or cryptographic error.", ERROR);
            break;

        case 0x3002:
            print_debug_message("SGX_ERROR_INVALID_ATTRIBUTE", ERROR);
            print_debug_message("The enclave is not authorized.", ERROR);
            break;

        case 0x3003:
            print_debug_message("SGX_ERROR_INVALID_CPUSVN", ERROR);
            print_debug_message("The CPU SVN is beyond the CPU SVN value of the platform.", ERROR);
            break;

        case 0x3004:
            print_debug_message("SGX_ERROR_INVALID_ISVSVN", ERROR);
            print_debug_message("The ISV SVN is greater than the ISV SVN value of the enclave.", ERROR);
            break;

        case 0x3005:
            print_debug_message("SGX_ERROR_INVALID_KEYNAME", ERROR);
            print_debug_message("Unsupported key name value.", ERROR);
            break;

        case 0x4001:
            print_debug_message("SGX_ERROR_SERVICE_UNAVAILABLE", ERROR);
            print_debug_message("AE service did not respond or the requested service is not supported.", ERROR);
            print_debug_message("Probably aesmd service is corrupted, so try reinstalling Intel SGX driver.", ERROR);
            break;

        case 0x4002:
            print_debug_message("SGX_ERROR_SERVICE_TIMEOUT", ERROR);
            print_debug_message("The request to AE service timed out.", ERROR);
            break;

        case 0x4003:
            print_debug_message("SGX_ERROR_AE_INVALID_EPIDBLOB", ERROR);
            print_debug_message("Indicates an Intel(R) EPID blob verification error.", ERROR);
            break;

        case 0x4004:
            print_debug_message("SGX_ERROR_SERVICE_INVALID_PRIVILEDGE", ERROR);
            print_debug_message("Enclave has no priviledge to get launch token.", ERROR);
            break;

        case 0x4005:
            print_debug_message("SGX_ERROR_EPID_MEMBER_REVOKED", ERROR);
            print_debug_message("The Intel(R) EPID group membership has been revoked.", ERROR);
            print_debug_message("The platform is not trusted. Updating platform and retrying", ERROR);
            print_debug_message("will not remedy the revocation.", ERROR);
            break;

        case 0x4006:
            print_debug_message("SGX_ERROR_UPDATE_NEEDED", ERROR);
            print_debug_message("Intel(R) SGX needs to be updated.", ERROR);
            break;

        case 0x4007:
            print_debug_message("SGX_ERROR_NETWORK_FAILURE", ERROR);
            print_debug_message("Network connecting or proxy setting issue is encountered.", ERROR);
            break;

        case 0x4008:
            print_debug_message("SGX_ERROR_AE_SESSION_INVALID", ERROR);
            print_debug_message("The session is invalid or ended by AE service.", ERROR);
            break;

        case 0x400a:
            print_debug_message("SGX_ERROR_BUSY", ERROR);
            print_debug_message("The requested service is temporarily not available.", ERROR);
            break;

        case 0x400c:
            print_debug_message("SGX_ERROR_MC_NOT_FOUND", ERROR);
            print_debug_message("The Monotonic Counter does not exist or has been invalidated.", ERROR);
            break;

        case 0x400d:
            print_debug_message("SGX_ERROR_MC_NO_ACCESS_RIGHT", ERROR);
            print_debug_message("The caller does not have the access right to the specified VMC.", ERROR);
            break;

        case 0x400e:
            print_debug_message("SGX_ERROR_MC_USED_UP", ERROR);
            print_debug_message("No Monotonic Counter is available.", ERROR);
            break;

        case 0x400f:
            print_debug_message("SGX_ERROR_MC_OVER_QUOTA", ERROR);
            print_debug_message("Monotonic Counter reached quota limit.", ERROR);
            break;

        case 0x4011:
            print_debug_message("SGX_ERROR_KDF_MISMATCH", ERROR);
            print_debug_message("Key derivation function does not match during key exchange.", ERROR);
            break;

        case 0x4012:
            print_debug_message("SGX_QL_UNRECOGNIZED_PLATFORM", ERROR);
            print_debug_message("Intel(R) EPID Provisioning failed because the platform was not recognized", ERROR);
            print_debug_message("by the back-end server.", ERROR);
            break;

        case 0x4013:
            print_debug_message("SGX_QL_SM_SERVICE_CLOSED", ERROR);
            print_debug_message("The secure message service instance was closed.", ERROR);
            break;

        case 0x4014:
            print_debug_message("SGX_QL_SM_SERVICE_UNAVAILABLE", ERROR);
            print_debug_message("The secure message service applet does not have an existing session.", ERROR);
            break;

        case 0x4015:
            print_debug_message("SGX_QL_SM_SERVICE_UNCAUGHT_EXCEPTION", ERROR);
            print_debug_message("The secure message service instance was terminated with an uncaught exception.", ERROR);
            break;

        case 0x4016:
            print_debug_message("SGX_QL_SM_SERVICE_RESPONSE_OVERFLOW", ERROR);
            print_debug_message("The response data of the service applet is too large.", ERROR);
            break;

        case 0x4017:
            print_debug_message("SGX_QL_SM_SERVICE_INTERNAL_ERROR", ERROR);
            print_debug_message("The secure message service got an internal error.", ERROR);
            break;

        case 0x5002:
            print_debug_message("SGX_ERROR_NO_PRIVILEDGE", ERROR);
            print_debug_message("You do not have enough priviledges to perform the operation.", ERROR);
            break;

        case 0x6001:
            print_debug_message("SGX_ERROR_PCL_ENCRYPTED", ERROR);
            print_debug_message("Trying to encrypt an already encrypted enclave.", ERROR);
            break;

        case 0x6002:
            print_debug_message("SGX_ERROR_PCL_NOT_ENCRYPTED", ERROR);
            print_debug_message("Trying to load a plain enclave using sgx_created_encrypted_enclave.", ERROR);
            break;

        case 0x6003:
            print_debug_message("SGX_ERROR_PCL_MAC_MISMATCH", ERROR);
            print_debug_message("Section MAC result does not match build time MAC.", ERROR);
            break;

        case 0x6004:
            print_debug_message("SGX_ERROR_PCL_SHA_MISMATCH", ERROR);
            print_debug_message("Unsealed key MAC doesn't match MAC of key hardcoded in enclave binary.", ERROR);
            break;

        case 0x6005:
            print_debug_message("SGX_ERROR_PCL_GUID_MISMATCH", ERROR);
            print_debug_message("GUID in sealed blob doesn't match GUID hardcoded in enclave binary.", ERROR);
            break;

        case 0x7001:
            print_debug_message("SGX_ERROR_FILE_BAD_STATUS", ERROR);
            print_debug_message("The file is in a bad status, run sgx_clearerr to try and fix it.", ERROR);
            break;

        case 0x7002:
            print_debug_message("SGX_ERROR_FILE_NO_KEY_ID", ERROR);
            print_debug_message("The Key ID field is all zeros, cannot re-generate the encryption key.", ERROR);
            break;

        case 0x7003:
            print_debug_message("SGX_ERROR_FILE_NAME_MISMATCH", ERROR);
            print_debug_message("The current file name is different than the original file name", ERROR);
            print_debug_message("(not allowed, substitution attack).", ERROR);
            break;

        case 0x7004:
            print_debug_message("SGX_ERROR_FILE_NOT_SGX_FILE", ERROR);
            print_debug_message("The file is not an Intel SGX file.", ERROR);
            break;

        case 0x7005:
            print_debug_message("SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE", ERROR);
            print_debug_message("A recovery file cannot be opened, so the flush operation cannot continue", ERROR);
            print_debug_message("(only used when no EXXX is returned).", ERROR);
            break;

        case 0x7006:
            print_debug_message("SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE", ERROR);
            print_debug_message("A recovery file cannot be writen, so the flush operation cannot continue", ERROR);
            print_debug_message("(only used when no EXXX is returned).", ERROR);
            break;

        case 0x7007:
            print_debug_message("SGX_ERROR_FILE_RECOVERY_NEEDED", ERROR);
            print_debug_message("When opening the file, recovery is needed, but the recovery process failed.", ERROR);
            break;

        case 0x7008:
            print_debug_message("SGX_ERROR_FILE_FLUSH_FAILED", ERROR);
            print_debug_message("fflush operation (to the disk) failed (only used when no EXXX is returned).", ERROR);
            break;

        case 0x7009:
            print_debug_message("SGX_ERROR_FILE_CLOSE_FAILED", ERROR);
            print_debug_message("fclose operation (to the disk) failed (only used when no EXXX is returned).", ERROR);
            break;

        case 0x8001:
            print_debug_message("SGX_ERROR_IPLDR_NOTENCRYPTED", ERROR);
            print_debug_message("sgx_create_encrypted_enclave was called, but the enclave file is not encrypted.", ERROR);
            break;

        case 0x8002:
            print_debug_message("SGX_ERROR_IPLDR_MAC_MISMATCH", ERROR);
            print_debug_message("sgx_create_encrypted_enclave was called but there was a verification error", ERROR);
            print_debug_message("when decrypting the data.", ERROR);
            break;

        case 0x8003:
            print_debug_message("SGX_ERROR_IPLDR_ENCRYPTED", ERROR);
            print_debug_message("sgx_create_encrypted_enclave was called, but the enclave file is encrypted.", ERROR);
            break;

        case 0xf001:
            print_debug_message("SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED", ERROR);
            print_debug_message("The ioctl for enclave_create unexpectedly failed with EINTR.", ERROR);
            break;

        default:
            print_debug_message("Unrecognized SGX status code.", ERROR);
    }

    print_debug_message("=============================================================================", INFO);
    return;
}


/* Quote検証結果表示 */
void print_ql_qv_result(sgx_ql_qv_result_t quote_verification_result)
{
    print_debug_message("=============================================================================", INFO);
    print_debug_message("Quote verification status: ", INFO);

    switch(quote_verification_result)
    {
        case SGX_QL_QV_RESULT_OK:
            print_debug_message("SGX_QL_QV_RESULT_OK", INFO);
            print_debug_message("The Quote verification passed and is at the latest TCB level.", INFO);
            break;

        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            print_debug_message("SGX_QL_QV_RESULT_CONFIG_NEEDED", WARN);
            print_debug_message("The Quote verification passed and the platform is patched to the latest TCB level", WARN);
            print_debug_message("but additional configuration of the SGX platform may be needed.", WARN);
            print_debug_message("(e.g. disabling hyperthread feature)", WARN);
            break;

        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            print_debug_message("SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED", WARN);
            print_debug_message("The Quote is good but the TCB level of the SGX platform is out of date", WARN);
            print_debug_message("and additional configuration of the SGX platform", WARN);
            print_debug_message("at its current patching level may be needed.", WARN);
            print_debug_message("(e.g. disabling hyperthread feature)", WARN);
            print_debug_message("The platform needs patching to be at the latest TCB level.", WARN);
            break;

        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            print_debug_message("SGX_QL_QV_RESULT_INVALID_SIGNATURE", ERROR);
            print_debug_message("The signature over the application report (Quote) is invalid.", ERROR);
            print_debug_message("DO NOT ACCEPT THIS ATTESTATION.", ERROR);
            break;

        case SGX_QL_QV_RESULT_REVOKED:
            print_debug_message("SGX_QL_QV_RESULT_REVOKED", ERROR);
            print_debug_message("The attestation key or platform has been revoked.", ERROR);
            print_debug_message("DO NOT ACCEPT THIS ATTESTATION.", ERROR);
            break;

        case SGX_QL_QV_RESULT_UNSPECIFIED:
            print_debug_message("SGX_QL_QV_RESULT_UNSPECIFIED", ERROR);
            print_debug_message("The Quote verification failed due to an error in processing the Quote.", ERROR);
            print_debug_message("DO NOT ACCEPT THIS ATTESTATION.", ERROR);
            break;

        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            print_debug_message("SGX_QL_QV_RESULT_SW_HARDENING_NEEDED", WARN);
            print_debug_message("The TCB level of the platform is up to date,", WARN);
            print_debug_message("but SGX SW (i.e. software-based) Hardening of the enclave is needed.", WARN);
            break;

        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            print_debug_message("SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED", WARN);
            print_debug_message("The TCB level of the platform is up to date,", WARN);
            print_debug_message("but additional configuration of the platform", WARN);
            print_debug_message("at its current patching level may be needed.", WARN);
            print_debug_message("(e.g. disabling hyperthread feature)", WARN);
            print_debug_message("Moreover, SGX SW (i.e. software-based) Hardening of the enclave", WARN);
            print_debug_message("is also needed.", WARN);
            break;

        //SGXでは未使用だが、QvLが返し得る可能性を否定しきれないので一応処理
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED:
            print_debug_message("SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED", ERROR);
            print_debug_message("This status shouldn't appear when you are using SGX,", ERROR);
            print_debug_message("therefore you shouldn't accept this attestation.", ERROR);
            break;

        //SGXでは未使用だが、QvLが返し得る可能性を否定しきれないので一応処理
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            print_debug_message("SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED", ERROR);
            print_debug_message("This status shouldn't appear when you are using SGX,", ERROR);
            print_debug_message("therefore you shouldn't accept this attestation.", ERROR);
            break;

        default:
            print_debug_message("Unexpected attestation status.", ERROR);
            print_debug_message("DO NOT ACCEPT THIS ATTESTATION.", ERROR);
    }

    print_debug_message("=============================================================================", INFO);
    return;
}


/* DCAP-RA用エラー表示 */
void print_ql_status(quote3_error_t qe3_error)
{
    print_debug_message("=============================================================================", INFO);
    print_debug_message("Error name: ", INFO);

    switch (qe3_error)
    {
        case SGX_QL_SUCCESS:
            print_debug_message("SGX_QL_SUCCESS", INFO);
            print_debug_message("Exited SGX QL function successfully.", INFO);
            break;

        case SGX_QL_ERROR_UNEXPECTED:
            print_debug_message("SGX_QL_ERROR_UNEXPECTED", ERROR);
            print_debug_message("An unexpected error has occured.", ERROR);
            break;

        case SGX_QL_ERROR_INVALID_PARAMETER:
            print_debug_message("SGX_QL_ERROR_INVALID_PARAMETER", ERROR);
            print_debug_message("The parameter is incorrect.", ERROR);
            break;

        case SGX_QL_ERROR_OUT_OF_MEMORY:
            print_debug_message("SGX_QL_ERROR_OUT_OF_MEMORY", ERROR);
            print_debug_message("Not enough memory is available to complete this operation.", ERROR);
            break;

        case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
            print_debug_message("SGX_QL_ERROR_ECDSA_ID_MISMATCH", ERROR);
            print_debug_message("Expected ECDSA_ID does not match the value stored in the ECDSA Blob.", ERROR);
            break;

        case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
            print_debug_message("SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR", ERROR);
            print_debug_message("The ECDSA blob pathname is too large.", ERROR);
            break;

        case SGX_QL_FILE_ACCESS_ERROR:
            print_debug_message("SGX_QL_FILE_ACCESS_ERROR", ERROR);
            print_debug_message("Error accessing ECDSA blob.", ERROR);
            break;

        case SGX_QL_ERROR_STORED_KEY:
            print_debug_message("SGX_QL_ERROR_STORED_KEY", ERROR);
            print_debug_message("Cached ECDSA key is invalid.", ERROR);
            break;

        case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
            print_debug_message("SGX_QL_ERROR_PUB_KEY_ID_MISMATCH", ERROR);
            print_debug_message("Cached ECDSA key does not match requested key.", ERROR);
            break;

        case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
            print_debug_message("SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME", ERROR);
            print_debug_message("PCE use the incorrect signature scheme.", ERROR);
            break;

        case SGX_QL_ATT_KEY_BLOB_ERROR:
            print_debug_message("SGX_QL_ATT_KEY_BLOB_ERROR", ERROR);
            print_debug_message("There is a problem with the attestation key blob.", ERROR);
            break;

        case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
            print_debug_message("SGX_QL_UNSUPPORTED_ATT_KEY_ID", ERROR);
            print_debug_message("Unsupported attestation key ID.", ERROR);
            break;

        case SGX_QL_UNSUPPORTED_LOADING_POLICY:
            print_debug_message("SGX_QL_UNSUPPORTED_LOADING_POLICY", ERROR);
            print_debug_message("Unsupported enclave loading policy.", ERROR);
            break;

        case SGX_QL_INTERFACE_UNAVAILABLE:
            print_debug_message("SGX_QL_INTERFACE_UNAVAILABLE", ERROR);
            print_debug_message("Unable to load the PCE enclave.", ERROR);
            break;

        case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
            print_debug_message("SGX_QL_PLATFORM_LIB_UNAVAILABLE", ERROR);
            print_debug_message("Unable to find the platform library with the dependent APIs. Not fatal.", ERROR);
            break;

        case SGX_QL_ATT_KEY_NOT_INITIALIZED:
            print_debug_message("SGX_QL_ATT_KEY_NOT_INITIALIZED", ERROR);
            print_debug_message("The attestation key doesn't exist or has not been certified.", ERROR);
            break;

        case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
            print_debug_message("SGX_QL_ATT_KEY_CERT_DATA_INVALID", ERROR);
            print_debug_message("The certification data retrieved from the platform library is invalid.", ERROR);
            break;

        case SGX_QL_NO_PLATFORM_CERT_DATA:
            print_debug_message("SGX_QL_NO_PLATFORM_CERT_DATA", ERROR);
            print_debug_message("The platform library doesn't have any platfrom cert data.", ERROR);
            break;

        case SGX_QL_OUT_OF_EPC:
            print_debug_message("SGX_QL_OUT_OF_EPC", ERROR);
            print_debug_message("Not enough memory in the EPC to load the enclave.", ERROR);
            break;

        case SGX_QL_ERROR_REPORT:
            print_debug_message("SGX_QL_ERROR_REPORT", ERROR);
            print_debug_message("There was a problem verifying an SGX REPORT.", ERROR);
            break;

        case SGX_QL_ENCLAVE_LOST:
            print_debug_message("SGX_QL_ENCLAVE_LOST", ERROR);
            print_debug_message("Interfacing to the enclave failed due to a power transition.", ERROR);
            break;

        case SGX_QL_INVALID_REPORT:
            print_debug_message("SGX_QL_INVALID_REPORT", ERROR);
            print_debug_message("Error verifying the application enclave's report.", ERROR);
            break;

        case SGX_QL_ENCLAVE_LOAD_ERROR:
            print_debug_message("SGX_QL_ENCLAVE_LOAD_ERROR", ERROR);
            print_debug_message("Unable to load the enclaves. Could be due to file I/O error,", ERROR);
            print_debug_message("loading infrastructure error, or non-SGX capable system.", ERROR);
            break;

        case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
            print_debug_message("SGX_QL_UNABLE_TO_GENERATE_QE_REPORT", ERROR);
            print_debug_message("The QE was unable to generate its own report targeting the application enclave either", ERROR);
            print_debug_message("because the QE doesn't support this feature there is an enclave compatibility issue.", ERROR);
            print_debug_message("Please call again with the p_qe_report_info to NULL.", ERROR);
            break;

        case SGX_QL_KEY_CERTIFCATION_ERROR:
            print_debug_message("SGX_QL_KEY_CERTIFCATION_ERROR", ERROR);
            print_debug_message("Caused when the provider library returns an invalid TCB (too high).", ERROR);
            break;

        case SGX_QL_NETWORK_ERROR:
            print_debug_message("SGX_QL_NETWORK_ERROR", ERROR);
            print_debug_message("Network error when retrieving PCK certs.", ERROR);
            break;

        case SGX_QL_MESSAGE_ERROR:
            print_debug_message("SGX_QL_MESSAGE_ERROR", ERROR);
            print_debug_message("Message error when retrieving PCK certs.", ERROR);
            break;

        case SGX_QL_NO_QUOTE_COLLATERAL_DATA:
            print_debug_message("SGX_QL_NO_QUOTE_COLLATERAL_DATA", ERROR);
            print_debug_message("The platform does not have the quote verification collateral data available.", ERROR);
            break;

        case SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
            print_debug_message("SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED", ERROR);
            print_debug_message("The quote verifier doesn’t support the certification data in the Quote.", ERROR);
            break;

        case SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
            print_debug_message("SGX_QL_QUOTE_FORMAT_UNSUPPORTED", ERROR);
            print_debug_message("The inputted quote format is not supported. Either because the header information is not supported", ERROR);
            print_debug_message("or the quote is malformed in some way.", ERROR);
            break;

        case SGX_QL_UNABLE_TO_GENERATE_REPORT:
            print_debug_message("SGX_QL_UNABLE_TO_GENERATE_REPORT", ERROR);
            print_debug_message("The QVE was unable to generate its own report targeting the application enclave", ERROR);
            print_debug_message("because there is an enclave compatibility issue.", ERROR);
            break;

        case SGX_QL_QE_REPORT_INVALID_SIGNATURE:
            print_debug_message("SGX_QL_QE_REPORT_INVALID_SIGNATURE", ERROR);
            print_debug_message("The signature over the QE Report is invalid.", ERROR);
            break;

        case SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
            print_debug_message("SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT", ERROR);
            print_debug_message("The quote verifier doesn’t support the format of the application REPORT the Quote.", ERROR);
            break;

        case SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
            print_debug_message("SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT", ERROR);
            print_debug_message("The format of the PCK Cert is unsupported.", ERROR);
            break;

        case SGX_QL_PCK_CERT_CHAIN_ERROR:
            print_debug_message("SGX_QL_PCK_CERT_CHAIN_ERROR", ERROR);
            print_debug_message("Cannot parse the PCK certificate chain, or root certificate is not trusted.", ERROR);
            break;

        case SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
            print_debug_message("SGX_QL_TCBINFO_UNSUPPORTED_FORMAT", ERROR);
            print_debug_message("The format of the TCBInfo structure is unsupported.", ERROR);
            break;

        case SGX_QL_TCBINFO_MISMATCH:
            print_debug_message("SGX_QL_TCBINFO_MISMATCH", ERROR);
            print_debug_message("PCK Cert FMSPc does not match the TCBInfo FMSPc.", ERROR);
            break;

        case SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
            print_debug_message("SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT", ERROR);
            print_debug_message("The format of the QEIdentity structure is unsupported.", ERROR);
            break;

        case SGX_QL_QEIDENTITY_MISMATCH:
            print_debug_message("SGX_QL_QEIDENTITY_MISMATCH", ERROR);
            print_debug_message("The Quote’s QE doesn’t match the inputted expected QEIdentity.", ERROR);
            break;

        case SGX_QL_TCB_OUT_OF_DATE:
            print_debug_message("SGX_QL_TCB_OUT_OF_DATE", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
            print_debug_message("SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
            print_debug_message("SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
            print_debug_message("SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_QE_IDENTITY_OUT_OF_DATE:
            print_debug_message("SGX_QL_QE_IDENTITY_OUT_OF_DATE", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_TCB_INFO_EXPIRED:
            print_debug_message("SGX_QL_SGX_TCB_INFO_EXPIRED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
            print_debug_message("SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_CRL_EXPIRED:
            print_debug_message("SGX_QL_SGX_CRL_EXPIRED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
            print_debug_message("SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
            print_debug_message("SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_PCK_REVOKED:
            print_debug_message("SGX_QL_PCK_REVOKED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_TCB_REVOKED:
            print_debug_message("SGX_QL_TCB_REVOKED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_TCB_CONFIGURATION_NEEDED:
            print_debug_message("SGX_QL_TCB_CONFIGURATION_NEEDED", ERROR);
            print_debug_message("(Detail is not provided by Intel. Probably related to RA result status)", ERROR);
            break;

        case SGX_QL_UNABLE_TO_GET_COLLATERAL:
            print_debug_message("SGX_QL_UNABLE_TO_GET_COLLATERAL", ERROR);
            print_debug_message("Failed to retrieve collateral.", ERROR);
            break;

        case SGX_QL_ERROR_INVALID_PRIVILEGE:
            print_debug_message("SGX_QL_ERROR_INVALID_PRIVILEGE", ERROR);
            print_debug_message("No enough privilege to perform the operation.", ERROR);
            break;

        case SGX_QL_NO_QVE_IDENTITY_DATA:
            print_debug_message("SGX_QL_NO_QVE_IDENTITY_DATA", ERROR);
            print_debug_message("The platform does not have the QVE identity data available.", ERROR);
            break;

        case SGX_QL_CRL_UNSUPPORTED_FORMAT:
            print_debug_message("SGX_QL_CRL_UNSUPPORTED_FORMAT", ERROR);
            print_debug_message("(Detail is not provided by Intel.)", ERROR);
            break;

        case SGX_QL_QEIDENTITY_CHAIN_ERROR:
            print_debug_message("SGX_QL_QEIDENTITY_CHAIN_ERROR", ERROR);
            print_debug_message("There was an error verifying the QEIdentity signature chain including QEIdentity revocation.", ERROR);
            break;

        case SGX_QL_TCBINFO_CHAIN_ERROR:
            print_debug_message("SGX_QL_TCBINFO_CHAIN_ERROR", ERROR);
            print_debug_message("There was an error verifying the TCBInfo signature chain including TCBInfo revocation.", ERROR);
            break;

        case SGX_QL_ERROR_QVL_QVE_MISMATCH:
            print_debug_message("SGX_QL_ERROR_QVL_QVE_MISMATCH", ERROR);
            print_debug_message("Supplemental data size and version mismatched between QVL and QvE.", ERROR);
            print_debug_message("Please make sure to use QVL and QvE from same release package.", ERROR);
            break;

        case SGX_QL_TCB_SW_HARDENING_NEEDED:
            print_debug_message("SGX_QL_TCB_SW_HARDENING_NEEDED", ERROR);
            print_debug_message("TCB up to date but SW Hardening needed.", ERROR);
            break;

        case SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
            print_debug_message("SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED", ERROR);
            print_debug_message("TCB up to date but Configuration and SW Hardening needed.", ERROR);
            break;

        case SGX_QL_UNSUPPORTED_MODE:
            print_debug_message("SGX_QL_UNSUPPORTED_MODE", ERROR);
            print_debug_message("The platform has been configured to use the out-of-process implementation of quote generation.", ERROR);
            break;

        case SGX_QL_NO_DEVICE:
            print_debug_message("SGX_QL_NO_DEVICE", ERROR);
            print_debug_message("Can't open SGX device. This error happens only when running in out-of-process mode.", ERROR);
            break;

        case SGX_QL_SERVICE_UNAVAILABLE:
            print_debug_message("SGX_QL_SERVICE_UNAVAILABLE", ERROR);
            print_debug_message("Indicates AESM didn't respond or the requested service is not supported.", ERROR);
            print_debug_message("This error happens only when running in out-of-process mode.", ERROR);
            break;

        case SGX_QL_NETWORK_FAILURE:
            print_debug_message("SGX_QL_NETWORK_FAILURE", ERROR);
            print_debug_message("Network connection or proxy setting issue is encountered.", ERROR);
            print_debug_message("This error happens only when running in out-of-process mode.", ERROR);
            break;

        case SGX_QL_SERVICE_TIMEOUT:
            print_debug_message("SGX_QL_SERVICE_TIMEOUT", ERROR);
            print_debug_message("The request to out-of-process service has timed out.", ERROR);
            print_debug_message("This error happens only when running in out-of-process mode.", ERROR);
            break;

        case SGX_QL_ERROR_BUSY:
            print_debug_message("SGX_QL_ERROR_BUSY", ERROR);
            print_debug_message("The requested service is temporarily not available.", ERROR);
            print_debug_message("This error happens only when running in outof-process mode.", ERROR);
            break;

        case SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
            print_debug_message("SGX_QL_UNKNOWN_MESSAGE_RESPONSE", ERROR);
            print_debug_message("Unexpected error from the cache service.", ERROR);
            break;

        case SGX_QL_PERSISTENT_STORAGE_ERROR:
            print_debug_message("SGX_QL_PERSISTENT_STORAGE_ERROR", ERROR);
            print_debug_message("Error storing the retrieved cached data in persistent memory.", ERROR);
            break;

        case SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
            print_debug_message("SGX_QL_ERROR_MESSAGE_PARSING_ERROR", ERROR);
            print_debug_message("Message parsing error.", ERROR);
            break;

        case SGX_QL_PLATFORM_UNKNOWN:
            print_debug_message("SGX_QL_PLATFORM_UNKNOWN", ERROR);
            print_debug_message("Platform was not found in the cache.", ERROR);
            break;

        case SGX_QL_UNKNOWN_API_VERSION:
            print_debug_message("SGX_QL_UNKNOWN_API_VERSION", ERROR);
            print_debug_message("The current PCS API version configured is unknown.", ERROR);
            break;

        case SGX_QL_CERTS_UNAVAILABLE:
            print_debug_message("SGX_QL_CERTS_UNAVAILABLE", ERROR);
            print_debug_message("Certificates are not available for this platform.", ERROR);
            break;

        case SGX_QL_QVEIDENTITY_MISMATCH:
            print_debug_message("SGX_QL_QVEIDENTITY_MISMATCH", ERROR);
            print_debug_message("QvE Identity is NOT match to Intel signed QvE identity.", ERROR);
            break;

        case SGX_QL_QVE_OUT_OF_DATE:
            print_debug_message("SGX_QL_QVE_OUT_OF_DATE", ERROR);
            print_debug_message("QvE ISVSVN is smaller than the ISVSVN threshold, or input QvE ISVSVN is too small.", ERROR);
            break;

        case SGX_QL_PSW_NOT_AVAILABLE:
            print_debug_message("SGX_QL_PSW_NOT_AVAILABLE", ERROR);
            print_debug_message("SGX PSW library cannot be loaded, could be due to file I/O error.", ERROR);
            break;

        case SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED:
            print_debug_message("SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED", ERROR);
            print_debug_message("SGX quote verification collateral version not supported by QVL/QvE.", ERROR);
            break;

        case SGX_QL_TDX_MODULE_MISMATCH:
            print_debug_message("SGX_QL_TDX_MODULE_MISMATCH", ERROR);
            print_debug_message("TDX SEAM module identity is NOT match to Intel signed TDX SEAM module.", ERROR);
            break;

        case SGX_QL_QEIDENTITY_NOT_FOUND:
            print_debug_message("SGX_QL_QEIDENTITY_NOT_FOUND", ERROR);
            print_debug_message("QE identity was not found.", ERROR);
            break;

        case SGX_QL_TCBINFO_NOT_FOUND:
            print_debug_message("SGX_QL_TCBINFO_NOT_FOUND", ERROR);
            print_debug_message("TCB Info was not found.", ERROR);
            break;

        case SGX_QL_INTERNAL_SERVER_ERROR:
            print_debug_message("SGX_QL_INTERNAL_SERVER_ERROR", ERROR);
            print_debug_message("Internal server error.", ERROR);
            break;

        case SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED:
            print_debug_message("SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED", ERROR);
            print_debug_message("The supplemental data version is not supported.", ERROR);
            break;

        case SGX_QL_ROOT_CA_UNTRUSTED:
            print_debug_message("SGX_QL_ROOT_CA_UNTRUSTED", ERROR);
            print_debug_message("The certificate used to establish SSL session is untrusted.", ERROR);
            break;

        case SGX_QL_TCB_NOT_SUPPORTED:
            print_debug_message("SGX_QL_TCB_NOT_SUPPORTED", ERROR);
            print_debug_message("Current TCB level cannot be found in platform/enclave TCB info.", ERROR);
            break;

        case SGX_QL_CONFIG_INVALID_JSON:
            print_debug_message("SGX_QL_CONFIG_INVALID_JSON", ERROR);
            print_debug_message("The QPL's config file is in JSON format but has a format error.", ERROR);
            break;

        case SGX_QL_RESULT_INVALID_SIGNATURE:
            print_debug_message("SGX_QL_RESULT_INVALID_SIGNATURE", ERROR);
            print_debug_message("Invalid signature during quote verification.", ERROR);
            break;

        case SGX_QL_ERROR_MAX:
            print_debug_message("SGX_QL_ERROR_MAX", ERROR);
            print_debug_message("Indicate max error to allow better translation. For internal error management.", ERROR);
            break;

        default:
            print_debug_message("Unrecognized SGX status code.", ERROR);
    }

    print_debug_message("=============================================================================", INFO);
    return;
}
