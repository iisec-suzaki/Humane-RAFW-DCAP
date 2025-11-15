#pragma once
#include <sgx_error.h>
#include <sgx_ql_lib_common.h>
#include <sgx_qve_header.h>
#include "debug_print.hpp"

void print_sgx_status(sgx_status_t status);

void print_ql_qv_result(sgx_ql_qv_result_t quote_verification_result);

void print_ql_status(quote3_error_t qe3_error);