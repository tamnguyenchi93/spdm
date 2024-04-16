/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "enum.hpp"

#ifdef SPDMCPP_ENUM_HPP

// library API
ENUM_START(RetStat, int32_t)
ENUM_VALUE(RetStat, OK, 0)
ENUM_VALUE(RetStat, WARNING_BUFFER_TOO_BIG,
           1) // TODO some of these may be better as flags?! but then we must
              // use helper functions or better make it a simple class?
ENUM_VALUE(RetStat, ERROR_UNKNOWN, -1)
ENUM_VALUE(RetStat, ERROR_BUFFER_TOO_SMALL, -2)
ENUM_VALUE(RetStat, ERROR_WRONG_REQUEST_RESPONSE_CODE, -3)
ENUM_VALUE(RetStat, ERROR_UNKNOWN_REQUEST_RESPONSE_CODE, -4)
ENUM_VALUE(RetStat, ERROR_RESPONSE, -5)
ENUM_VALUE(RetStat, ERROR_TIMEOUT, -6)
ENUM_VALUE(RetStat, ERROR_INVALID_HEADER_VERSION, -7)
ENUM_VALUE(RetStat, ERROR_UNSUPPORTED_SPDM_VERSION, -8)
ENUM_VALUE(RetStat, ERROR_ROOT_CERTIFICATE_HASH_INVALID, -9)
ENUM_VALUE(RetStat, ERROR_CERTIFICATE_PARSING_ERROR, -10)
ENUM_VALUE(RetStat, ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID, -11)
ENUM_VALUE(RetStat, ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED, -12)
ENUM_VALUE(RetStat, ERROR_AUTHENTICATION_FAILED, -13)
ENUM_VALUE(RetStat, ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED, -14)
ENUM_VALUE(RetStat, ERROR_MISSING_CAPABILITY_CERT, -15)
ENUM_VALUE(RetStat, ERROR_MISSING_CAPABILITY_CHAL, -16)
ENUM_VALUE(RetStat, ERROR_MISSING_CAPABILITY_MEAS, -17)
ENUM_VALUE(RetStat, ERROR_WRONG_MCTP_TYPE, -18)
ENUM_VALUE(RetStat, ERROR_WRONG_EID, -19)
ENUM_VALUE(RetStat, ERROR_CERTIFICATE_CHAIN_SIZE_INVALID, -20)
ENUM_VALUE(RetStat, ERROR_INVALID_FLAG_SIZE, -21)
ENUM_VALUE(RetStat, ERROR_INDICES_INVALID_SIZE, -22)
ENUM_VALUE(RetStat, ERROR_WRONG_ALGO_BITS, -23)
ENUM_VALUE(RetStat, ERROR_INVALID_PARAMETER, -24)
ENUM_VALUE(RetStat, ERROR_INVALID_RESERVED, -25)
ENUM_VALUE(RetStat, ERROR_WRONG_MCTP_TAG, -26)
ENUM_VALUE(RetStat, ERROR_WRONG_MCTP_TO, -27)
ENUM_END()

ENUM_START(ConnectionInfoEnum, uint8_t)
ENUM_VALUE(ConnectionInfoEnum, SUPPORTED_VERSIONS, 0)
ENUM_VALUE(ConnectionInfoEnum, CHOOSEN_VERSION, 1)
ENUM_VALUE(ConnectionInfoEnum, CAPABILITIES, 2)
ENUM_VALUE(ConnectionInfoEnum, ALGORITHMS, 3)
ENUM_VALUE(ConnectionInfoEnum, DIGESTS, 4)
ENUM_VALUE(ConnectionInfoEnum, MEASUREMENTS, 5)
ENUM_VALUE(ConnectionInfoEnum, NUM, 6)
ENUM_END()

ENUM_START(SlotInfoEnum, uint8_t)
ENUM_VALUE(SlotInfoEnum, DIGEST, 0)
ENUM_VALUE(SlotInfoEnum, CERTIFICATES, 1)
ENUM_VALUE(SlotInfoEnum, NUM, 3)
ENUM_END()

ENUM_START(HashEnum, uint8_t)
ENUM_VALUE(HashEnum, NONE, 0)
ENUM_VALUE(HashEnum, TPM_ALG_SHA_256, 1)
ENUM_VALUE(HashEnum, TPM_ALG_SHA_384, 2)
ENUM_VALUE(HashEnum, TPM_ALG_SHA_512, 3)
ENUM_VALUE(HashEnum, INVALID, 4)
ENUM_END()

ENUM_START(SignatureEnum, uint8_t)
ENUM_VALUE(SignatureEnum, NONE, 0)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSASSA_2048, 1)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSAPSS_2048, 2)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSASSA_3072, 3)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSAPSS_3072, 4)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSASSA_4096, 5)
ENUM_VALUE(SignatureEnum, TPM_ALG_RSAPSS_4096, 6)
ENUM_VALUE(SignatureEnum, TPM_ALG_ECDSA_ECC_NIST_P256, 7)
ENUM_VALUE(SignatureEnum, TPM_ALG_ECDSA_ECC_NIST_P384, 8)
ENUM_VALUE(SignatureEnum, TPM_ALG_ECDSA_ECC_NIST_P521, 9)
ENUM_VALUE(SignatureEnum, INVALID, 10)
ENUM_END()

// MCTP
ENUM_START(MCTPMessageTypeEnum, uint8_t)
ENUM_VALUE(MCTPMessageTypeEnum, CONTROL, 0x00)
ENUM_VALUE(MCTPMessageTypeEnum, PLDM, 0x01)
ENUM_VALUE(MCTPMessageTypeEnum, SPDM, 0x05)
ENUM_VALUE(MCTPMessageTypeEnum, SECURED, 0x06)
ENUM_END()


ENUM_START(MessageVersionEnum, uint8_t)
ENUM_VALUE(MessageVersionEnum, UNKNOWN, 0)
ENUM_VALUE(MessageVersionEnum, SPDM_1_0, 0x10)
ENUM_VALUE(MessageVersionEnum, SPDM_1_1, 0x11)
ENUM_END()

// WARNING when changing REMEMBER to MODIFY isRequest and isResponse
// accordingly!
ENUM_START(RequestResponseEnum, uint8_t)
ENUM_VALUE(RequestResponseEnum, INVALID, 0)
/// SPDM request code (1.0)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_DIGESTS, 0x81)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_CERTIFICATE, 0x82)
ENUM_VALUE(RequestResponseEnum, REQUEST_CHALLENGE, 0x83)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_VERSION, 0x84)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_MEASUREMENTS, 0xE0)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_CAPABILITIES, 0xE1)
ENUM_VALUE(RequestResponseEnum, REQUEST_NEGOTIATE_ALGORITHMS, 0xE3)
ENUM_VALUE(RequestResponseEnum, REQUEST_VENDOR_DEFINED_REQUEST, 0xFE)
ENUM_VALUE(RequestResponseEnum, REQUEST_RESPOND_IF_READY, 0xFF)
/// SPDM request code (1.1)
ENUM_VALUE(RequestResponseEnum, REQUEST_KEY_EXCHANGE, 0xE4)
ENUM_VALUE(RequestResponseEnum, REQUEST_FINISH, 0xE5)
ENUM_VALUE(RequestResponseEnum, REQUEST_PSK_EXCHANGE, 0xE6)
ENUM_VALUE(RequestResponseEnum, REQUEST_PSK_FINISH, 0xE7)
ENUM_VALUE(RequestResponseEnum, REQUEST_HEARTBEAT, 0xE8)
ENUM_VALUE(RequestResponseEnum, REQUEST_KEY_UPDATE, 0xE9)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_ENCAPSULATED_REQUEST, 0xEA)
ENUM_VALUE(RequestResponseEnum, REQUEST_DELIVER_ENCAPSULATED_RESPONSE, 0xEB)
ENUM_VALUE(RequestResponseEnum, REQUEST_END_SESSION, 0xEC)
/// SPDM response code (1.0)
ENUM_VALUE(RequestResponseEnum, RESPONSE_DIGESTS, 0x01)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CERTIFICATE, 0x02)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CHALLENGE_AUTH, 0x03)
ENUM_VALUE(RequestResponseEnum, RESPONSE_VERSION, 0x04)
ENUM_VALUE(RequestResponseEnum, RESPONSE_MEASUREMENTS, 0x60)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CAPABILITIES, 0x61)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ALGORITHMS, 0x63)
ENUM_VALUE(RequestResponseEnum, RESPONSE_VENDOR_DEFINED_RESPONSE, 0x7E)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ERROR, 0x7F)
/// SPDM response code (1.1)
ENUM_VALUE(RequestResponseEnum, RESPONSE_KEY_EXCHANGE_RSP, 0x64)
ENUM_VALUE(RequestResponseEnum, RESPONSE_FINISH_RSP, 0x65)
ENUM_VALUE(RequestResponseEnum, RESPONSE_PSK_EXCHANGE_RSP, 0x66)
ENUM_VALUE(RequestResponseEnum, RESPONSE_PSK_FINISH_RSP, 0x67)
ENUM_VALUE(RequestResponseEnum, RESPONSE_HEARTBEAT_ACK, 0x68)
ENUM_VALUE(RequestResponseEnum, RESPONSE_KEY_UPDATE_ACK, 0x69)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ENCAPSULATED_REQUEST, 0x6A)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ENCAPSULATED_RESPONSE_ACK, 0x6B)
ENUM_VALUE(RequestResponseEnum, RESPONSE_END_SESSION_ACK, 0x6C)
ENUM_END()
// WARNING when changing REMEMBER to MODIFY isRequest and isResponse
// accordingly!

ENUM_START(AlgTypeEnum, uint8_t)
ENUM_VALUE(AlgTypeEnum, UNKNOWN, 0)
ENUM_VALUE(AlgTypeEnum, DHE, 2)
ENUM_VALUE(AlgTypeEnum, AEADCipherSuite, 3)
ENUM_VALUE(AlgTypeEnum, ReqBaseAsymAlg, 4)
ENUM_VALUE(AlgTypeEnum, KeySchedule, 5)
ENUM_END()

#endif
