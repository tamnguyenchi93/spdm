/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include "assert.hpp"
#include "common.hpp"
#include "context.hpp"
#include "event.hpp"
#include "hash.hpp"
#include "mbedtls_support.hpp"
#include "signature.hpp"

#include <array>
#include <bitset>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace spdmcpp
{
/*
class FlowClass
{
  public:
    FlowClass(ConnectionClass* con) : Connection(con)
    {}
    virtual ~FlowClass() = 0;

    virtual RetStat handle_send() = 0;
    virtual RetStat handleRecv(std::vector<uint8_t>& buf) = 0;

  protected:
    ConnectionClass* Connection = nullptr;
};

class QueryFlowClass : public FlowClass
{
  public:
    QueryFlowClass(ConnectionClass* con) : FlowClass(con)
    {}

    enum StateEnum
    {
        STATE_START,
        STATE_GOT_VERSION,
        STATE_GOT_CAPABILITIES,
        STATE_GOT_ALGORITHMS,
        STATE_GOT_DIGEST,
        STATE_END,
    };

    RetStat handle_send();
    RetStat handleRecv(std::vector<uint8_t>& buf);

  private:
    StateEnum State = STATE_START;
};*/

/** @class TimingClass
 *  @brief Helper class for calculating timeout periods
 *  @details Timeouts defined by DSP0274_1.1.1 section "9 Timing requirements"
 * page 29
 */
class TimingClass
{
  public:
    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - Gateway ip address.
     */
    timeout_ms_t getT1() const
    {
        return RTT + sT1;
    }
    timeout_ms_t getT2() const
    {
        return RTT + CT;
    }

    void setCTExponent(uint8_t ctexp)
    {
        // the spdm specification defines timeouts in microseconds,
        // we use milliseconds, so convert
        if (ctexp < 10) // 2^10 is < 1024 us, so < 1 ms
        {
            CT = 1; // so set to 1 ms
            return;
        }
        ctexp -= 10;
        if (ctexp >= sizeof(CT) * 8) // exceeds value range, cap to max
        {
            CT = timeoutMsMaximum;
            return;
        }
        CT = static_cast<timeout_ms_t>(1) << ctexp;
        // TODO add the extra missing bit due to dividing by 1024 instead of
        // 1000;
    }

  private:
    timeout_ms_t RTT = 3000; // round-trip transport implementation defined,
                             // TODO likely needs to be CLI configurable?!
                             // openbmc in qemu is extremely slow
    static constexpr timeout_ms_t sT1 = 100;

    timeout_ms_t CT = 0;
};

/** @class ConnectionClass
 *  @brief Class for handling communication with a specific SPDM Responder
 *  @details Currently the core purpose of this class is to perform the
 *           following flows from the DSP0274_1.1.1 spec:
 *           - "10.1 Capability discovery and negotiation" page 32
 *           - "10.5 Responder identity authentication" page 52-58
 *           - "10.10 Firmware and other measurements" page 68-77
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class ConnectionClass : public NonCopyable
{
    // TODO this has become extremely spaghetti (not enough time to do better,
    // and spdm spec is very stateful...), but it's worth trying to refactor
  public:
    /** Type alias to distinguish Certificate Slot Indices */
    using SlotIdx = uint8_t;
    bool stateEnabled = true;

    /** Constant to define the maximum possible number of slots defined by
     * DSP0274_1.1.1 page 56 */
    static constexpr SlotIdx slotNum = 8;

    /** @brief Main constructor
     *  @param[in] context - Context containing various common configuration and
     * information
     *  @param[in] log - the LogClass to use for logging
     */
    explicit ConnectionClass(const ContextClass& context, LogClass& log,
                             uint8_t eid, std::string sockPath);

    ~ConnectionClass() = default;

    /** @brief get send timeout during the connection
     *
     */
    auto getSendTimeoutValue() const noexcept
    {
        return SendTimeout;
    }

    /** @brief Get send buffer value
     *
     */
    const auto& getSendBufferRef() const noexcept
    {
        return SendBuffer;
    }

    /** @brief Registers a TransportClass for handling the connection (e.g. with
     * standard mtcp-demux-daemon the instance handles encapsulating with the
     * EndpointID)
     *  @param[in] transport - Object to be used for sending/reading messages,
     * ConnectionClass does not take ownership and will not deallocate the
     * object
     */
    void registerTransport(TransportClass& trans)
    {
        SPDMCPP_ASSERT(!transport);
        transport = &trans;
    }

    /** @brief Unregisters the TransportClass object, should be called before
     * destroying ConnectionClass
     *  @param[in] transport - the parameter is provided just for verifying
     * correctness (register and unregister calls must match and can't be
     * redundant)
     */
    void unregisterTransport(TransportClass& trans)
    {
        SPDMCPP_ASSERT(transport == &trans);
        transport = nullptr;
    }

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     */
    RetStat refreshMeasurements(SlotIdx slotidx);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] nonce - The nonce that should be embeded in the appropriate
     * field during authentication and measurement DSP0274_1.1.1 page 60 and 70
     */
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] measurementIndices - A bitmask of the measurements that
     * should be requested, bit 0 is reserved and invalid, and bit 255 is
     * signifies that all measurements should be requested at once, (if bit 255
     * is set all others should be unset)
     */
    RetStat refreshMeasurements(SlotIdx slotidx,
                                const std::bitset<256>& measurementIndices);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] measurementIndices - A bitmask of the measurements that
     * should be requested, bit 0 is reserved and invalid, and bit 255 is
     * signifies that all measurements should be requested at once, (if bit 255
     * is set all others should be unset)
     *  @param[in] nonce - The nonce that should be embeded in the appropriate
     * field during authentication and measurement DSP0274_1.1.1 page 60 and 70
     */
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce,
                                const std::bitset<256>& measurementIndices);

    /** @brief Resets all connection information to a state equivalent to just
     * after constructing ConnectionClass
     */
    void resetConnection();

    /** @brief Gets the Certificate Slot Index that was used during the current
     * and/or last performed communication flow, this is the value that was
     * passed to the refreshMeasurements() function call
     */
    SlotIdx getCurrentCertificateSlotIdx() const
    {
        return CertificateSlotIdx;
    }

    /** @brief Function to query whether the ConnectionClass has received
     * the given information from the responder
     */
    bool hasInfo(ConnectionInfoEnum info) const
    {
        return !!(GotInfo &
                  (1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                       info)));
    }

    /** @brief Function to query whether the ConnectionClass has received
     * the given information from the responder for a specific Certificate Slot
     */
    bool slotHasInfo(SlotIdx slotidx, SlotInfoEnum info) const
    {
        SPDMCPP_ASSERT(slotidx < slotNum);
        return !!(
            Slots[slotidx].GotInfo &
            (1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info)));
    }

    /** @brief Function to query whether ConnectionClass is still waiting for
     * some response message from an SPDM Responder
     *  @details After issuing a refreshMeasurement call and passing new
     * messages this function can be used to detect when the communication flow
     * is finished (both successfully or with an error condition)
     */
    bool isWaitingForResponse() const
    {
        return WaitingForResponse != RequestResponseEnum::INVALID;
    }

    /* @brief Get wait for state */
    auto getDbgLastWaitState() const noexcept
    {
        return LastWaitingForResponse;
    }

    /* @brief Get wait for response state */
    RequestResponseEnum getWaitingForResponse() const
    {
        return WaitingForResponse;
    }

    /** @brief The hash algorithm used for generating signatures
     */
    SignatureEnum getSignatureEnum() const
    {
        SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toSignature(Algorithms.Min.BaseAsymAlgo);
    }
    /** @brief The hash algorithm used for generating signatures
     */
    HashEnum getSignatureHashEnum() const
    {
        SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.BaseHashAlgo);
    }
    /** @brief The hash algorithm used for generating measurement digests
     */
    HashEnum getMeasurementHashEnum() const
    {
        SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.MeasurementHashAlgo);
    }

    /** @brief Capabilities flag for responder capabilities
     *
     */
    auto getCapabilitiesFlags() const
    {
        SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CAPABILITIES));
        return responderCapabilitiesFlags;
    }

    /** @brief The SPDM version used during communication
     */
    MessageVersionEnum getMessageVersion() const
    {
        SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
        return MessageVersion;
    }

    /** @brief Returns the certificate chain for the given slot index
     *  @details Note this function will return false if the certificate chain
     * was not fetched for the given slot (even if it is available on the device
     * itself)
     *  @param[out] buf - the buffer into which the certificate chain is written
     *  @returns true if the certificate chain was available and written into
     * buf, false otherwise
     */
    bool getCertificatesDER(std::vector<uint8_t>& buf, SlotIdx slotidx) const;

    /** @brief Returns the certificate chain for the given slot index
     *  @details Note this function will return false if the certificate chain
     * was not fetched for the given slot (even if it is available on the device
     * itself) or if there was an unexpected error encoding it
     *  @param[out] str - the string into which the certificate chain is written
     *  @returns true if the certificate chain was available and written into
     * buf, false otherwise
     */
    bool getCertificatesPEM(std::string& str, SlotIdx slotidx) const;

    /** @brief The buffer containing measurements communication, used for
     * computing the L1/L2 hash
     *  @details Contains all the GET_MEASUREMENTS requests and corresponding
     * MEASUREMENTS responses
     */
    using DMTFMeasurementsContainer =
        std::map<uint8_t, PacketMeasurementFieldVar>;
    const DMTFMeasurementsContainer& getDMTFMeasurements() const
    {
        return DMTFMeasurements;
    }
    /** @brief The buffer containing measurements communication, used for
     * computing the L1/L2 hash
     *  @details Contains all the GET_MEASUREMENTS requests and corresponding
     * MEASUREMENTS responses
     */
    const std::vector<uint8_t>& getSignedMeasurementsBuffer() const
    {
        return refBuf(BufEnum::L);
    }
    /** @brief The L1/L2 hash of the measurements, as returned by
     * getSignedMeasurementsBuffer()
     */
    const std::vector<uint8_t>& getSignedMeasurementsHash() const
    {
        return MeasurementsHash;
    }
    /** @brief Signature for getSignedMeasurementsHash() and corresponding to
     * getSignedMeasurementsBuffer()
     *  @details This is the signature generated by the Responder
     */
    const std::vector<uint8_t>& getMeasurementsSignature() const
    {
        return MeasurementsSignature;
    }
    const nonce_array_32& getMeasurementNonce() const
    {
        return MeasurementNonce;
    }

    /** @brief Returns the LogClass used for logging the communication flow and
     * packets
     */
    LogClass& getLog()
    {
        return Log;
    }

    /** @brief This is the buffer that the received response data should be
     * stored in prior to calling handleRecv()
     *  @details TODO this interface is likely quite confusing and should be
     * refactored
     */
    std::vector<uint8_t>& getResponseBufferRef()
    {
        return ResponseBuffer;
    }

    /** @brief Callback for handling incomming events
     */
    [[nodiscard]] RetStat handleEvent(EventClass& event);

    /**
     * @brief Callback for handling response if ready delay
     */
    [[nodiscard]] RetStat handleResponseIfReadyDelay();

  protected:
    [[nodiscard]] RetStat tryGetVersion();

    [[nodiscard]] RetStat tryGetCapabilities();
    [[nodiscard]] RetStat tryNegotiateAlgorithms();
    [[nodiscard]] RetStat tryGetDigest();
    [[nodiscard]] RetStat tryGetCertificate(SlotIdx idx);
    [[nodiscard]] RetStat tryGetCertificateChunk(SlotIdx idx);
    [[nodiscard]] RetStat tryGetMeasurements();
    [[nodiscard]] RetStat tryGetMeasurements(uint8_t idx);

    [[nodiscard]] RetStat tryChallengeIfSupported();
    [[nodiscard]] RetStat tryChallenge();

    template <class T>
    [[nodiscard]] RetStat handleRecv();
    [[nodiscard]] RetStat handleRecv(EventReceiveClass& event);
    [[nodiscard]] RetStat handleTimeoutOrRetry(EventTimeoutClass& event);

    /** @brief This enum is used for selecting the buffer for computing the
     * M1/M2 and L1/L2 hash
     *  @details The definitions for A/B/C buffers which are used for the M1/M2
     * hash are defined in DSP0274_1.1.1 pages 64-66. The L buffer is used for
     * the L1/L2 hash, defined in DSP0274_1.1.1 pages 73-75
     */
    enum class BufEnum : uint8_t
    {
        M_START,
        A = M_START,
        B,
        C,
        M_END = C,
        L,
        NUM,
    };

    /** @struct SlotClass
     *  @brief Protected helper struct for storing the Certificate chains
     * received from the Responder
     */
    // NOLINTNEXTLINE cppcoreguidelines-special-member-functions
    struct SlotClass
    {
        /** @brief SPDM digest of the certificate chain
         */
        std::vector<uint8_t> Digest;

        /** @brief storage for the accumulated certificate_chain as defined in
         * DSP0274_1.1.1 pages 54-55
         */
        std::vector<uint8_t> Certificates;

        /** @brief SPDM parsed certificates decoded from the certificate_chain
         * ordered root, intermediate, leaf
         */
        std::vector<std::unique_ptr<mbedtls_x509_crt_raii>> MCertificates;
        // TODO mbedtls_x509_crt should be abstracted to CertificateClass

        /** @brief Offset into Certificates[] where the DER data starts
         */
        size_t CertificateOffset = 0;

        /** @brief Holder for the SlotInfoEnum bits
         */
        uint8_t GotInfo = 0;
        SPDMCPP_STATIC_ASSERT(sizeof(GotInfo) * 8 >=
                              static_cast<std::underlying_type_t<SlotInfoEnum>>(
                                  SlotInfoEnum::NUM));

        /** @brief Mark the specified SlotInfoEnum as "available", to be later
         * queried by ConnectionClass::slotHasInfo()
         */
        void markInfo(SlotInfoEnum info)
        {
            GotInfo |=
                1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info);
        }

        /** @brief Gets the first certificate from the chain, pressumed to be
         * the CA root certificate
         */
        mbedtls_x509_crt* getRootCert() const
        {
            // SPDMCPP_ASSERT(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return *MCertificates[0];
        }
        /** @brief Gets the last certificate from the chain, pressumed to be the
         * Responder leaf certificate
         */
        mbedtls_x509_crt* getLeafCert() const
        {
            // SPDMCPP_ASSERT(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return *MCertificates[MCertificates.size() - 1];
        }

        /** @brief clears all the fields of the given slot
         */
        void clear()
        {
            GotInfo = 0;
            CertificateOffset = 0;

            Digest.clear();
            Certificates.clear();
            MCertificates.clear();
        }

        ~SlotClass()
        {
            clear();
        }
    };

    /** @brief Parses a buffer containing PacketCertificateChain as returned by
     * a reposnder in CERTIFICATE_RESPONSE into SlotClass
     *  @param[out] slot - SlotClass into which the certificates should be
     * written
     *  @param[in] buf - Buffer with data to parse
     */
    RetStat parseCertChain(SlotClass& slot, const std::vector<uint8_t>& buf);

    /** @brief verifies the certificate chain is valid
     */
    RetStat verifyCertificateChain(const SlotClass& slot);

    /** @brief This function interprets the response previously stored in
     * ResponseBuffer
     *  @param[out] packet - The response type and variable into which the
     * response should be decoded into
     *  @param[in] fargs - Any additional information that may be needed for
     * decoding the packet, typically PacketDecodeInfo
     */
    template <typename T, typename... Targs>
    RetStat interpretResponse(T& packet, Targs... fargs);

    /** @brief Sends a request and sets up a wait for a response
     *  @param[in] request - The request to send
     *  @param[in] response - The type of response to setup the wait for, the
     * value is actually ignored, only the type is relevant
     *  @param[in] bufidx - The buffer to which the request should be appended
     * (further details in BufEnum description, if BufEnum::NUM then the request
     * will not be appended to any buffer
     *  @param[in] timeout - The response timeout
     *  @param[in] retry - The number of times the request should be
     * automatically retried if a response was not received
     */
    template <typename R, typename T>
    RetStat sendRequestSetupResponse(const T& request,
                                     BufEnum bufidx = BufEnum::NUM,
                                     timeout_ms_t timeout = timeoutMsInfinite,
                                     uint16_t retry = 4);

    /** @brief This is the common implementation for all the public
     * refreshMeasurements variants
     */
    RetStat refreshMeasurementsInternal();

    /** @brief Low-level, typically shouldn't be used, sends a request
     */
    template <typename T>
    RetStat sendRequest(const T& packet, BufEnum bufidx = BufEnum::NUM);

    /** @brief Low-level, typically shouldn't be used, sets up information that
     * we're waiting for a response packet of the given type and setups a
     * timeout if it isn't timeoutMsInfinite
     *  @param[in] timeout - The response timeout
     *  @param[in] retry - The number of times the request should be
     * automatically retried if a response was not received
     */

    template <typename T>
    RetStat setupResponseWait(timeout_ms_t timeout = timeoutMsInfinite,
                              uint16_t retry = 4);

    /** @brief Clears a previously setup response timeout
     */
    void clearTimeout();

    /**
     * Retry command n times with timeout between packets
     */
    RetStat retryTimeout(RetStat lastError, timeout_ms_t timeout = 3000,
                         uint16_t retry = 4);

    std::vector<uint8_t> SendBuffer;
    timeout_ms_t SendTimeout = 0;
    uint16_t SendRetry = 0;
    RetStat lastRetryError{};

    /** @brief Buffer for the received response from which interpretResponse
     * decodes the packet
     */
    std::vector<uint8_t> ResponseBuffer;

    /** @brief Offset into ResponseBuffer where the actual spdm packet starts,
     * before the offset is the transport layer data
     */
    size_t ResponseBufferSPDMOffset = 0;

    const ContextClass& context;
    TransportClass* transport = nullptr;
    LogClass& Log;

    /** @brief All versions reported by the Responder as being supported
     */
    std::vector<PacketVersionNumber> SupportedVersions;

    /** @brief The choosen version for communicating with the Responder
     */
    MessageVersionEnum MessageVersion = MessageVersionEnum::UNKNOWN;

    /** @brief The supported Responder Capabilities
     */
    ResponderCapabilitiesFlags responderCapabilitiesFlags =
        ResponderCapabilitiesFlags::NIL;

    /** @brief The decodeded Algorithms response from the Responder
     */
    PacketAlgorithmsResponseVar Algorithms;

    /** @brief The per certificate slot information queried from the Responder
     */
    std::array<SlotClass, slotNum> Slots;

    TimingClass Timings;

    /** @brief Buffers for storing the communication flow and computing M1/M2
     * and L1/L2 hashes
     */
    std::array<std::vector<uint8_t>, static_cast<size_t>(BufEnum::NUM)> Bufs;

    /** @brief Low-level helper metheod
     */
    std::vector<uint8_t>& refBuf(BufEnum bufidx)
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    /** @brief Low-level helper metheod
     */
    const std::vector<uint8_t>& refBuf(BufEnum bufidx) const
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }

    /** @brief Calculates the given hashtype of the given storage buffer
     */
    void hashBuf(std::vector<uint8_t>& hash, HashEnum hashtype,
                 BufEnum bufidx) const
    {
        HashClass::compute(hash, hashtype, refBuf(bufidx));
    }

    /** @brief Low-level helper metheod
     */
    void appendToBuf(BufEnum bufidx, uint8_t* data, size_t size)
    {
        // HashM1M2.update(data, size);
        std::vector<uint8_t>& buf = refBuf(bufidx);
        size_t off = buf.size();
        buf.resize(off + size);
        memcpy(&buf[off], data, size);
    }
    /** @brief Low-level helper metheod
     */
    void appendRecvToBuf(BufEnum bufidx)
    {
        appendToBuf(bufidx, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }

    /** @brief This contains certain information from some requests necessary
     * for decoding the expected response packet
     */
    PacketDecodeInfo packetDecodeInfo;

    /** @brief Storage for the received and decoded measurements
     */
    DMTFMeasurementsContainer DMTFMeasurements;

    /** @brief Storage for the final L1/L2 hash
     */
    std::vector<uint8_t> MeasurementsHash;

    /** @brief Storage for the Responder signature of the L1/L2 hash
     */
    std::vector<uint8_t> MeasurementsSignature;

    /** @brief Storage for the nonce used during communication, it's  either the
     * value passed to refreshMeasurements, or a random value
     */
    nonce_array_32 MeasurementNonce{};

    /** @brief A bitmask of the requested measurements as passed to
     * refreshMeasurements
     */
    std::bitset<256> MeasurementIndices;

    /** @brief The certificate slot index that was passed to refreshMeasurements
     * and is used during communication
     */
    SlotIdx CertificateSlotIdx = slotNum;

    /** @brief The response that we're expecting to receive typically setup by
     * asyncResponse called by sendRequestSetupResponse
     */
    RequestResponseEnum WaitingForResponse = RequestResponseEnum::INVALID;

    /** @brief The last response we are wating for debug purpose only
     *
     */
    RequestResponseEnum LastWaitingForResponse = RequestResponseEnum::INVALID;

    /** @brief Bitmask for which ConnectionInfoEnum we're holding used by
     * markInfo and hasInfo
     */
    uint8_t GotInfo = 0;
    SPDMCPP_STATIC_ASSERT(
        sizeof(GotInfo) * 8 >=
        static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
            ConnectionInfoEnum::NUM));

    /** @brief Marks the given ConnectionInfoEnum as being received/available,
     * can be queried with hasInfo
     */
    void markInfo(ConnectionInfoEnum info)
    {
        GotInfo |=
            1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(info);
    }

    /** @brief Low-level helper function for getting the first MeasurementIndex
     * that should be requested from the Responder
     */
    uint8_t getFirstMeasurementIndex() const
    {
        SPDMCPP_ASSERT(MeasurementIndices.any());
        for (uint8_t i = 0; i < 255; ++i)
        {
            if (MeasurementIndices[i])
            {
                return i;
            }
        }
        // std::unreachable();
        return 255;
    }

  private:
    /** @brief Helper function for choosing the SPDM version that should be used
     * for communication
     */
    RetStat chooseVersion();

    /** @brief Helper function for checking measurements capabilities */
    bool skipMeasurements() const noexcept
    {
        return !(responderCapabilitiesFlags &
                 (ResponderCapabilitiesFlags::MEAS_CAP_10 |
                  ResponderCapabilitiesFlags::MEAS_CAP_01));
    }

    /** @brief Helper function for checking certificate capabilities */
    bool skipCertificate() const noexcept
    {
        return !(responderCapabilitiesFlags &
                 ResponderCapabilitiesFlags::CERT_CAP);
    }

    /** @brief Helper function for checking signature capabilities */
    bool skipVerifySignature() const noexcept
    {
        return ((responderCapabilitiesFlags &
                 ResponderCapabilitiesFlags::MEAS_CAP_01) ==
                ResponderCapabilitiesFlags::MEAS_CAP_01);
    }

    /// Connection socket path
    const std::string sockPath;

    /// Try retry certificate count
    uint8_t retryCertCount{};

    /// Retry packet count
    uint8_t retryPktCount{};

    /// Response if ready token value
    std::optional<uint8_t> respIfReadyToken;

    /// Request code for retry if ready
    uint8_t respIfReqCode;

    /// Return true if retry is needed
    static bool checkErrorCodeForRetry(RetStat ec);

  public:
    const uint8_t m_eid;
};

} // namespace spdmcpp
