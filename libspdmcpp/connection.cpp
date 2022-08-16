
#include <spdmcpp/connection.hpp>
#include <spdmcpp/connection_inl.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <algorithm>
#include <fstream>

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs)                                 \
    do                                                                         \
    {                                                                          \
        SPDMCPP_LOG_TRACE_RS(Log, (rs));                                       \
        if (isError(rs))                                                       \
            return rs;                                                         \
    } while (false)

namespace spdmcpp
{

ConnectionClass::ConnectionClass(const ContextClass& cont, LogClass& log) :
    context(cont), Log(log)
{
    resetConnection();
}

RetStat ConnectionClass::refreshMeasurements(SlotIdx slotidx)
{
    CertificateSlotIdx = slotidx;
    fillRandom(MeasurementNonce);
    MeasurementIndices.reset();
    MeasurementIndices.set(255);
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(SlotIdx slotidx,
                                             const nonce_array_32& nonce)
{
    CertificateSlotIdx = slotidx;
    MeasurementNonce = nonce;
    MeasurementIndices.reset();
    MeasurementIndices.set(255);
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(
    SlotIdx slotidx, const std::bitset<256>& measurementIndices)
{
    CertificateSlotIdx = slotidx;
    fillRandom(MeasurementNonce);
    MeasurementIndices = measurementIndices;
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(
    SlotIdx slotidx, const nonce_array_32& nonce,
    const std::bitset<256>& measurementIndices)
{
    CertificateSlotIdx = slotidx;
    MeasurementNonce = nonce;
    MeasurementIndices = measurementIndices;
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurementsInternal()
{
    if (MeasurementIndices[255])
    {
        SPDMCPP_ASSERT(MeasurementIndices.count() == 1);
    }
    else
    {
        SPDMCPP_ASSERT(!MeasurementIndices[0]);
    }
    auto rs = tryGetVersion();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

void ConnectionClass::resetConnection()
{
    clearTimeout();

    GotInfo = 0;
    CertificateSlotIdx = slotNum;
    MessageVersion = MessageVersionEnum::UNKNOWN;
    WaitingForResponse = RequestResponseEnum::INVALID;
    Algorithms = PacketAlgorithmsResponseVar();
    packetDecodeInfo = PacketDecodeInfo();
    SupportedVersions.clear();

    DMTFMeasurements.clear();
    MeasurementsHash.clear();
    MeasurementsSignature.clear();
    MeasurementNonce.fill(0);
    MeasurementIndices.reset();

    for (auto& s : Slots)
    {
        s.clear();
    }

    for (auto& b : Bufs)
    {
        b.clear();
    }
}

bool ConnectionClass::getCertificatesDER(std::vector<uint8_t>& buf,
                                         SlotIdx slotidx) const
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.clear();

    if (!slotHasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
    {
        return false;
    }

    const SlotClass& slot = Slots[slotidx];

    // Certificate offset tells the offset where the DER data starts.
    if (slot.CertificateOffset == 0 ||
        slot.CertificateOffset >= slot.Certificates.size())
    {
        // Both of the above cases mean that we don't have valid DER data.
        return false;
    }
    auto src = std::span(slot.Certificates).subspan(slot.CertificateOffset);
    buf.resize(src.size());
    std::copy(src.begin(), src.end(), buf.begin());
    return true;
}

bool ConnectionClass::getCertificatesPEM(std::string& str,
                                         SlotIdx slotidx) const
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    str.clear();

    if (!slotHasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
    {
        return false;
    }

    const SlotClass& slot = Slots[slotidx];

    for (auto& cert : slot.MCertificates)
    {
        size_t off = str.size();
        size_t size = 4096;
        str.resize(off + size);
        auto span = std::span(str).subspan(off);
        int ret = mbedtls_pem_write_buffer(
            "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
            (const unsigned char*)(*cert)->raw.p, (*cert)->raw.len,
            // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
            reinterpret_cast<unsigned char*>(span.data()), span.size(), &size);
        if (ret)
        {
            Log.iprint(
                "ConnectionClass::getCertificatesPEM() mbedtls_pem_write_buffer failed with: ");
            Log.println(ret);
            return false;
        }
        // -1 because mbedtls_pem_write_buffer counts the null byte
        str.resize(off + size - 1);
    }
    return true;
}

RetStat ConnectionClass::parseCertChain(SlotClass& slot,
                                        const std::vector<uint8_t>& cert)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    PacketCertificateChain certChain;
    size_t off = 0;
    auto rs = packetDecodeInternal(certChain, cert, off);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    SPDMCPP_ASSERT(certChain.Length == cert.size());
    std::vector<uint8_t> rootCertHash;

    {
        rootCertHash.resize(getHashSize(Algorithms.Min.BaseHashAlgo));
        rs = packetDecodeBasic(rootCertHash, cert, off);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
        Log.iprint("provided root certificate hash = ");
        Log.println(rootCertHash);
    }

    slot.CertificateOffset = off;

    do
    {
        {
            auto [ret, c] = mbedtlsCertParseDer(cert, off);
            if (ret)
            {
                mbedtlsPrintErrorLine(Log, "mbedtls_x509_crt_parse_der()", ret);
                return RetStat::ERROR_CERTIFICATE_PARSING_ERROR;
            }
            slot.MCertificates.push_back(std::move(c));
        }
    } while (off < cert.size());

    return RetStat::OK;
}

RetStat ConnectionClass::verifyCertificateChain(const SlotClass& slot)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    for (size_t i = 1; i < slot.MCertificates.size(); ++i)
    {
        (*slot.MCertificates[i])->next = *slot.MCertificates[i - 1];
        uint32_t rflags = 0;
        int ret = mbedtls_x509_crt_verify(*slot.MCertificates[i - 1],
                                          *slot.MCertificates[i], nullptr,
                                          nullptr, &rflags, nullptr, nullptr);
        Log.iprint("mbedtls_x509_crt_verify ret = ");
        Log.println(ret);
        if (ret)
        {
            std::string info;
            info.resize(4096);
            ret = mbedtls_x509_crt_verify_info(info.data(), info.size(), "",
                                               rflags);
            SPDMCPP_ASSERT(ret >= 0);
            info.resize(ret);
            Log.print(info);
            return RetStat::ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED;
        }
    }
    return RetStat::OK;
}

RetStat ConnectionClass::tryGetVersion()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    // SPDMCPP_ASSERT(MessageVersion == MessageVersionEnum::UNKNOWN);

    for (auto& b : Bufs)
    {
        b.clear();
    }

    PacketGetVersionRequest spdmRequest;
    auto rs = sendRequestSetupResponse<PacketVersionResponseVar>(
        spdmRequest, BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketVersionResponseVar>()
{
    PacketVersionResponseVar resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    // the version response should have 1.0 in the header according to
    // DSP0274_1.1.1 page 34
    if (resp.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
    {
        return RetStat::ERROR_INVALID_HEADER_VERSION;
    }

    std::swap(SupportedVersions, resp.VersionNumberEntries);
    markInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS);

    appendRecvToBuf(BufEnum::A);

    rs = chooseVersion();
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    Log.iprint("chosen MessageVersion: ");
    Log.println(MessageVersion);

    rs = tryGetCapabilities();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::chooseVersion()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS));

    std::vector<MessageVersionEnum> vers;
    vers.reserve(SupportedVersions.size());
    for (auto iter : SupportedVersions)
    {
        MessageVersionEnum e = iter.getMessageVersion();
        if (e != MessageVersionEnum::UNKNOWN)
        {
            vers.push_back(e);
        }
    }
    std::sort(vers.begin(), vers.end(), std::greater());

    for (auto ours : context.getSupportedVersions())
    {
        for (auto theirs : vers)
        {
            if (ours == theirs)
            {
                MessageVersion = theirs;
                markInfo(ConnectionInfoEnum::CHOOSEN_VERSION);
                return RetStat::OK;
            }
            if (theirs < ours)
            {
                break;
            }
        }
    }
    return RetStat::ERROR_UNSUPPORTED_SPDM_VERSION;
}

RetStat ConnectionClass::tryGetCapabilities()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));

    // NOLINTNEXTLINE cppcoreguidelines-init-variables
    RetStat rs; // which conflicts with cppcheck redundantInitialization
    if (MessageVersion == MessageVersionEnum::SPDM_1_0)
    {
        PacketGetCapabilities10Request request;
        request.Header.MessageVersion = MessageVersion;

        rs = sendRequestSetupResponse<PacketCapabilitiesResponse>(
            request, BufEnum::A, Timings.getT1());
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    else
    {
        PacketGetCapabilitiesRequest request;
        request.Header.MessageVersion = MessageVersion;

        request.Flags = RequesterCapabilitiesFlags::CHAL_CAP;

        rs = sendRequestSetupResponse<PacketCapabilitiesResponse>(
            request, BufEnum::A, Timings.getT1());
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketCapabilitiesResponse>()
{
    PacketCapabilitiesResponse resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    markInfo(ConnectionInfoEnum::CAPABILITIES);
    appendRecvToBuf(BufEnum::A);

    responderCapabilitiesFlags = resp.Flags;
    if (!(resp.Flags & ResponderCapabilitiesFlags::CERT_CAP))
    {
        return RetStat::ERROR_MISSING_CAPABILITY_CERT;
    }
    if (!(resp.Flags & ResponderCapabilitiesFlags::MEAS_CAP_10))
    {
        return RetStat::ERROR_MISSING_CAPABILITY_MEAS;
    }

    Timings.setCTExponent(resp.CTExponent);

    rs = tryNegotiateAlgorithms();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryNegotiateAlgorithms()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CAPABILITIES));

    PacketNegotiateAlgorithmsRequestVar request;
    request.Min.Header.MessageVersion = MessageVersion;
    request.Min.MeasurementSpecification = 1 << 0;

    request.Min.BaseAsymAlgo = BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256 |
                               BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384 |
                               BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521;
    request.Min.BaseHashAlgo = BaseHashAlgoFlags::TPM_ALG_SHA_256 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_384 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_512;

#if 0 // workaround for responders requiring the algorithm structure information
      // in addition to the above flags
    if (MessageVersion != MessageVersionEnum::SPDM_1_0)
    {
        request.PacketReqAlgVector.push_back(
            PacketReqAlgStruct::buildAlgSupported(AlgTypeEnum::DHE, 0x01,
                                                  0x00));
        request.PacketReqAlgVector.push_back(
            PacketReqAlgStruct::buildAlgSupported(AlgTypeEnum::AEADCipherSuite,
                                                  0x02, 0x00));
        request.PacketReqAlgVector.push_back(
            PacketReqAlgStruct::buildReqBaseAsymAlg(request.Min.BaseAsymAlgo));
        request.PacketReqAlgVector.push_back(
            PacketReqAlgStruct::buildAlgSupported(AlgTypeEnum::KeySchedule,
                                                  0x01, 0x00));
    }
#endif

    request.finalize();

    auto rs = sendRequestSetupResponse<PacketAlgorithmsResponseVar>(
        request, BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketAlgorithmsResponseVar>()
{
    // Note that this response is decoded and stored in the ConnectionClass
    // member field because we need information from it for later operations
    PacketAlgorithmsResponseVar& resp = Algorithms;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    markInfo(ConnectionInfoEnum::ALGORITHMS);

    appendRecvToBuf(BufEnum::A);

    packetDecodeInfo.BaseHashSize = getHashSize(resp.Min.BaseHashAlgo);
    packetDecodeInfo.SignatureSize = getSignatureSize(resp.Min.BaseAsymAlgo);

    rs = tryGetDigest();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryGetDigest()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    PacketGetDigestsRequest request;
    request.Header.MessageVersion = MessageVersion;

    auto rs = sendRequestSetupResponse<PacketDigestsResponseVar>(
        request, BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketDigestsResponseVar>()
{
    PacketDigestsResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    bool skipCert = false;
    for (SlotIdx i = 0; i < slotNum; ++i)
    {
        if (resp.Min.Header.Param2 & (1 << i))
        {
            if (i == CertificateSlotIdx &&
                slotHasInfo(i, SlotInfoEnum::DIGEST) &&
                slotHasInfo(i, SlotInfoEnum::CERTIFICATES) &&
                resp.Digests[i] == Slots[i].Digest)
            {
                skipCert = true;
            }
            else
            {
                std::swap(resp.Digests[i], Slots[i].Digest);
                Slots[i].markInfo(SlotInfoEnum::DIGEST);
            }
        }
        else
        {
            // clear slot data in case it is no longer valid
            Slots[i].clear();
            // TODO this may not necessarily be the correct/expected behaviour?
        }
    }
    markInfo(ConnectionInfoEnum::DIGESTS);

    appendRecvToBuf(BufEnum::B);
    if (skipCert)
    {
        rs = tryChallengeIfSupported();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    else
    {
        rs = tryGetCertificate(CertificateSlotIdx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::tryGetCertificateChunk(SlotIdx slotidx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);
    if (slotidx >= slotNum)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[slotidx].Certificates;

    PacketGetCertificateRequest request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = slotidx;
    request.Offset = cert.size();
    request.Length = std::numeric_limits<uint16_t>::max();
    // TODO according to spec DSP0274_1.1.1 page 57 above code isn't entirely
    // correct. Because it should be capped to no more than "The RemainderLength
    // of the preceding GET_CERTIFICATE response."

    auto rs = sendRequestSetupResponse<PacketCertificateResponseVar>(
        request, BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketCertificateResponseVar>()
{
    PacketCertificateResponseVar resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    appendRecvToBuf(BufEnum::B);

    SlotIdx idx = CertificateSlotIdx;
    SlotClass& slot = Slots[idx];
    std::vector<uint8_t>& cert = slot.Certificates;
    if (cert.empty())
    { // first chunk so reserve space for what's expected to come
        cert.reserve(resp.Min.PortionLength + resp.Min.RemainderLength);
    }
    { // store chunk data
        auto off = cert.end() - cert.begin();
        cert.resize(off + resp.Min.PortionLength);
        std::copy(resp.CertificateVector.begin(), resp.CertificateVector.end(),
                  std::next(cert.begin(), off));
    }
    if (resp.Min.RemainderLength)
    { // if there's more expected request it and return (waiting for response)
        rs = tryGetCertificateChunk(idx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }

    // parse chain and store in the respective SlotClass
    rs = parseCertChain(slot, cert);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    if (Log.logLevel >= LogClass::Level::Informational)
    {
        for (auto& c : slot.MCertificates)
        {
            Log.print(mbedtlsToInfoString(*c));
        }
    }

    //rs = verifyCertificateChain(slot);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    slot.markInfo(SlotInfoEnum::CERTIFICATES);

    rs = tryChallengeIfSupported();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryGetCertificate(SlotIdx idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    if (idx >= slotNum)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[idx].Certificates;
    cert.clear();

    auto rs = tryGetCertificateChunk(idx);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryChallengeIfSupported()
{
    if (!(responderCapabilitiesFlags & ResponderCapabilitiesFlags::CHAL_CAP))
    {
        return tryGetMeasurements();
    }
    return tryChallenge();
}

RetStat ConnectionClass::tryChallenge()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    PacketChallengeRequest request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = CertificateSlotIdx;
    request.Header.Param2 = packetDecodeInfo.ChallengeParam2 = 0xFF;
    // 		request.Header.Param2 = packetDecodeInfo.ChallengeParam2 = 1;
    fillRandom(request.Nonce);

    auto rs = sendRequestSetupResponse<PacketChallengeAuthResponseVar>(
        request, BufEnum::C, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handleRecv<PacketChallengeAuthResponseVar>()
{
    PacketChallengeAuthResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    appendToBuf(BufEnum::C, &ResponseBuffer[ResponseBufferSPDMOffset],
                ResponseBuffer.size() - ResponseBufferSPDMOffset -
                    packetDecodeInfo.SignatureSize);

    {
        std::vector<uint8_t> hash;
        {
            HashClass ha;
            ha.setup(getSignatureHashEnum());

            for (std::vector<uint8_t>& buf : Bufs)
            {
                if (!buf.empty())
                {
                    ha.update(buf);
                }
            }
            ha.hashFinish(hash);
        }
        Log.iprint("computed m2 hash = ");
        Log.println(hash);

        Log.iprint("resp.SignatureVector = ");
        Log.println(resp.SignatureVector);

        {
            int ret = verifySignature(Slots[CertificateSlotIdx].getLeafCert(),
                                      resp.SignatureVector, hash);
            SPDMCPP_LOG_TRACE_RS(Log, ret);
            if (!ret)
            {
                Log.iprintln(
                    "challenge_auth_response SIGNATURE verify PASSED!");
            }
            else
            {
                mbedtlsPrintErrorLine(Log, "verifySignature()", ret);
                return RetStat::ERROR_AUTHENTICATION_FAILED;
            }
        }
        rs = tryGetMeasurements();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::tryGetMeasurements()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    DMTFMeasurements.clear();

    if (MeasurementIndices[255])
    { // this means we get all measurements at once
        MeasurementIndices.reset();
        return tryGetMeasurements(255);
    }
    if (MeasurementIndices.any())
    { // this means we get some measurements one by one
        uint8_t idx = getFirstMeasurementIndex();
        MeasurementIndices.reset(idx);
        return tryGetMeasurements(idx);
    }
    Log.iprintln("Warning: no measurements were requested?!");
    return RetStat::OK;
}

RetStat ConnectionClass::tryGetMeasurements(uint8_t idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    PacketGetMeasurementsRequestVar request;
    request.Min.Header.MessageVersion = MessageVersion;

    if (MeasurementIndices.none())
    {
        // means this is the last getMeasurements, so we set the nonce and
        // request a signature
        request.Min.Header.Param1 = packetDecodeInfo.GetMeasurementsParam1 =
            0x1;
        request.setNonce();
        request.Nonce = MeasurementNonce;
        request.SlotIDParam = CertificateSlotIdx;
    }
    else
    {
        // there will be more getMeasurements requests so we don't need a
        // signature yet
        request.Min.Header.Param1 = packetDecodeInfo.GetMeasurementsParam1 =
            0x0;
    }

    request.Min.Header.Param2 = idx;

    auto rs = sendRequestSetupResponse<PacketMeasurementsResponseVar>(
        request, BufEnum::L, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handleRecv<PacketMeasurementsResponseVar>()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    PacketMeasurementsResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    // parse and store DMTF Measurements
    for (const auto& block : resp.MeasurementBlockVector)
    {
        if (block.Min.MeasurementSpecification == 1)
        {
            if (DMTFMeasurements.find(block.Min.Index) !=
                DMTFMeasurements.end())
            {
                Log.iprintln("DUPLICATE MeasurementBlock Index!");
            }
            else
            {
                size_t off = 0;
                rs = packetDecodeInternal(DMTFMeasurements[block.Min.Index],
                                          block.MeasurementVector, off);
                SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
                if (off != block.MeasurementVector.size())
                {
                    Log.iprintln("MeasurementBlock not fully parsed!");
                }
            }
        }
    }

    if (packetDecodeInfo.GetMeasurementsParam1 & 1)
    {
        /*HashL1L2.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                        ResponseBuffer.size() - ResponseBufferSPDMOffset -
                            packetDecodeInfo.SignatureSize);*/

        appendToBuf(BufEnum::L, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset -
                        packetDecodeInfo.SignatureSize);

        { // store measurement signature
            MeasurementsSignature.resize(packetDecodeInfo.SignatureSize);
            size_t off = ResponseBuffer.size() - MeasurementsSignature.size();
            memcpy(MeasurementsSignature.data(), &ResponseBuffer[off],
                   MeasurementsSignature.size());
        }
        std::vector<uint8_t>& hash = MeasurementsHash;
        hash.clear();
#if 0
        HashL1L2.hashFinish(hash);
#else
        hashBuf(hash, getSignatureHashEnum(), BufEnum::L);
#endif
        Log.iprint("computed l2 hash = ");
        Log.println(hash);

        int ret = verifySignature(Slots[CertificateSlotIdx].getLeafCert(),
                                  resp.SignatureVector, hash);
        SPDMCPP_LOG_TRACE_RS(Log, ret);
        if (!ret)
        {
            Log.iprintln("measurements SIGNATURE verify PASSED!");
            markInfo(ConnectionInfoEnum::MEASUREMENTS);
        }
        else
        {
            mbedtlsPrintErrorLine(Log, "verifySignature()", ret);
            return RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED;
        }
    }
    else
    {
        appendRecvToBuf(BufEnum::L);

        SPDMCPP_ASSERT(MeasurementIndices.any());
        uint8_t idx = getFirstMeasurementIndex();
        MeasurementIndices.reset(idx);
        return tryGetMeasurements(idx);
    }
    return rs;
}

RetStat ConnectionClass::handleRecv(EventReceiveClass& event)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);

    clearTimeout();

    // swap to avoid copy, this is currently safe because nothing else would
    // want to access the data afterwards
    // TODO however it's error prone, so we should pass the event to each
    // function that needs it instead (via const references)
    std::swap(event.buffer, ResponseBuffer);

    Log.iprint("ResponseBuffer.size() = ");
    Log.println(ResponseBuffer.size());
    Log.iprint("ResponseBuffer = ");
    Log.println(ResponseBuffer);

    // NOLINTNEXTLINE cppcoreguidelines-init-variables
    MessageVersionEnum version;
    // NOLINTNEXTLINE cppcoreguidelines-init-variables
    RequestResponseEnum code;
    // the above conflict with cppcheck redundantInitialization

    { // transport decode
        TransportClass::LayerState lay; // TODO double decode
        if (transport)
        {
            auto rs = transport->decode(ResponseBuffer, lay);
            SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
        }
        ResponseBufferSPDMOffset = lay.getEndOffset();

        if (ResponseBuffer.size() - ResponseBufferSPDMOffset <
            sizeof(PacketMessageHeader))
        {
            return RetStat::ERROR_BUFFER_TOO_SMALL;
        }
        version = packetMessageHeaderGetMessageVersion(
            ResponseBuffer, ResponseBufferSPDMOffset);
        code = packetMessageHeaderGetRequestresponsecode(
            ResponseBuffer, ResponseBufferSPDMOffset);
    }

    // "custom" response handling for ERRORS
    if (code == RequestResponseEnum::RESPONSE_ERROR)
    {
        Log.iprint("RESPONSE_ERROR while waiting for response: ");
        Log.println(WaitingForResponse);
        WaitingForResponse = RequestResponseEnum::INVALID;

        PacketErrorResponseVar err;
        auto rs = interpretResponse(err);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return RetStat::ERROR_RESPONSE;
    }

    // if we're not expecting this response return an error
    if (code != WaitingForResponse)
    {
        Log.iprint("ERROR_WRONG_REQUEST_RESPONSE_CODE: ");
        Log.println(code);
        Log.iprint(" while waiting for response: ");
        Log.println(WaitingForResponse);
        WaitingForResponse = RequestResponseEnum::INVALID;
        return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
    }
    WaitingForResponse = RequestResponseEnum::INVALID;

    RetStat rs = RetStat::ERROR_UNKNOWN;
    if (code == RequestResponseEnum::RESPONSE_VERSION)
    {
        // version response is what sets the MessageVersion, so it has to be
        // handled separately from the packets below
        rs = handleRecv<PacketVersionResponseVar>();
    }
    else
    {
        // all other packets should have the "choosen version" in the header
        if (version != MessageVersion)
        {
            return RetStat::ERROR_INVALID_HEADER_VERSION;
        }
        switch (code)
        { // clang-format off
        // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
        #define DTYPE(type)                                                            \
            case type::requestResponseCode:                                            \
                rs = handleRecv<type>();                                               \
                break;
            DTYPE(PacketCapabilitiesResponse)
            DTYPE(PacketAlgorithmsResponseVar)
            DTYPE(PacketDigestsResponseVar)
            DTYPE(PacketCertificateResponseVar)
            DTYPE(PacketChallengeAuthResponseVar)
            DTYPE(PacketMeasurementsResponseVar)
            default:
                Log.iprint("!!! Unknown code: ");
                Log.println(code);
                return RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE;
        #undef DTYPE
        } // clang-format on
    }
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
    return rs;
}

[[nodiscard]] RetStat ConnectionClass::handleEvent(EventClass& event)
{
    if (auto e = event.getAs<EventReceiveClass>())
    {
        return handleRecv(*e);
    }
    if (auto e = event.getAs<EventTimeoutClass>())
    {
        return handleTimeout(*e);
    }
    return RetStat::ERROR_UNKNOWN;
}

RetStat ConnectionClass::handleTimeout(EventTimeoutClass& /*event*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    if (SendRetry)
    {
        --SendRetry;
        auto rs = context.getIO().write(SendBuffer);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

        rs = transport->setupTimeout(SendTimeout);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }
    WaitingForResponse = RequestResponseEnum::INVALID;
    return RetStat::ERROR_TIMEOUT;
}

void ConnectionClass::clearTimeout()
{
    if (transport)
    {
        transport->clearTimeout();
    }
    SendTimeout = 0;
    SendRetry = 0;
}

} // namespace spdmcpp

#undef SPDMCPP_CONNECTION_RS_ERROR_RETURN