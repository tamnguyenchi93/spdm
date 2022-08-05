#pragma once

#include "config.h"

#include "spdmd_app_context.hpp"
#include "xyz/openbmc_project/Association/Definitions/server.hpp"
#include "xyz/openbmc_project/SPDM/Responder/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/mctp_support.hpp>

#include <map>
#include <memory>

namespace spdmd
{

namespace dbus_api
{

class Responder;

/** @class MctpTransportClass
 *  @brief Support class for transport through the mctp-demux-daemon with
 * timeouts handled by sdeventplus
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class MctpTransportClass : public spdmcpp::MctpTransportClass
{
  public:
    MctpTransportClass(uint8_t eid, Responder& resp) :
        spdmcpp::MctpTransportClass(eid), responder(resp)
    {}
    ~MctpTransportClass() override = default;

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_ms_t timeout) override;

    bool clearTimeout() override;

  protected:
    Responder& responder;
    std::unique_ptr<SpdmdAppContext::Timer> time;

    void timeoutCallback();
};

using ResponderIntf = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::SPDM::server::Responder,
    sdbusplus::xyz::openbmc_project::Association::server::Definitions>;

/** @class Responder
 *  @brief OpenBMC SPDM.Responder implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.SPDM.Responder DBus APIs.
 */
class Responder : public ResponderIntf
{
  public:
    Responder() = delete;
    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;
    Responder(Responder&&) = delete;
    Responder& operator=(Responder&&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] eid - MCTP EndpointID of the responder
     *  @param[in] inventoryPath - Used for the object-manager association
     */
    Responder(SpdmdAppContext& appCtx, const std::string& path, uint8_t eid,
              const sdbusplus::message::object_path& mctpPath,
              const sdbusplus::message::object_path& inventPath);

    ~Responder() override;

    void refresh(uint8_t slot, std::vector<uint8_t> nonc,
                 std::vector<uint8_t> measurementIndices,
                 uint32_t sessionId) override;

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    void refreshSerialNumber();
#endif

    spdmcpp::LogClass& getLog()
    {
        return log;
    }
    sdeventplus::Event& getEvent()
    {
        return appContext.event;
    }

    /** @brief Event callback for receiving events
     *  @param[inout] bus - Buffer containing the data, note that after the call
     * the contents of buf will be effectively clobbered
     */
    spdmcpp::RetStat handleEvent(
        spdmcpp::EventClass& event) // cppcheck-suppress constParameter
    {
        return (this->*eventHandler)(event);
    }

  protected:
    using MeasurementsContainerType =
        std::vector<std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>>;
    using CertificatesContainerType =
        std::vector<std::tuple<uint8_t, std::string>>;

    SpdmdAppContext& appContext;

    spdmcpp::LogClass log;
    spdmcpp::ConnectionClass connection;
    MctpTransportClass transport;
    sdbusplus::message::object_path inventoryPath;

    spdmcpp::RetStat (Responder::*eventHandler)(spdmcpp::EventClass& event) =
        nullptr;

    void updateVersionInfo();
    void updateAlgorithmsInfo();
    void updateCertificatesInfo();
    void updateLastUpdateTime();
    void syncSlotsInfo();

    void handleError(spdmcpp::RetStat rs);
    spdmcpp::RetStat handleEventForRefresh(spdmcpp::EventClass& event);
#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    spdmcpp::RetStat handleEventForSerialNumber(spdmcpp::EventClass& event);
#endif
};

} // namespace dbus_api
} // namespace spdmd
