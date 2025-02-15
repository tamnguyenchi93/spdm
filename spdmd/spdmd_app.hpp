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

#include "dbus_impl_responder.hpp"
#include "spdmcpp/common.hpp"
#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"
#include "spdmcpp/mctp_support.hpp"
#include "spdmd_app_context.hpp"
#include "utils.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>

#include <memory>
#include <unordered_map>

using namespace std;
using namespace spdmd;
using namespace spdmcpp;
using namespace sdbusplus;

namespace spdmd
{

class SpdmdApp : public SpdmdAppContext
{
  public:
    SpdmdApp(const SpdmdApp&) = delete;
    SpdmdApp(SpdmdApp&&) = delete;
    SpdmdApp& operator=(const SpdmdApp&) = delete;
    SpdmdApp& operator=(SpdmdApp&&) = delete;
    ~SpdmdApp() = default;

    /** @brief Constructs the SPDM daemon
     *
     */
    SpdmdApp();

    /** @brief Setup CLI for SPDM daemon
     *
     */
    void setupCli(int argc, char** argv);

    /** @brief Connect SPDM daemon to D-bus
     *
     */
    void connectDBus();

    /** @brief Connect SPDM daemon to MCTP
     *  @details Safe to call redundantly if necessary,
     * it'll create only one connection.
     */
    void connectMCTP(const std::string& sockPath);

    /** @brief Sets up the automatic measurement delay according to commandline
     * parameters
     */
    void setupMeasurementDelay();

    /** @brief Enter SPDM daemon into forever loop
     *
     */
    int loop();

    /** @brief Get reference to the used d-bus object
     *
     */
    sdbusplus::bus::bus& getBus()
    {
        return SpdmdAppContext::bus;
    }

    /** @brief Check the UUIDs in the existing disovery table responder
     * and create responder when UUID is not exist, or re-create responder
     * if the higher priority reponder is detected
     * @param respArgs Discovered response arguments
     *
     */
    void discoveryUpdateResponder(const dbus_api::ResponderArgs& respArg);

  private:
    /** @brief SPDMD callback signal called
     *
     */
    void mctpCallback(uint32_t revents, spdmcpp::MctpIoClass& mctpIo);

    /** @brief Create new Responder object
     *
     */
    void createResponder(const dbus_api::ResponderArgs& args);

    /** @brief When responder should be recreated
     *
     */
    static bool needRecreateResponder(spdmcpp::TransportMedium currMedium,
                                      spdmcpp::TransportMedium newMedium);

    /** @brief verbose - debug level for SPDM daemon */
    spdmcpp::LogClass::Level verbose = spdmcpp::LogClass::Level::Emergency;

    /** @brief Event handlar for MCTP events - used for transmission purposes
     * over MCTP */
    std::unordered_map<std::string, std::unique_ptr<sdeventplus::source::IO>>
        mctpEvents;

    /** @brief Array of all responder objects, managed by SPDM daemon */
    std::vector<std::unique_ptr<dbus_api::Responder>> responders;
    /** @brief Discovery responders by UUID map*/
    std::map<std::string, dbus_api::ResponderArgs> resp_discovery;

    /** @brief Buffer for packets received from responders over MCTP */
    std::vector<uint8_t> packetBuffer;

    /** @brief Timer for handling the measurement delay
     */
    std::unique_ptr<Timer> measurementDelayTimer;

    /** @brief Callback for the automatic measurement delay
     */
    void measurementDelayCallback();

    /** @brief checks if the given eid should be measured and issues a refresh
     *  @returns true if refresh was called, false otherwise
     */
    bool autoMeasure(uint8_t eid) const;
};

} // namespace spdmd
