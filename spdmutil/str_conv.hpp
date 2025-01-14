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

#include <spdmcpp/packet.hpp>

namespace spdmt
{
std::string verToString(const spdmcpp::PacketVersionNumber& ver);
std::string verToString(spdmcpp::MessageVersionEnum ver);
std::vector<std::string>
    capFlagsToStr(spdmcpp::ResponderCapabilitiesFlags flags);
std::string hashAlgoToStr(spdmcpp::BaseHashAlgoFlags flags);
std::string asymAlgoToStr(spdmcpp::BaseAsymAlgoFlags flags);
} // namespace spdmt