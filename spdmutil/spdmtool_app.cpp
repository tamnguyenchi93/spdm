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

#include <spdm_tool.hpp>

#include <iostream>

// Tool main looop
auto main(int argc, char** argv) -> int
{
    try
    {
        spdmt::SpdmTool app;
        // Parse arguments
        if (app.parseArgs(argc, argv))
        {
            return EXIT_FAILURE;
        }
        // Run application
        if (!app.run())
        {
            return EXIT_FAILURE;
        }
    }
    catch (const std::exception& exc)
    {
        std::cerr << "Unhandled exception " << exc.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
