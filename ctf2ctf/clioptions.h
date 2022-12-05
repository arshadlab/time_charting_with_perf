/*
  clioptions.h

  This file is part of ctf2ctf, a converter from LTTng/CTF to Chromium's Common Trace Format.

  Copyright (C) 2019 Klarälvdalens Datakonsult AB, a KDAB Group company, info@kdab.com
  Author: Milian Wolff <milian.wolff@kdab.com>

  Licensees holding valid commercial KDAB ctf2ctf licenses may use this file in
  accordance with ctf2ctf Commercial License Agreement provided with the Software.

  Contact info@kdab.com if any conditions of this licensing are not clear to you.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <filesystem>
#include <string>
#include <vector>

struct CliOptions
{
    std::string outputFile;
    std::filesystem::path path;
    std::vector<std::string> exclude;
    std::vector<int64_t> pidWhitelist;
    std::vector<std::string> processWhitelist;
    int64_t minTime = 0;
    int64_t maxTime = 0;
    bool enableStatistics = false;
    bool relativeTimestamps = false;
    bool skipInstantEvents = false;
};

CliOptions parseCliOptions(int argc, char** argv);
