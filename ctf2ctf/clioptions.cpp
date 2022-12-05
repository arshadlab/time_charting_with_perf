/*
  clioptions.cpp

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

#include "clioptions.h"

#include <iostream>

#include "args/args.hxx"

CliOptions parseCliOptions(int argc, char** argv)
{
    args::ArgumentParser parser("Convert binary LTTng/Common Trace Format trace data to JSON in Chrome Trace Format",
                                "The converted trace data in JSON format is written to stdout.");
    args::HelpFlag helpArg(parser, "help", "Display this help menu", {'h', "help"});
    args::ValueFlag<std::string> outputFileArg(parser, "path", "Write output to a file instead of stdout.",
                                               {'o', "output"});
    args::ValueFlagList<std::string> excludeArg(parser, "name substring", "Exclude events with this name",
                                                {'x', "exclude"});
    args::ValueFlagList<int64_t> pidWhitelistArg(parser, "pid", "Only show events for this process id",
                                                 {"pid-whitelist"});
    args::ValueFlagList<std::string> processWhitelistArg(parser, "process", "Only show events for this process",
                                                         {"process-whitelist"});
    args::ValueFlag<double> minTimeArg(parser, "ms", "skip events before this time", {"min-time"});
    args::ValueFlag<double> maxTimeArg(parser, "ms", "skip events after this time", {"max-time"});
    args::Flag printStatsArg(parser, "stats", "print statistics to stderr", {"print-stats"});
    args::Flag relativeTimestampsArg(parser, "relative-timestamps", "print timestamps relative to the first event",
                                     {"relative-timestamps"});
    args::Flag skipInstantEventsArg(parser, "skip-instant-events", "don't emit instant events (ph: i)",
                                    {"skip-instant-events"});
    args::Positional<std::filesystem::path> pathArg(
        parser, "path", "The path to an LTTng trace folder, will be searched recursively for trace data");
    try {
        parser.ParseCLI(argc, argv);
    } catch (const args::Help&) {
        std::cout << parser;
        exit(0);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl << parser;
        exit(1);
    }

    const auto path = args::get(pathArg);
    if (!std::filesystem::exists(path)) {
        std::cerr << "path does not exist: " << path << std::endl;
        exit(1);
    }

    auto toNs = [](double ms) { return static_cast<int64_t>(ms * 1E3); };

    return {
        args::get(outputFileArg),
        path,
        args::get(excludeArg),
        args::get(pidWhitelistArg),
        args::get(processWhitelistArg),
        toNs(args::get(minTimeArg)),
        toNs(args::get(maxTimeArg)),
        args::get(printStatsArg),
        args::get(relativeTimestampsArg),
        args::get(skipInstantEventsArg),
    };
}
