/*
  ctf2ctf.cpp

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

#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/iterator.h>

#include <cassert>
#include <cmath>
#include <cstdio>
#include <stdio_ext.h>
#include <csignal>

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include "clioptions.h"

#include "config.h"

#if Qt5Gui_FOUND
#include <QEvent>
#include <QMetaEnum>
#include <QString>
#endif

namespace
{
volatile std::sig_atomic_t s_shutdownRequested = 0;

void shutdownGracefully(int sig)
{
    if (!s_shutdownRequested) {
        s_shutdownRequested = 1;
        return;
    }

    // re-raise signal with default handler and trigger program termination
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

void installSignalHandler()
{
#ifdef SIGHUP
    std::signal(SIGHUP, shutdownGracefully);
#endif
#ifdef SIGINT
    std::signal(SIGINT, shutdownGracefully);
#endif
#ifdef SIGTERM
    std::signal(SIGTERM, shutdownGracefully);
#endif
}

struct ErrorOutput
{
    std::ostream& out(std::string_view prefix, std::string_view file, int line)
    {
        if (m_lastWasProgress)
            std::cerr << '\n';
        m_lastWasProgress = false;
        return std::cerr << prefix << " (" << file << ':' << line << "): ";
    }

    std::ostream& progress()
    {
        if (m_lastWasProgress)
            return std::cerr << '\r';

        m_lastWasProgress = true;
        return std::cerr;
    }

    static ErrorOutput& self()
    {
        static ErrorOutput out;
        return out;
    }

private:
    bool m_lastWasProgress = false;
};

struct EndWithNewline
{
    EndWithNewline(std::ostream &out)
        : out(out)
    {}
    ~EndWithNewline()
    {
        out << '\n';
    }
    template<typename T>
    std::ostream &operator<<(T&& arg)
    {
        return out << arg;
    }
    std::ostream &out;
};

#define ERROR() EndWithNewline(ErrorOutput::self().out("ERROR", __FILE__, __LINE__))
#define WARNING() EndWithNewline(ErrorOutput::self().out("WARNING", __FILE__, __LINE__))
#define DEBUG() EndWithNewline(ErrorOutput::self().out("DEBUG", __FILE__, __LINE__))
#define PROGRESS() ErrorOutput::self().progress()

// cf. lttng-modules/instrumentation/events/lttng-module/block.h
std::string rwbsToString(uint64_t rwbs)
{
    std::string ret;
    auto check = [&ret, rwbs](std::string_view name, uint16_t flag) {
        if (rwbs & (1 << flag)) {
            if (!ret.empty())
                ret += ", ";
            ret += name;
        }
    };
    check("write", 0);
    check("discard", 1);
    check("read", 2);
    check("rahead", 3);
    check("barrier", 4);
    check("sync", 5);
    check("meta", 6);
    check("secure", 7);
    check("flush", 8);
    check("fua", 9);
    check("preflush", 10);
    return ret;
}

constexpr auto TIMESTAMP_PRECISION = std::numeric_limits<double>::max_digits10;

template<typename Callback>
void findMetadataFiles(const std::filesystem::path& path, Callback&& callback)
{
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
        if (entry.is_regular_file() && entry.path().filename() == "metadata")
            callback(entry.path().parent_path().c_str());
    }
}

template<typename T, typename Cleanup>
auto wrap(T* value, Cleanup cleanup)
{
    return std::unique_ptr<T, Cleanup>(value, cleanup);
}

template<typename Reader>
auto get(const bt_ctf_event* event, const bt_definition* scope, const char* name, Reader reader)
{
    auto definition = bt_ctf_get_field(event, scope, name);
    auto ret = std::optional<std::invoke_result_t<Reader, decltype(definition)>>();
    if (definition)
        ret = std::make_optional(reader(definition));
    return ret;
}

auto get_uint64(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_uint64);
}

auto get_int64(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_int64);
}

auto get_char_array(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_char_array);
}

auto get_string(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_string);
}

auto get_float(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_float);
}

bool startsWith(std::string_view string, std::string_view prefix)
{
    return string.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), string.begin());
}

bool endsWith(std::string_view string, std::string_view suffix)
{
    return string.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), string.rbegin());
}

bool removeSuffix(std::string& name, std::string_view suffix)
{
    if (!endsWith(name, suffix))
        return false;
    name.resize(name.size() - suffix.length());
    return true;
}

template<typename List, typename Needle>
bool contains(List&& list, const Needle& needle)
{
    return std::find(list.begin(), list.end(), needle) != list.end();
}

template<typename T1, typename T2>
bool contains(const std::initializer_list<T1>& list, const T2& needle)
{
    return std::find(begin(list), end(list), needle) != end(list);
}

template<typename Whitelist, typename Needle>
bool isWhitelisted(const Whitelist& whitelist, const Needle& needle)
{
    return whitelist.empty() || contains(whitelist, needle);
}

template<typename T>
auto findMmapAt(T&& mmaps, uint64_t addr)
{
    for (auto it = mmaps.begin(), end = mmaps.end(); it != end; ++it) {
        if (it->addr > addr)
            break;
        if (it->addr <= addr && addr < (it->addr + it->len))
            return it;
    }
    return mmaps.end();
}

struct KMemAlloc
{
    uint64_t requested = 0;
    uint64_t allocated = 0;
};

KMemAlloc operator+(const KMemAlloc& lhs, const KMemAlloc& rhs)
{
    return {lhs.requested + rhs.requested, lhs.allocated + rhs.allocated};
}

KMemAlloc operator-(const KMemAlloc& lhs, const KMemAlloc& rhs)
{
    return {lhs.requested - rhs.requested, lhs.allocated - rhs.allocated};
}

KMemAlloc& operator+=(KMemAlloc& lhs, const KMemAlloc& rhs)
{
    lhs = lhs + rhs;
    return lhs;
}

KMemAlloc& operator-=(KMemAlloc& lhs, const KMemAlloc& rhs)
{
    lhs = lhs - rhs;
    return lhs;
}

std::string commName(std::string_view comm, int64_t tid)
{
    std::string ret;
    ret += comm;
    ret += " (";
    ret += std::to_string(tid);
    ret += ")";
    return ret;
}

enum class ArgsType
{
    Object,
    Array,
    Event,
};

enum class IntegerArgFormatFlag
{
    Decimal,
    Hexadecimal
};

enum class ArgError
{
    UnknownType,
    UnknownSignedness,
    UnhandledArrayType,
    UnhandledType,
};

using Arg = std::variant<int64_t, uint64_t, double, std::string_view, char, ArgError>;

class JsonArgsPrinter
{
public:
    const std::string_view label;
    const ArgsType type = ArgsType::Object;

    JsonArgsPrinter(ArgsType type, std::string_view label, FILE* out, JsonArgsPrinter* parent)
        : label(label)
        , type(type)
        , out(out)
        , parent(parent)
    {
    }

    ~JsonArgsPrinter()
    {
        if (!firstField) {
            switch (type) {
            case ArgsType::Event:
            case ArgsType::Object:
                fprintf(out, "}");
                break;
            case ArgsType::Array:
                fprintf(out, "]");
                break;
            }
        }
    }

    template<typename T, typename... FormatArgs>
    void writeField(std::string_view field, T value, FormatArgs... formatArgs)
    {
        newField(field);
        writeValue(value, formatArgs...);
    }

    JsonArgsPrinter argsPrinter(ArgsType type, std::string_view label)
    {
        assert(type != ArgsType::Event);
        return {type, label, out, this};
    }

private:
    void newField(std::string_view field)
    {
        if (firstField) {
            firstField = false;

            if (parent)
                parent->newField(label);

            switch (type) {
            case ArgsType::Event:
            case ArgsType::Object:
                fprintf(out, "{");
                break;
            case ArgsType::Array:
                fprintf(out, "[");
                break;
            }
        } else {
            fprintf(out, ", ");
        }

        if (type == ArgsType::Array)
            return;

        writeValue(field);
        fprintf(out, ": ");
    }

    void writeValue(int64_t value, int base = 10)
    {
        switch (base) {
        case 8:
            if (value < 0)
                fprintf(out, "\"-0o%lo\"", -static_cast<uint64_t>(value));
            else
                fprintf(out, "\"0o%lo\"", static_cast<uint64_t>(value));
            break;
        case 16:
            if (value < 0)
                fprintf(out, "\"-0x%lx\"", -static_cast<uint64_t>(value));
            else
                fprintf(out, "\"0x%lx\"", static_cast<uint64_t>(value));
            break;
        default:
            WARNING() << "unhandled integer base: " << base;
            [[fallthrough]];
        case 10:
            fprintf(out, "%ld", value);
            break;
        }
    }

    void writeValue(double value)
    {
        fprintf(out, "%.*g", TIMESTAMP_PRECISION, value);
    }

    void writeValue(uint64_t value, int base = 10)
    {
        switch (base) {
        case 8:
            fprintf(out, "\"0o%lo\"", value);
            break;
        case 16:
            fprintf(out, "\"0x%lx\"", value);
            break;
        default:
            WARNING() << "unhandled integer base: " << base;
            [[fallthrough]];
        case 10:
            fprintf(out, "%lu", value);
            break;
        }
    }

    void writeValue(std::string_view string)
    {
        putc('"', out);
        for (auto c : string) {
            if (c == '\n') {
                fputs("\\n", out);
                continue;
            } else if (c == '\r') {
                fputs("\\r", out);
                continue;
            }
            if ((c >= 0 && c <= 0x1F) || c == '"' || c == '\\')
                putc('\\', out);
            putc(c, out);
        }
        putc('"', out);
    }

    void writeValue(ArgError error, int64_t arg)
    {
        switch (error) {
        case ArgError::UnknownType:
            fputs(R"("<unknown type>")", out);
            break;
        case ArgError::UnknownSignedness:
            fputs(R"("<unknown signedness>")", out);
            break;
        case ArgError::UnhandledArrayType:
            fprintf(out, R"("<unhandled array type %ld>")", arg);
            break;
        case ArgError::UnhandledType:
            fprintf(out, R"("<unhandled type %ld>")", arg);
            break;
        }
    }

    void writeValue(char c)
    {
        fprintf(out, "\"%c\"", c);
    }

    void writeValue(const Arg& arg)
    {
        std::visit([this](auto arg) { writeValue(arg); }, arg);
    }

    FILE* out = nullptr;
    JsonArgsPrinter* parent = nullptr;
    bool firstField = true;
};

class JsonPrinter
{
public:
    JsonPrinter(const std::string& output)
    {
        if (output.empty() || output == "-")
            return;

        if (output == "stderr") {
            out = stderr;
            return;
        }

        if (auto fd = fopen(output.c_str(), "w"))
            out = fd;
        else
            ERROR() << "failed to open " << output << ": " << strerror(errno);
    }

    ~JsonPrinter()
    {
        if (!firstEvent)
            writeSuffix();
        if (out != stderr && out != stdout)
            fclose(out);
        else
            fflush(out);
    }

    JsonArgsPrinter eventPrinter()
    {
        if (firstEvent) {
            firstEvent = false;
            writePrefix();
        } else {
            fprintf(out, ",");
        }

        fprintf(out, "\n    ");

        return {ArgsType::Event, {}, out, nullptr};
    }

private:
    void writePrefix()
    {
        fprintf(out, "{\n  \"traceEvents\": [");
    }

    void writeSuffix()
    {
        fprintf(out, "\n  ]\n}\n");
    }

    FILE* out = stdout;
    bool firstEvent = true;
};

struct Event;
struct Context
{
    static constexpr const uint64_t PAGE_SIZE = 4096;

    bool reportedBrokenTracefString = false;
    JsonPrinter printer;
    CliOptions options;

    Context(CliOptions options)
        : printer(options.outputFile)
        , options(std::move(options))
    {
        cores.reserve(32);
        pids.reserve(1024);
        tids.reserve(1024);
        irqs.reserve(32);
        blockDevices.reserve(32);
    }

    double toMs(int64_t timestamp)
    {
        if (options.relativeTimestamps) {
            if (isFilteredByTime(timestamp)) {
                timestamp = 0;
            } else if (!firstTimestamp) {
                firstTimestamp = timestamp;
                timestamp = 0;
            } else {
                timestamp -= firstTimestamp;
            }
        }

        const auto ms = timestamp / 1000;
        const auto ns = timestamp % 1000;
        return static_cast<double>(ms) + static_cast<double>(ns) * 1E-3;
    }

    int64_t tid(uint64_t cpuId) const
    {
        if (cores.size() <= cpuId)
            return INVALID_TID;
        return cores[cpuId].tid;
    }

    int64_t pid(int64_t tid) const
    {
        auto it = tids.find(tid);
        return it == tids.end() ? INVALID_TID : it->second.pid;
    }

    void setTid(uint64_t cpuId, int64_t tid)
    {
        if (cores.size() <= cpuId)
            cores.resize(cpuId + 1);
        cores[cpuId].tid = tid;
    }

    void setPid(int64_t tid, int64_t pid)
    {
        tids[tid].pid = pid;
    }

    void setOpenAtFilename(int64_t tid, std::string_view filename)
    {
        tids[tid].openAtFilename = filename;
    }

    void setOpenAtFd(int64_t pid, int64_t tid, int64_t fd)
    {
        pids[pid].fdToFilename[fd] = std::move(tids[tid].openAtFilename);
    }

    void setFdFilename(int64_t pid, int64_t fd, std::string_view filename)
    {
        pids[pid].fdToFilename[fd] = filename;
    }

    void closeFd(int64_t pid, int64_t fd)
    {
        auto& fds = pids[pid].fdToFilename;
        auto it = fds.find(fd);
        if (it != fds.end())
            fds.erase(it);
    }

    std::string_view fdToFilename(int64_t pid, int64_t fd) const
    {
        std::string_view filename = "??";
        if (fd == 0)
            filename = "stdin";
        else if (fd == 1)
            filename = "stdout";
        else if (fd == 2)
            filename = "stderr";

        auto pid_it = pids.find(pid);
        if (pid_it == pids.end())
            return filename;
        const auto& fds = pid_it->second.fdToFilename;
        auto fd_it = fds.find(fd);
        if (fd_it == fds.end())
            return filename;
        filename = fd_it->second;
        return filename;
    }

    void setIrqName(uint64_t irq, std::string_view name, std::string_view action)
    {
        irqs[irq] = {std::string(name), std::string(action)};
    }

    struct IrqDataView
    {
        std::string_view name;
        std::string_view action;
    };
    IrqDataView irq(uint64_t irq) const
    {
        auto it = irqs.find(irq);
        if (it == irqs.end())
            return {};
        return {it->second.name, it->second.action};
    }

    void setBlockDeviceName(uint64_t device, std::string_view name)
    {
        blockDevices[device].name = name;
    }

    std::string_view blockDeviceName(uint64_t device) const
    {
        auto it = blockDevices.find(device);
        if (it == blockDevices.end())
            return "??";
        return it->second.name;
    }

    void mmap(int64_t pid, uint64_t addr, uint64_t len, std::string_view file, int64_t fd)
    {
        auto& mmaps = pids[pid].mmaps;
        auto it =
            std::lower_bound(mmaps.begin(), mmaps.end(), addr, [](auto map, auto addr) { return map.addr < addr; });
        mmaps.insert(it, {addr, len, std::string(file), fd});
    }

    void mmapEntry(int64_t tid, uint64_t len, int64_t fd)
    {
        tids[tid].mmapEntry = {len, fd};
    }

    void mmapExit(int64_t pid, int64_t tid, uint64_t addr, int64_t timestamp)
    {
        auto& entry = tids[tid].mmapEntry;
        if (addr && entry.len) {
            mmap(pid, addr, entry.len, fdToFilename(pid, entry.fd), entry.fd);
            anonMmapped(pid, timestamp, entry.fd, entry.len, true);
        }
        entry = {};
    }

    void munmap(int64_t pid, uint64_t addr, uint64_t len, int64_t timestamp)
    {
        auto& mmaps = pids[pid].mmaps;
        auto it = findMmapAt(mmaps, addr);
        if (it == mmaps.end())
            return;

        anonMmapped(pid, timestamp, it->fd, len, false);

        if (it->addr == addr && it->len == len) {
            mmaps.erase(it);
            return;
        } else if (it->addr == addr) {
            it->addr += len;
        } else if (it->addr + len == addr + len) {
            it->len -= len;
        } else {
            // split up
            const auto trailing = it->addr + it->len - addr - len;
            it->len = (addr - it->addr);
            mmaps.insert(it + 1, {addr + len, trailing, it->file, it->fd});
        }
    }

    std::string_view fileMmappedAt(int64_t pid, uint64_t addr) const
    {
        auto pid_it = pids.find(pid);
        if (pid_it == pids.end())
            return "??";

        const auto& mmaps = pid_it->second.mmaps;
        auto it = findMmapAt(mmaps, addr);
        if (it == mmaps.end())
            return "??";
        return it->file;
    }

    void fork(int64_t parentPid, int64_t childPid)
    {
        // follow children by default
        if (options.processWhitelist.empty())
            return;
        if (!contains(options.pidWhitelist, parentPid) || contains(options.pidWhitelist, childPid))
            return;
        options.pidWhitelist.push_back(childPid);
    }

    void threadExit(int64_t tid, int64_t pid, int64_t timestamp)
    {
        if (tid == pid) {
            auto pid_it = pids.find(pid);
            if (pid_it != pids.end()) {
                if (pid_it->second.anonMmapped > 0) {
                    // reset counters to zero to ensure the graph expands the full width of process lifetime
                    printCounterValue("anon mmapped", timestamp, pid, int64_t(0));
                }
                pids.erase(pid_it);
            }
        }

        if (auto tid_it = tids.find(tid); tid_it != tids.end())
            tids.erase(tids.find(tid));
    }

    void pageFault(int64_t pid, int64_t timestamp)
    {
        auto& pageFaults = pids[pid].pageFaults;
        pageFaults++;
        printCounterValue("page faults", timestamp, pid, pageFaults);
    }

    void printName(int64_t tid, int64_t pid, std::string_view name, int64_t timestamp)
    {
        if (tid == pid) {
            bool whiteListedPid = contains(options.pidWhitelist, pid);
            if (isFilteredByProcessName(name) && !whiteListedPid)
                return;

            if (!options.processWhitelist.empty() && !whiteListedPid)
                options.pidWhitelist.push_back(pid); // add pid to filer to exclude events
        }

        if (isFilteredByPid(pid))
            return;

        auto getName = [this](int64_t id) -> std::string& {
            auto it = tids.find(id);
            if (it == tids.end())
                it = tids.insert(it, {id, {}});
            return it->second.name;
        };

        auto printName = [this, tid, pid, name, timestamp](const char* type) {
            printEvent(type, 'M', timestamp, pid, tid, {}, {{"name", name}});
        };

        if (pid != INVALID_TID) {
            auto& pidName = getName(pid);
            if (pidName.empty() || (tid == pid && pidName != name)) {
                if (pidName.empty()) {
                    printEvent("process_sort_index", 'M', timestamp, pid, pid, {}, {{"sort_index", pid}});
                }
                pidName = name;
                printName("process_name");
                if (tid == pid) {
                    // always update main thread name when we update the process name
                    printName("thread_name");
                    return;
                }
            }
        }
        if (tid != INVALID_TID) {
            auto& tidName = getName(tid);
            if (tidName != name) {
                tidName = name;
                printName("thread_name");
            }
        }
    }

    void parseEvent(bt_ctf_event* event);
    void handleEvent(const Event& event);
    void drainHeldBackEvents(std::vector<Event>& heldBackEvents_forCpu);
    void drainHeldBackEvents();

    enum KMemType
    {
        KMalloc,
        CacheAlloc,
    };
    void alloc(uint64_t ptr, const KMemAlloc& alloc, int64_t timestamp, KMemType type)
    {
        auto& hash = type == KMalloc ? kmem : kmemCached;
        auto& current = type == KMalloc ? currentAlloc : currentCached;
        hash[ptr] = alloc;
        current += alloc;
        printCount(type, timestamp);
    }

    void free(uint64_t ptr, int64_t timestamp, KMemType type)
    {
        auto& hash = type == KMalloc ? kmem : kmemCached;
        auto& current = type == KMalloc ? currentAlloc : currentCached;
        current -= hash[ptr];
        printCount(type, timestamp);
    }

    void pageAlloc(uint32_t order, int64_t timestamp)
    {
        currentKmemPages += pow(2, order);
        printCount(CounterGroup::Memory, "mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    void pageFree(uint32_t order, int64_t timestamp)
    {
        currentKmemPages -= pow(2, order);
        printCount(CounterGroup::Memory, "mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    // swapper is the idle process on linux
    static const constexpr int64_t SWAPPER_TID = 0;

    void schedSwitch(int64_t prevTid, int64_t prevPid, std::string_view prevComm, int64_t nextTid, int64_t nextPid,
                     std::string_view nextComm, uint64_t cpuId, int64_t timestamp)
    {
        if (prevTid == nextTid || isFilteredByTime(timestamp))
            return;

        if (cores.size() <= cpuId)
            cores.resize(cpuId);

        auto& core = cores[cpuId];

        const bool wasRunning = core.running;
        const bool isRunning = nextTid != SWAPPER_TID;
        if (wasRunning != isRunning) {
            const auto numRunning = std::count_if(cores.begin(), cores.end(), [](auto core) { return core.running; });
            printCount(CounterGroup::CPU, "CPU utilization", numRunning, timestamp);
            core.running = isRunning;
        }

        const auto group = dataFor(CounterGroup::CPU, timestamp);
        const auto eventTid = CPU_PROCESS_TID_MULTIPLICATOR * static_cast<int64_t>(cpuId + 1);
        if (!core.printedCpuStateName) {
            printEvent("thread_name", 'M', timestamp, group.id, eventTid, {},
                       {{"name", "CPU " + std::to_string(cpuId) + " state"}});
            core.printedCpuStateName = true;
        }

        auto printCpuCoreProcessEvent = [this, eventTid, timestamp, group](int64_t tid, char type) {
            if (tid == SWAPPER_TID)
                return;

            if (isFilteredByPid(pid(tid)))
                return;

            printEvent(commName(tids[tid].name, tid), type, timestamp, group.id, eventTid, "process");
        };
        printCpuCoreProcessEvent(prevTid, 'E');
        printCpuCoreProcessEvent(nextTid, 'B');

        // TODO: look into flow events?
        if (!isFilteredByPid(prevPid)) {
            auto event = eventPrinter("sched_switch", 'B', timestamp, prevPid, prevTid, "sched");
            auto args = event.argsPrinter(ArgsType::Object, "args");
            auto out = args.argsPrinter(ArgsType::Object, "out");
            out.writeField("next_comm", nextComm);
            out.writeField("next_pid", nextPid);
            out.writeField("next_tid", nextTid);
        }
        if (!isFilteredByPid(nextPid)) {
            auto event = eventPrinter("sched_switch", 'E', timestamp, nextPid, nextTid, "sched");
            auto args = event.argsPrinter(ArgsType::Object, "args");
            auto out = args.argsPrinter(ArgsType::Object, "in");
            out.writeField("prev_comm", prevComm);
            out.writeField("prev_pid", prevPid);
            out.writeField("prev_tid", prevTid);
        }
    }

    void cpuFrequency(uint64_t cpuId, uint64_t frequency, int64_t timestamp)
    {
        printCount(CounterGroup::CPU, "CPU " + std::to_string(cpuId) + " frequency", frequency, timestamp);
    }

    void cpuUsage(const std::string& label, double usage, int64_t timestamp)
    {
        printCount(CounterGroup::CPU, label + " usage", usage, timestamp);
    }

    void blockRqIssue(uint64_t dev, uint64_t sector, uint64_t nr_sector, uint64_t bytes, uint64_t rwbs, int64_t tid,
                      std::string_view comm, int64_t timestamp)
    {
        if (isFilteredByTime(timestamp))
            return;

        const auto pid = this->pid(tid);
        if (isFilteredByPid(pid))
            return;

        auto device_it = blockDevices.find(dev);
        if (device_it == blockDevices.end())
            return;
        auto& device = device_it->second;

        const auto group = dataFor(CounterGroup::Block, timestamp);
        const auto eventTid = BLOCK_TID_OFFFSET - dev;
        if (!device.printedDeviceName) {
            printEvent("thread_name", 'M', timestamp, group.id, eventTid, {}, {{"name", device.name + " requests"}});
            device.printedDeviceName = true;
        }

        device.bytesPending += bytes;
        device.requests[sector] = {bytes, std::string(comm), tid};
        printCount(CounterGroup::Block, device.name + " bytes pending", device.bytesPending, timestamp);

        printEvent(commName(comm, tid), 'B', timestamp, group.id, eventTid, "block",
                   {{"sector", sector}, {"nr_sector", nr_sector}, {"bytes", bytes}, {"rwbs", rwbsToString(rwbs)}});

        auto& pidData = pids[pid];
        pidData.blockIoBytesPending += bytes;
        printCounterValue("block I/O bytes pending", timestamp, pid, pidData.blockIoBytesPending);
    }

    void blockRqRequeue(uint64_t dev, uint64_t sector, int64_t timestamp)
    {
        finishBlockRequest(
            dev, sector, timestamp, [this](const auto& comm, auto tid, auto groupId, auto eventTid, auto timestamp) {
                printEvent(commName(comm, tid), 'E', timestamp, groupId, eventTid, "block", {{"error", "requeue"}});
            });
    }

    void blockRqComplete(uint64_t dev, uint64_t sector, int64_t error, int64_t timestamp)
    {
        finishBlockRequest(
            dev, sector, timestamp,
            [error, this](const auto& comm, auto tid, auto groupId, auto eventTid, auto timestamp) {
                printEvent(commName(comm, tid), 'E', timestamp, groupId, eventTid, "block", {{"error", error}});
            });
    }

    bool isFiltered(std::string_view name) const
    {
        return std::any_of(options.exclude.begin(), options.exclude.end(),
                           [name](const auto& pattern) { return name.find(pattern) != name.npos; });
    }

    bool isFilteredByPid(int64_t pid) const
    {
        return !isWhitelisted(options.pidWhitelist, pid)
            // when the process name filter wasn't applied yet, filter all pids
            || (options.pidWhitelist.empty() && !options.processWhitelist.empty());
    }

    bool isFilteredByProcessName(std::string_view name) const
    {
        return !isWhitelisted(options.processWhitelist, name);
    }

    bool isFilteredByTime(int64_t timestamp) const
    {
        if (options.minTime && timestamp < options.minTime)
            return true;
        if (options.maxTime && timestamp > options.maxTime)
            return true;
        return false;
    }

    bool isFilteredByType(char type) const
    {
        return options.skipInstantEvents && type == 'i';
    }

    void printStats(std::ostream& out) const
    {
        if (!options.enableStatistics)
            return;

        out << "\n\nTrace Data Statistics:\n\n";

        auto printSortedStats = [&out](const auto& stats) {
            auto sortedStats = stats;
            std::sort(sortedStats.begin(), sortedStats.end(),
                      [](const auto& lhs, const auto& rhs) { return lhs.counter < rhs.counter; });
            for (const auto& entry : sortedStats)
                out << std::setw(16) << entry.counter << '\t' << entry.name << '\n';
        };

        out << "Event Stats:\n";
        printSortedStats(eventStats);

        out << "\nEvent Category Stats:\n";
        printSortedStats(categoryStats);
    }

    int64_t generateTidForString(const std::string& string, int64_t timestamp, int64_t pid = -1)
    {
        assert(customTidMapping.size() == tids.size());
        auto& tid = customTidMapping[string];
        if (tid == 0) {
            // newly added string, create new mapping
            tid = customTidMapping.size();
            if (pid == -1)
                pid = tid;
            printName(tid, pid, string, timestamp);
        }
        return tid;
    }

    void printCounterValue(std::string_view name, int64_t timestamp, int64_t pid, Arg value)
    {
        printEvent(name, 'C', timestamp, pid, pid, {}, {{"value", value}});
    }

    enum SpecialIds
    {
        INVALID_TID = -1,
        CPU_COUNTER_PID = -2,
        MEMORY_COUNTER_PID = -3,
        BLOCK_COUNTER_PID = -4,
        // cpu id * multiplicator gives us a thread id for per-core events
        CPU_PROCESS_TID_MULTIPLICATOR = -100,
        // offset - block device id gives us a thread id for per-block events
        BLOCK_TID_OFFFSET = -2000,
    };

private:
    template<typename PrintEventCallback>
    void finishBlockRequest(uint64_t dev, uint64_t sector, int64_t timestamp, PrintEventCallback&& callback)
    {
        auto device_it = blockDevices.find(dev);
        if (device_it == blockDevices.end())
            return;
        auto& device = device_it->second;

        auto it = device.requests.find(sector);
        if (it == device.requests.end())
            return;

        const auto& bytes = it->second.bytes;
        const auto& comm = it->second.comm;
        const auto tid = it->second.tid;

        device.bytesPending -= bytes;

        printCount(CounterGroup::Block, device.name, device.bytesPending, timestamp);
        const auto group = dataFor(CounterGroup::Block, timestamp);
        const auto eventTid = BLOCK_TID_OFFFSET - dev;
        callback(comm, tid, group.id, eventTid, timestamp);

        const auto pid = this->pid(tid);
        auto& pidData = pids[pid];
        pidData.blockIoBytesPending -= bytes;
        printCounterValue("block I/O bytes pending", timestamp, pid, pidData.blockIoBytesPending);

        device.requests.erase(it);
    }

    void anonMmapped(int64_t pid, int64_t timestamp, int64_t fd, uint64_t len, bool add)
    {
        if (fd != -1 || isFilteredByPid(pid) || isFilteredByTime(timestamp))
            return;

        auto& anonMmapped = pids[pid].anonMmapped;
        if (add)
            anonMmapped += len;
        else
            anonMmapped -= len;

        printCounterValue("anon mmapped", timestamp, pid, anonMmapped);
    }
    void count(std::string_view name, std::string_view category)
    {
        if (!options.enableStatistics)
            return;

        auto count = [](auto& stats, auto name) {
            auto it = std::lower_bound(stats.begin(), stats.end(), name,
                                       [](const auto& entry, const auto& name) { return entry.name < name; });
            if (it == stats.end() || it->name != name)
                it = stats.insert(it, {std::string(name)});
            it->counter++;
        };
        count(eventStats, name);
        count(categoryStats, category.empty() ? "uncategorized" : category);
    }

    void printCount(KMemType type, int64_t timestamp)
    {
        const auto& current = type == KMalloc ? currentAlloc : currentCached;
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_requested" : "kmem_cache_alloc_requested",
                   current.requested, timestamp);
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_allocated" : "kmem_cache_alloc_allocated",
                   current.allocated, timestamp);
    }

    enum class CounterGroup
    {
        CPU,
        Memory,
        Block,
        NUM_COUNTER_GROUP
    };
    struct GroupData
    {
        const char* const name;
        const int64_t id;
        bool namePrinted;
    };
    GroupData dataFor(CounterGroup counterGroup, int64_t timestamp)
    {
        static GroupData groups[] = {
            {"CPU statistics", CPU_COUNTER_PID, false},
            {"Memory statistics", MEMORY_COUNTER_PID, false},
            {"Block I/O statistics", BLOCK_COUNTER_PID, false},
        };
        static_assert(std::size(groups) == static_cast<std::size_t>(CounterGroup::NUM_COUNTER_GROUP));
        assert(counterGroup < NUM_COUNTER_GROUP);
        const auto groupIndex = static_cast<std::underlying_type_t<CounterGroup>>(counterGroup);
        auto& group = groups[groupIndex];
        if (!group.namePrinted) {
            printEvent("process_sort_index", 'M', timestamp, group.id, group.id, {}, {{"sort_index", group.id}});
            printEvent("process_name", 'M', timestamp, group.id, group.id, {}, {{"name", group.name}});
            group.namePrinted = true;
        }
        return group;
    }
    void printCount(CounterGroup counterGroup, std::string_view name, Arg value, int64_t timestamp)
    {
        if (isFiltered(name) || isFilteredByTime(timestamp))
            return;

        const auto group = dataFor(counterGroup, timestamp);
        count(name, group.name);

        printCounterValue(name, timestamp, group.id, value);
    }

    JsonArgsPrinter eventPrinter(std::string_view name, char type, int64_t timestamp, int64_t pid, int64_t tid,
                                 std::string_view category = {})
    {
        JsonArgsPrinter eventPrinter = printer.eventPrinter();
        eventPrinter.writeField("name", name);
        eventPrinter.writeField("ph", type);
        eventPrinter.writeField("ts", toMs(timestamp));
        eventPrinter.writeField("pid", pid);
        eventPrinter.writeField("tid", tid);
        if (!category.empty())
            eventPrinter.writeField("cat", category);
        return eventPrinter;
    }

    void printEvent(std::string_view name, char type, int64_t timestamp, int64_t pid, int64_t tid,
                    std::string_view category = {}, std::initializer_list<std::pair<std::string_view, Arg>> args = {})
    {
        auto eventP = eventPrinter(name, type, timestamp, pid, tid, category);
        if (args.size()) {
            auto argsP = eventP.argsPrinter(ArgsType::Object, "args");
            for (const auto& arg : args)
                argsP.writeField(arg.first, arg.second);
        }
    }

    struct CoreData
    {
        // currently running thread id
        int64_t tid = INVALID_TID;
        // true if core is currently running a non-idle process
        bool running = false;
        // true if we printed the name for the 'CPU State' thread
        bool printedCpuStateName = false;
    };
    std::vector<CoreData> cores;
    struct TidData
    {
        int64_t pid = INVALID_TID;
        std::string name;
        std::string openAtFilename;
        struct MMapEntry
        {
            uint64_t len = 0;
            int64_t fd = -1;
        };
        MMapEntry mmapEntry;
    };
    std::unordered_map<int64_t, TidData> tids;
    struct MMap
    {
        uint64_t addr = 0;
        uint64_t len = 0;
        std::string file;
        int64_t fd = -1;
    };
    struct PidData
    {
        std::unordered_map<int64_t, std::string> fdToFilename;
        std::vector<MMap> mmaps;
        uint64_t anonMmapped = 0;
        uint64_t pageFaults = 0;
        uint64_t blockIoBytesPending = 0;
    };
    std::unordered_map<int64_t, PidData> pids;
    std::unordered_map<std::string, int64_t> customTidMapping;
    struct IrqData
    {
        std::string name;
        std::string action;
    };
    std::unordered_map<uint64_t, IrqData> irqs;
    struct BlockDeviceData
    {
        std::string name;
        struct RequestData
        {
            uint64_t bytes;
            std::string comm;
            int64_t tid;
        };
        uint64_t bytesPending = 0;
        std::unordered_map<uint64_t, RequestData> requests;
        bool printedDeviceName = false;
    };
    std::unordered_map<uint64_t, BlockDeviceData> blockDevices;
    std::unordered_map<uint64_t, KMemAlloc> kmem;
    std::unordered_map<uint64_t, KMemAlloc> kmemCached;
    KMemAlloc currentAlloc;
    KMemAlloc currentCached;
    std::unordered_map<uint64_t, uint64_t> kmemPages;
    uint64_t currentKmemPages = 0;
    struct EventStats
    {
        std::string name;
        uint64_t counter = 0;
    };
    std::vector<EventStats> eventStats;
    struct CategoryStats
    {
        std::string name;
        uint64_t counter = 0;
    };
    std::vector<CategoryStats> categoryStats;
    int64_t firstTimestamp = 0;
    int64_t firstProgressTimestamp = 0;
    int64_t lastProgressTimestamp = 0;
    /**
     * Sadly, on some (non-x86?) systems the lttng-ust trace points lead to
     * a lot of syscall event spam - every lttng-ust event is preceded by a
     * syscall_getcpu_{entry,exit} and a syscall_clock_gettime_entry and then
     * followed by a syscall_clock_gettime_exit. This leads to overly large
     * data files and additionally breaks the UST trace points, as they
     * are each sandwiched between a begin/end, which makes it impossible to
     * use them to build their own begin/end pairs.
     */
    struct LttngUstCleanupData
    {
        std::vector<Event> heldBackEvents;
        bool ignoreNextClockGettime = false;
    };
    std::unordered_map<uint64_t, LttngUstCleanupData> ustCleanup;
};

struct Event
{
    Event(bt_ctf_event* event, Context* context)
        : ctf_event(event)
        , event_fields_scope(bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS))
        , name(bt_ctf_event_name(event))
        , timestamp(bt_ctf_get_timestamp(event))
        , isFilteredByTime(context->isFilteredByTime(timestamp))
    {
        auto stream_packet_context_scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
        if (!stream_packet_context_scope)
            WARNING() << "failed to get stream packet context scope";

        const auto rawCpuId = get_uint64(event, stream_packet_context_scope, "cpu_id");
        if (!rawCpuId) {
            parseNonLttngEvent(context);
            return;
        }

        cpuId = rawCpuId.value();

        tid = context->tid(cpuId);
        pid = context->pid(tid);

        if (!event_fields_scope) {
            WARNING() << "failed to get event fields scope";
            return;
        }

        auto rewriteName = [this](std::string& name, std::string_view needle, std::string_view replacement,
                                  bool atStart) {
            const auto pos = atStart ? 0 : name.find(needle);

            if (atStart && !startsWith(name, needle))
                return false;
            else if (!atStart && pos == name.npos)
                return false;

            name.replace(pos, needle.size(), replacement);
            return true;
        };

        auto setType = [rewriteName](std::string& name) -> char {
            if (removeSuffix(name, "_entry") || rewriteName(name, "syscall_entry_", "syscall_", true)
                || rewriteName(name, "_begin_", "_", false) || rewriteName(name, "_before_", "_", false)) {
                return 'B';
            } else if (removeSuffix(name, "_exit")
		       || removeSuffix(name, "__return") || rewriteName(name, "syscall_exit_", "syscall_", true)
                       || rewriteName(name, "_end_", "_", false) || rewriteName(name, "_after_", "_", false)) {
                return 'E';
            } else {
                return 'i';
            }
        };

        if (name == "sched_switch") {
            const auto next_tid = get_int64(event, event_fields_scope, "next_tid").value();
            context->setTid(cpuId, next_tid);

            const auto next_pid = context->pid(next_tid);
            const auto next_comm = get_char_array(event, event_fields_scope, "next_comm").value();
            context->printName(next_tid, next_pid, next_comm, timestamp);

            const auto prev_tid = get_int64(event, event_fields_scope, "prev_tid").value();
            const auto prev_pid = context->pid(prev_tid);
            const auto prev_comm = get_char_array(event, event_fields_scope, "prev_comm").value();
            context->printName(prev_tid, prev_pid, prev_comm, timestamp);

            context->schedSwitch(prev_tid, prev_pid, prev_comm, next_tid, next_pid, next_comm, cpuId, timestamp);
        } else if (name == "sched_process_fork") {
            const auto parent_pid = get_int64(event, event_fields_scope, "parent_pid").value();
            const auto child_tid = get_int64(event, event_fields_scope, "child_tid").value();
            const auto child_pid = get_int64(event, event_fields_scope, "child_pid").value();
            context->setPid(child_tid, child_pid);

            const auto child_comm = get_char_array(event, event_fields_scope, "child_comm").value();
            context->printName(child_tid, child_pid, child_comm, timestamp);
            context->fork(parent_pid, child_pid);
        } else if (name == "sched_process_free") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto pid = context->pid(tid);
            context->threadExit(tid, pid, timestamp);
        } else if (name == "sched_process_exec") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto pid = context->pid(tid);
            context->setPid(tid, pid);

            auto filename = std::string_view(get_string(event, event_fields_scope, "filename").value());
            auto it = filename.find_last_of('/');
            if (it != filename.npos)
                filename.remove_prefix(it + 1);
            context->printName(tid, pid, filename, timestamp);
        } else if (name == "lttng_statedump_process_state") {
            const auto cpu = get_uint64(event, event_fields_scope, "cpu").value();
            const auto vtid = get_int64(event, event_fields_scope, "vtid").value();
            const auto vpid = get_int64(event, event_fields_scope, "vpid").value();

            context->setTid(cpu, vtid);
            context->setPid(vtid, vpid);

            const auto name = get_char_array(event, event_fields_scope, "name").value();
            context->printName(vtid, vpid, name, timestamp);
        } else if (name == "lttng_statedump_interrupt") {
            const auto irq = get_uint64(event, event_fields_scope, "irq").value();
            const auto name = get_string(event, event_fields_scope, "name").value();
            const auto action = get_string(event, event_fields_scope, "action").value();
            context->setIrqName(irq, name, action);
        } else if (name == "lttng_statedump_block_device") {
            const auto device = get_uint64(event, event_fields_scope, "dev").value();
            const auto diskname = get_string(event, event_fields_scope, "diskname").value();
            context->setBlockDeviceName(device, diskname);
        } else if (name == "lttng_statedump_file_descriptor") {
            const auto pid = get_int64(event, event_fields_scope, "pid").value();
            const auto fd = get_int64(event, event_fields_scope, "fd").value();
            const auto filename = get_string(event, event_fields_scope, "filename").value();
            context->setFdFilename(pid, fd, filename);
        } else if (name == "lttng_ust_statedump:bin_info") {
            const auto baddr = get_uint64(event, event_fields_scope, "baddr").value();
            const auto memsz = get_uint64(event, event_fields_scope, "memsz").value();
            const auto path = get_string(event, event_fields_scope, "path").value();
            context->mmap(pid, baddr, memsz, path, -1);
        } else if (name == "syscall_entry_mmap") {
            const auto len = get_uint64(event, event_fields_scope, "len").value();
            const auto fd = get_int64(event, event_fields_scope, "fd").value();
            context->mmapEntry(tid, len, fd);
        } else if (name == "syscall_exit_mmap") {
            const auto ret = get_uint64(event, event_fields_scope, "ret").value();
            context->mmapExit(pid, tid, ret, timestamp);
        } else if (name == "syscall_entry_munmap") {
            const auto addr = get_uint64(event, event_fields_scope, "addr").value();
            const auto len = get_uint64(event, event_fields_scope, "len").value();
            context->munmap(pid, addr, len, timestamp);
        } else if (name == "kmem_kmalloc" || name == "kmem_cache_alloc") {
            const auto ptr = get_uint64(event, event_fields_scope, "ptr").value();
            const auto bytes_req = get_uint64(event, event_fields_scope, "bytes_req").value();
            const auto bytes_alloc = get_uint64(event, event_fields_scope, "bytes_alloc").value();
            context->alloc(ptr, {bytes_req, bytes_alloc}, timestamp,
                           name == "kmem_kmalloc" ? Context::KMalloc : Context::CacheAlloc);
        } else if (name == "kmem_kfree" || name == "kmem_cache_free") {
            const auto ptr = get_uint64(event, event_fields_scope, "ptr").value();
            context->free(ptr, timestamp, name == "kmem_kfree" ? Context::KMalloc : Context::CacheAlloc);
        } else if (name == "power_cpu_frequency") {
            const auto state = get_uint64(event, event_fields_scope, "state").value();
            context->cpuFrequency(cpuId, state, timestamp);
        } else if (name == "kmem_mm_page_alloc") {
            const auto order = get_uint64(event, event_fields_scope, "order").value();
            context->pageAlloc(order, timestamp);
        } else if (name == "kmem_mm_page_free") {
            const auto order = get_uint64(event, event_fields_scope, "order").value();
            context->pageFree(order, timestamp);
        } else if (name == "block_rq_issue") {
            const auto dev = get_uint64(event, event_fields_scope, "dev").value();
            const auto sector = get_uint64(event, event_fields_scope, "sector").value();
            const auto nr_sector = get_uint64(event, event_fields_scope, "nr_sector").value();
            const auto bytes = get_uint64(event, event_fields_scope, "bytes").value();
            const auto rwbs = get_uint64(event, event_fields_scope, "rwbs").value();
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto comm = get_char_array(event, event_fields_scope, "comm").value();
            context->blockRqIssue(dev, sector, nr_sector, bytes, rwbs, tid, comm, timestamp);
        } else if (name == "block_rq_complete") {
            const auto dev = get_uint64(event, event_fields_scope, "dev").value();
            const auto sector = get_uint64(event, event_fields_scope, "sector").value();
            auto error = get_int64(event, event_fields_scope, "error");
            if (!error)
                error = get_int64(event, event_fields_scope, "errors");
            context->blockRqComplete(dev, sector, error.value(), timestamp);
        } else if (name == "block_rq_requeue") {
            const auto dev = get_uint64(event, event_fields_scope, "dev").value();
            const auto sector = get_uint64(event, event_fields_scope, "sector").value();
            context->blockRqRequeue(dev, sector, timestamp);
        } else if (name == "lttng_ust_tracef:event") {
            const auto msg = std::string_view(get_string(event, event_fields_scope, "msg").value());
            if (!msg.data() && !context->reportedBrokenTracefString) {
                WARNING() << "failed to read lttng_ust_tracef:event.msg\n"
                          << "please build babeltrace with https://github.com/efficios/babeltrace/pull/98 applied to "
                             "fix this";
                context->reportedBrokenTracefString = true;
            } else {
                std::string new_name(msg.substr(0, msg.find(' ')));
                const auto fullMsg = new_name == msg;
                if (!new_name.empty() && new_name.back() == ':')
                    new_name.resize(new_name.size() - 1);
                const auto new_type = setType(new_name);
                if (new_type != 'i') {
                    name = new_name;
                    type = new_type;
                    category = "lttng_ust";
                    skipArgs = fullMsg;
                    return;
                }
            }
        }

        type = setType(name);

        // TODO: also parse /sys/kernel/debug/tracing/available_events if accessible
        static const auto prefixes = {
            "block",
            "irq",
            "jbd2",
            "kmem",
            "lttng_statedump",
            "lttng_ust",
            "napi",
            "net",
            "module",
            "power",
            "random",
            "rcu",
            "sched",
            "scsi",
            "signal",
            "skb",
            "syscall",
            "timer",
            "workqueue",
            "writeback",
            "x86_exceptions_page_fault",
            "x86_irq_vectors",
        };
        for (auto prefix : prefixes) {
            if (startsWith(name, prefix)) {
                category = prefix;
                break;
            }
        }

        const struct bt_definition *vpid_field = bt_ctf_get_field(event, event_fields_scope, "perf_pid");
        const struct bt_definition *vtid_field = bt_ctf_get_field(event, event_fields_scope, "perf_tid");
        if (vpid_field)
                pid = bt_ctf_get_int64(vpid_field);
        if (vtid_field)
                tid = bt_ctf_get_int64(vtid_field);

        if ( startsWith(name, "probe:") || startsWith(name, "probe_")) {
                auto colonPos = name.find(':');
                if (colonPos != name.npos)
                      name = name.substr(colonPos+1, name.npos);
        }

        if (category.empty()) {
            auto colonPos = name.find(':');
            if (colonPos != name.npos)
                category = name.substr(0, colonPos);
        }
    }

    const bt_ctf_event* ctf_event = nullptr;
    const bt_definition* event_fields_scope = nullptr;
    std::string name;
    std::string category;
    int64_t timestamp = 0;
    uint64_t cpuId = 0;
    int64_t tid = -1;
    int64_t pid = -1;
    char type = 'i';
    bool isFilteredByTime = false;
    bool skipArgs = false;

private:
    void parseNonLttngEvent(Context* context)
    {
        // BEGIN gst-shark
        static bool gstGroupsGenerated = false;
        if (!gstGroupsGenerated) {
            gstGroupsGenerated = true;
            const auto names = {"scheduling", "interlatency", "proctime", "framerate", "bitrate", "queuelevel"};
            for (auto&& name : names) {
                context->generateTidForString(name, timestamp);
            }
        }
        auto countInGroup = [&](auto&& counterName, auto&& value) {
            const auto groupPid = context->generateTidForString(name, timestamp);
            context->printCounterValue(counterName, timestamp, groupPid, value);
        };
        auto formatTime = [](uint64_t time) { return static_cast<double>(time) * 1E-9; };
        if (name == "scheduling") {
            const auto pad = get_string(ctf_event, event_fields_scope, "pad").value();
            const auto time = formatTime(get_uint64(ctf_event, event_fields_scope, "time").value());
            pid = context->generateTidForString(pad, timestamp);
            tid = pid;
            context->printCounterValue(name, timestamp, pid, time);
            countInGroup(pad, time);
        } else if (name == "interlatency") {
            const auto from_pad = get_string(ctf_event, event_fields_scope, "from_pad").value();
            const auto to_pad = get_string(ctf_event, event_fields_scope, "to_pad").value();
            const auto time = formatTime(get_uint64(ctf_event, event_fields_scope, "time").value());
            pid = context->generateTidForString(from_pad, timestamp);
            tid = pid;
            context->printCounterValue(std::string("interlatency to ") + to_pad, timestamp, pid, time);
            countInGroup(std::string(from_pad) + " to " + to_pad, time);
        } else if (name == "proctime") {
            const auto element = get_string(ctf_event, event_fields_scope, "element").value();
            const auto time = formatTime(get_uint64(ctf_event, event_fields_scope, "time").value());
            pid = context->generateTidForString(element, timestamp);
            tid = pid;
            context->printCounterValue(name, timestamp, pid, time);
            countInGroup(element, time);
        } else if (name == "framerate") {
            const auto pad = get_string(ctf_event, event_fields_scope, "pad").value();
            const auto fps = get_uint64(ctf_event, event_fields_scope, "fps").value();
            pid = context->generateTidForString(pad, timestamp);
            tid = pid;
            context->printCounterValue(name, timestamp, pid, fps);
            countInGroup(pad, fps);
        } else if (name == "bitrate") {
            const auto pad = get_string(ctf_event, event_fields_scope, "pad").value();
            const auto bps = get_uint64(ctf_event, event_fields_scope, "bps").value();
            pid = context->generateTidForString(pad, timestamp);
            tid = pid;
            context->printCounterValue(name, timestamp, pid, bps);
            countInGroup(pad, bps);
        } else if (name == "cpuusage") {
            double totalUsage = 0;
            uint64_t cpuId = 0;
            while (true) {
                const auto cpuName = "cpu" + std::to_string(cpuId);
                const auto usage = get_float(ctf_event, event_fields_scope, cpuName.c_str());
                if (!usage)
                    break;
                totalUsage += usage.value();
                context->cpuUsage(cpuName, usage.value(), timestamp);
                ++cpuId;
            }
            context->cpuUsage("total", totalUsage, timestamp);
            pid = Context::CPU_COUNTER_PID;
            tid = pid;
        } else if (name == "queuelevel") {
            const auto queue = std::string(get_string(ctf_event, event_fields_scope, "queue").value());
            pid = context->generateTidForString(queue, timestamp);
            tid = pid;
            const auto size_buffers = get_uint64(ctf_event, event_fields_scope, "size_buffers").value();
            context->printCounterValue(name + " buffers", timestamp, pid, size_buffers);
            countInGroup(queue + " buffers", size_buffers);
            const auto size_bytes = get_uint64(ctf_event, event_fields_scope, "size_bytes").value();
            context->printCounterValue(name + " bytes", timestamp, pid, size_bytes);
            countInGroup(queue + " bytes", size_bytes);
            const auto size_time = formatTime(get_uint64(ctf_event, event_fields_scope, "size_time").value());
            context->printCounterValue(name + " time", timestamp, pid, size_time);
            countInGroup(queue + " time", size_time);
        }
        // END gst-shark
        else {
            WARNING() << "unhandled event: " << name;
        }
    }
};

template<typename ValueFormatter>
void addArg(const bt_ctf_event* event, const bt_declaration* decl, const bt_definition* def, ValueFormatter&& formatter)
{
    const auto type = bt_ctf_field_type(decl);
    const auto field_name = bt_ctf_field_name(def);
    const auto encoding = bt_ctf_get_encoding(decl);
    const auto isString = encoding == CTF_STRING_ASCII || encoding == CTF_STRING_UTF8;

    // skip sequence lengths
    if (type == CTF_TYPE_INTEGER && startsWith(field_name, "_") && endsWith(field_name, "_length"))
        return;

    switch (type) {
    case CTF_TYPE_UNKNOWN:
        formatter(field_name, ArgError::UnknownType);
        break;
    case CTF_TYPE_FLOAT:
        formatter(field_name, bt_ctf_get_float(def));
        break;
    case CTF_TYPE_INTEGER:
        switch (bt_ctf_get_int_signedness(decl)) {
        case 0:
            formatter(field_name, bt_ctf_get_uint64(def), bt_ctf_get_int_base(decl));
            break;
        case 1:
            formatter(field_name, bt_ctf_get_int64(def), bt_ctf_get_int_base(decl));
            break;
        default:
            formatter(field_name, ArgError::UnknownSignedness);
            break;
        }
        break;
    case CTF_TYPE_STRING:
        formatter(field_name, bt_ctf_get_string(def));
        break;
    case CTF_TYPE_ARRAY:
    case CTF_TYPE_VARIANT:
    case CTF_TYPE_STRUCT:
    case CTF_TYPE_SEQUENCE: {
        if (isString && type == CTF_TYPE_SEQUENCE) {
            formatter(field_name, bt_ctf_get_string(def));
            break;
        } else if (isString && type == CTF_TYPE_ARRAY) {
            formatter(field_name, bt_ctf_get_char_array(def));
            break;
        }
        unsigned int numEntries = 0;
        const bt_definition* const* sequence = nullptr;
        if (bt_ctf_get_field_list(event, def, &sequence, &numEntries) != 0 || numEntries == 0) {
            // empty sequence, skip
            return;
        }
        formatter(field_name, sequence, numEntries, type);
        break;
    }
    default:
        formatter(field_name, ArgError::UnhandledType, type);
        break;
    }
}

template<typename ValueFormatter>
void printArgs(const bt_ctf_event* event, const bt_definition* scope, ValueFormatter&& formatter)
{
    unsigned int fields = 0;
    const bt_definition* const* list = nullptr;
    if (bt_ctf_get_field_list(event, scope, &list, &fields) != 0) {
        WARNING() << "failed to read field list";
        return;
    }
    for (unsigned int i = 0; i < fields; ++i) {
        auto def = list[i];
        auto decl = bt_ctf_get_decl_from_def(def);
        if (!decl) {
            WARNING() << "invalid declaration for field " << i;
            continue;
        }
        addArg(event, decl, def, formatter);
    }
}

struct Formatter
{
    Formatter(JsonArgsPrinter printer, Context* context, const Event* event)
        : context(context)
        , event(event)
        , printer(std::move(printer))
    {
    }

    void operator()(std::string_view field, int64_t value, int base)
    {
#if Qt5Gui_FOUND
        if (startsWith(event->category, "qt")) {
            auto isEventType = [this, field]() {
                if (field != "type")
                    return false;
                if (event->name.find("Event") != event->name.npos)
                    return true;
                if (event->name.find("Application_notify") != event->name.npos)
                    return true;
                return false;
            };
            if (isEventType()) {
                const auto metaEnum = QMetaEnum::fromType<QEvent::Type>();
                const auto values = metaEnum.valueToKeys(value);
                if (!values.isEmpty()) {
                    (*this)(field, values.constData());
                    return;
                }
            }
        }
#endif
        printer.writeField(field, value, base);

        if (event->category == "syscall") {
            if (field == "fd" && value != -1) {
                (*this)("file", context->fdToFilename(event->pid, value));
            } else if (field == "ret") {
                if (event->name == "syscall_openat")
                    context->setOpenAtFd(event->pid, event->tid, value);
                else if (event->name == "syscall_socket")
                    context->setFdFilename(event->pid, value, "socket");
                else if (event->name == "syscall_eventfd2")
                    context->setFdFilename(event->pid, value, "eventfd");
            }
        }
    }

    void operator()(std::string_view field, uint64_t value, int base)
    {
        printer.writeField(field, value, base);

        if (printer.type == ArgsType::Array && printer.label == "fildes" && event->name == "syscall_pipe2") {
            context->setFdFilename(event->pid, value, index == 0 ? "pipe(read)" : "pipe(write)");
        } else if (field == "fd" && event->category == "syscall") {
            (*this)("file", context->fdToFilename(event->pid, static_cast<int64_t>(value)));
            if (event->name == "syscall_close")
                context->closeFd(event->pid, value);
        } else if (event->category == "irq" && field == "vec") {
            const auto& irq = context->irq(value);
            (*this)("name", irq.name);
            (*this)("action", irq.action);
        } else if (event->category == "block") {
            if (field == "dev")
                (*this)("dev_name", context->blockDeviceName(value));
            else if (field == "old_dev")
                (*this)("old_dev_name", context->blockDeviceName(value));
        } else if (event->category == "x86_exceptions_page_fault" && field == "address") {
            (*this)("file", context->fileMmappedAt(event->pid, value));
        }
    }

    void operator()(std::string_view field, std::string_view value)
    {
        if (field == "msg" && event->category == "lttng_ust") {
            if (event->type == 'E')
                field = "exit_msg";
            else if (event->type == 'B')
                field = "entry_msg";
        }
        printer.writeField(field, value);
        if (event->name == "syscall_openat" && field == "filename") {
            context->setOpenAtFilename(event->tid, value);
        }
    }

    void operator()(std::string_view field, ArgError error, int64_t arg = 0)
    {
        printer.writeField(field, error, arg);
    }

    void operator()(std::string_view field, double value)
    {
        printer.writeField(field, value);
    }

    void operator()(std::string_view field, const bt_definition* const* sequence, unsigned numEntries, ctf_type_id type)
    {
        if (type == CTF_TYPE_SEQUENCE && startsWith(event->category, "qt")) {
            std::string string;
#if Qt5Gui_FOUND
            QString utf16String;
#endif
            for (unsigned i = 0; i < numEntries; ++i) {
                const auto* def = sequence[i];
                const auto* decl = bt_ctf_get_decl_from_def(def);
                if (!decl) {
                    WARNING() << "invalid declaration for field" << field;
                    break;
                }
                const auto type = bt_ctf_field_type(decl);
                if (type != CTF_TYPE_INTEGER) {
                    WARNING() << "unexpected sequence type for qt tracepoint " << field << ": " << type;
                    break;
                }
                const auto signedness = bt_ctf_get_int_signedness(decl);
                switch (signedness) {
                case 0:
#if Qt5Gui_FOUND
                    utf16String.append(QChar(static_cast<char16_t>(bt_ctf_get_uint64(def))));
#else
                    string.push_back(static_cast<char>(bt_ctf_get_uint64(def)));
#endif
                    break;
                case 1:
#if Qt5Gui_FOUND
                    utf16String.append(QChar(static_cast<char16_t>(bt_ctf_get_int64(def))));
#else
                    string.push_back(static_cast<char>(bt_ctf_get_int64(def)));
#endif
                    break;
                default:
                    WARNING() << "unexpected sequence signedness for qt tracepoint " << field << ": " << signedness;
                    break;
                }
            }
#if Qt5Gui_FOUND
            string = utf16String.toStdString();
#endif
            (*this)(field, string);
            return;
        }

        const auto isArray = type == CTF_TYPE_SEQUENCE || type == CTF_TYPE_ARRAY;

        Formatter childFormatter(printer.argsPrinter(isArray ? ArgsType::Array : ArgsType::Object, field), context,
                                 event);
        for (unsigned i = 0; i < numEntries; ++i) {
            childFormatter.index = i;
            const auto* def = sequence[i];
            const auto* decl = bt_ctf_get_decl_from_def(def);
            if (!decl) {
                WARNING() << "invalid declaration for field " << field;
                break;
            }
            addArg(event->ctf_event, decl, def, childFormatter);
        }
    }

    Context* context;
    const Event* event;
    unsigned index = 0;
    JsonArgsPrinter printer;
};

void Context::parseEvent(bt_ctf_event* ctf_event)
{
    const auto event = Event(ctf_event, this);

    auto& ustCleanup_forCpu = ustCleanup[event.cpuId];
    auto& ignoreNextClockGettime_forCpu = ustCleanup_forCpu.ignoreNextClockGettime;
    auto& heldBackEvents_forCpu = ustCleanup_forCpu.heldBackEvents;

    if (event.category == "syscall") {
        if (ignoreNextClockGettime_forCpu && event.name == "syscall_clock_gettime" && event.type == 'E') {
            ignoreNextClockGettime_forCpu = false;
            return;
        }
        const auto holdBackEvent = [numEvents = heldBackEvents_forCpu.size(), &event]() {
            if (event.name == "syscall_getcpu") {
                if (numEvents == 0 && event.type == 'B')
                    return true;
                else if (numEvents == 1 && event.type == 'E')
                    return true;
            } else if (event.name == "syscall_clock_gettime") {
                if (numEvents == 2 && event.type == 'B')
                    return true;
            }
            return false;
        }();
        if (holdBackEvent) {
            heldBackEvents_forCpu.push_back(std::move(event));
            return;
        }
    } else if (heldBackEvents_forCpu.size() == 3) {
        ignoreNextClockGettime_forCpu = true;
        heldBackEvents_forCpu.clear();
    }

    drainHeldBackEvents(heldBackEvents_forCpu);
    handleEvent(event);
}

void Context::drainHeldBackEvents(std::vector<Event>& heldBackEvents_forCpu)
{
    for (const auto& heldBackEvent : heldBackEvents_forCpu)
        handleEvent(heldBackEvent);
    heldBackEvents_forCpu.clear();
}

void Context::drainHeldBackEvents()
{
    for (auto& data : ustCleanup)
        drainHeldBackEvents(data.second.heldBackEvents);
    ustCleanup.clear();
}

void Context::handleEvent(const Event& event)
{
    count(event.name, event.category);

    if (event.isFilteredByTime || isFilteredByPid(event.pid))
        return;

    if (event.category == "x86_exceptions_page_fault")
        pageFault(event.pid, event.timestamp);

    if (isFilteredByType(event.type) || isFiltered(event.name))
        return;

    {
        auto printer = eventPrinter(event.name, event.type, event.timestamp, event.pid, event.tid, event.category);

        if (event.event_fields_scope && !event.skipArgs)
            printArgs(event.ctf_event, event.event_fields_scope,
                      Formatter(printer.argsPrinter(ArgsType::Object, "args"), this, &event));
    }

    if (!firstProgressTimestamp)
    {
        firstProgressTimestamp = event.timestamp;
        lastProgressTimestamp = event.timestamp;
    }
    else if (lastProgressTimestamp && event.timestamp - lastProgressTimestamp > 1E6)
    {
        PROGRESS() << "parsed " << std::fixed << std::setprecision(3) << 1E-9 * (event.timestamp - firstProgressTimestamp) << 's';
        lastProgressTimestamp = event.timestamp;
    }
}
}

int main(int argc, char** argv)
{
    // optimize: we only have a single thread
    std::ios_base::sync_with_stdio(false);
    __fsetlocking(stdout, FSETLOCKING_BYCALLER);
    __fsetlocking(stdin, FSETLOCKING_BYCALLER);

    Context context(parseCliOptions(argc, argv));
    installSignalHandler();

    auto ctx = wrap(bt_context_create(), bt_context_put);

    bool hasTrace = false;
    findMetadataFiles(context.options.path, [&ctx, &hasTrace](const char* path) {
        auto trace_id = bt_context_add_trace(ctx.get(), path, "ctf", nullptr, nullptr, nullptr);
        if (trace_id < 0)
            ERROR() << "failed to open trace: " << path;
        else
            hasTrace = true;
    });

    if (!hasTrace)
        return 1;

    // loop twice to parse: first parse the lttng_statedump data, then continue onwards
    for (int i = 0; i < 2; ++i) {
        auto iter = wrap(bt_ctf_iter_create(ctx.get(), nullptr, nullptr), bt_ctf_iter_destroy);
        if (!iter) {
            ERROR() << "failed to create iterator";
            return 1;
        }

        do {
            if (i == 1) {
                if (auto lost = bt_ctf_get_lost_events_count(iter.get()))
                    WARNING() << "lost " << lost << " events - this can corrupt the results";
            }

            auto ctf_event = bt_ctf_iter_read_event(iter.get());
            if (!ctf_event)
                break;

            try {
                if (i == 0) {
                    std::string_view name(bt_ctf_event_name(ctf_event));
                    if (!startsWith(name, "lttng_statedump"))
                        continue;
                    else if (name == "lttng_statedump_end")
                        break;
                }

                context.parseEvent(ctf_event);
            } catch (const std::exception& exception) {
                WARNING() << "failed to parse event: " << exception.what();
            }
        } while (bt_iter_next(bt_ctf_get_iter(iter.get())) == 0 && !s_shutdownRequested);

        context.drainHeldBackEvents();
    }

    context.printStats(std::cerr);

    return 0;
}
