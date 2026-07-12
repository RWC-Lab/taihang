/****************************************************************************
 * @file      bench_setting.cpp
 * @brief     set benchmark mode.
 * @author    This file is part of Taihang.
 ****************************************************************************/

#include <taihang/common/bench_setting.hpp>
#include <taihang/common/config.hpp>
#include <taihang/system/cpu.hpp>
#include <iostream>

namespace taihang{



void thread_configuration(BenchmarkMode mode){
    unsigned physical = system::get_physical_core_count();

    switch (mode)
    {
    case BenchmarkMode::SingleMachine:
        // Server and client execute concurrently on the same host.
        // Each party uses half of the available physical cores to
        // avoid CPU oversubscription.
        config::thread_num = std::max(1u, physical / 2);
        break;

    case BenchmarkMode::Distributed:
        // Each party runs on a dedicated machine and may utilize all
        // available physical cores.
        config::thread_num = physical;
        break;
    }

    std::cout << "\n"
          << "--------------------------------------------------------------------------------\n"
          << "Thread Configuration\n"
          << "--------------------------------------------------------------------------------\n"
          << "Benchmark mode      : "
          << (mode == BenchmarkMode::SingleMachine
                  ? "Single machine"
                  : "Distributed")
          << "\n"
          << "Physical cores      : " << physical << "\n"
          << "OMP threads/party   : " << config::thread_num << "\n";

    if (mode == BenchmarkMode::SingleMachine)
    {
        std::cout << "Total OMP threads   : "
                << config::thread_num * 2
                << " (server + client)\n";
    }

    std::cout << "--------------------------------------------------------------------------------\n";

}


} // namespace taihang