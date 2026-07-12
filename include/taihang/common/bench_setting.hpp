/****************************************************************************
 * @file      bench_setting.hpp
 * @brief     set benchmark mode.
 * @author    This file is part of Taihang.
 ****************************************************************************/

#pragma once

namespace taihang{

enum class BenchmarkMode
{
    SingleMachine,
    Distributed
};

void thread_configuration(BenchmarkMode mode); 


} // namespace taihang

