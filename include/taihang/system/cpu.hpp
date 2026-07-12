/****************************************************************************
 * @file      cpu.hpp
 * @brief     CPU hardware utilities.
 * @author    This file is part of Taihang.
 ****************************************************************************/

#pragma once

namespace taihang::system {

/**
 * @brief Returns the number of physical CPU cores.
 *
 * On macOS this queries hw.physicalcpu.
 *
 * On Linux the current implementation falls back to
 * std::thread::hardware_concurrency(). A more accurate
 * topology-based implementation can be added later without
 * changing this interface.
 *
 * @return Number of physical CPU cores (>=1).
 */
unsigned get_physical_core_count();

} // namespace taihang::system