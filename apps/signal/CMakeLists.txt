#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(signal C)

set(configure_string "")
config_option(
    AppSignalBench
    APP_SIGNALBENCH
    "Application to benchmark seL4 signals without modification to the kernel."
    DEFAULT
    ON
    DEPENDS
    "DefaultBenchDeps"
)

if (KernelArchArm)
    config_set(L1DCacheSize L1_DCACHE_SIZE "0x8000")
endif()

config_choice(
    SignalCacheToMeasure
    SIGNAL_CACHE_TO_MEASURE
    "cache to measure"
    "Hot Cache;Signal_HotCache;HOT_CACHE;AppSignalBench"
    "Clean L1 ICache;Signal_CleanL1ICache;CLEAN_L1_ICACHE;AppSignalBench;KernelArchARM;NOT AppSmpBench"
    "Clean L1 DCache;Signal_CleanL1DCache;CLEAN_L1_DCACHE;AppSignalBench;KernelArchARM;NOT AppSmpBench"
    "Clean L1 IDCache;Signal_CleanL1IDCache;CLEAN_L1_IDCACHE;AppSignalBench;KernelArchARM;NOT AppSmpBench"
    "SIGNAL Dirty L1 DCache;Signal_DirtyL1DCache;SIGNAL_DIRTY_L1_DCACHE;AppSignalBench;L1DCacheSize"
)

add_config_library(sel4benchsignal "${configure_string}")

file(GLOB deps src/*.c)
list(SORT deps)
add_executable(signal EXCLUDE_FROM_ALL ${deps})
target_link_libraries(signal sel4_autoconf sel4benchsignal_Config sel4 sel4benchsupport sel4muslcsys)

if(AppSignalBench)
    set_property(GLOBAL APPEND PROPERTY sel4benchapps_property "$<TARGET_FILE:signal>")
endif()
