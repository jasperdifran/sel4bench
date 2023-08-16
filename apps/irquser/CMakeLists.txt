#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(irquser C)

set(configure_string "")
config_option(
    AppIrqUserBench
    APP_IRQUSERBENCH
    "Application to benchmark seL4 IRQs without modification to the kernel."
    DEFAULT
    ON
    DEPENDS
    "DefaultBenchDeps"
)

if (KernelArchArm)
    config_set(L1DCacheSize L1_DCACHE_SIZE "0x8000")
endif()

config_choice(
    IrqUserCacheToMeasure
    IRQUSER_CACHE_TO_MEASURE
    "cache to measure"
    "Hot Cache;IrqUser_HotCache;HOT_CACHE;AppIrqUserBench"
    "Clean L1 ICache;IrqUser_CleanL1ICache;CLEAN_L1_ICACHE;AppIrqUserBench;KernelArchARM;NOT AppSmpBench"
    "Clean L1 DCache;IrqUser_CleanL1DCache;CLEAN_L1_DCACHE;AppIrqUserBench;KernelArchARM;NOT AppSmpBench"
    "Clean L1 IDCache;IrqUser_CleanL1IDCache;CLEAN_L1_IDCACHE;AppIrqUserBench;KernelArchARM;NOT AppSmpBench"
    "IRQ User Dirty L1 DCache;IrqUser_DirtyL1DCache;IRQ_USER_DIRTY_L1_DCACHE;AppIrqUserBench;L1DCacheSize"
)

add_config_library(sel4benchirquser "${configure_string}")

file(GLOB deps src/*.c)
list(SORT deps)
add_executable(irquser EXCLUDE_FROM_ALL ${deps})
target_link_libraries(
    irquser
    sel4_autoconf
    sel4benchirquser_Config
    sel4
    muslc
    sel4vka
    sel4allocman
    sel4utils
    sel4simple
    sel4muslcsys
    sel4platsupport
    platsupport
    sel4vspace
    sel4benchsupport
    sel4debug
)

if(AppIrqUserBench)
    set_property(GLOBAL APPEND PROPERTY sel4benchapps_property "$<TARGET_FILE:irquser>")
endif()
