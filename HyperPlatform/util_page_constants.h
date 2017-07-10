// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Defines page table related constants
///
/// This file defines platform dependent constants and is included only from a
/// function where initializes g_utilp_p*e_base, g_utilp_p*i_shift and g_utilp_p*i_mask global variables.

#pragma once

// Virtual Address Interpretation For Handling PTEs
//
// -- On x64
// Sign extension                     16 bits
// Page map level 4 selector           9 bits
// Page directory pointer selector     9 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
// ^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
// Sign extension    PML4      PDPT      PD        PT        Offset
//
// -- On x86(PAE)
// Page directory pointer selector     2 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 10 000011011 000001101 001001110101
// ^^ ~~~~~~~~~ ^^^^^^^^^ ~~~~~~~~~~~~
// PDPT PD      PT        Offset
//
// -- On x86 and ARM
// Page directory selector            10 bits
// Page table selector                10 bits
// Byte within page                   12 bits
// 1000001101 1000001101 001001110101
// ~~~~~~~~~~ ^^^^^^^^^^ ~~~~~~~~~~~~
// PD         PT         Offset
//
//
//                                   x64   x86(PAE)  x86   ARM
// Page map level 4 selector           9          -    -     -
// Page directory pointer selector     9          2    -     -
// Page directory selector             9          9   10    10
// Page table selector                 9          9   10    10
// Byte within page                   12         12   12    12
//
// 6666555555555544444444443333333333222222222211111111110000000000
// 3210987654321098765432109876543210987654321098765432109876543210
// ----------------------------------------------------------------
// aaaaaaaaaaaaaaaabbbbbbbbbcccccccccdddddddddeeeeeeeeeffffffffffff  x64
// ................................ccdddddddddeeeeeeeeeffffffffffff  x86(PAE)
// ................................ddddddddddeeeeeeeeeeffffffffffff  x86
// ................................ddddddddddeeeeeeeeeeffffffffffff  ARM
//
// a = Sign extension, b = PML4, c = PDPT, d = PD, e = PT, f = Offset

static const auto kUtilpPxiShift = 39ull;// Get the highest 25 bits
static const auto kUtilpPpiShift = 30ull;// Get the highest 34 bits
static const auto kUtilpPdiShift = 21ull;// Get the highest 43 bits
static const auto kUtilpPtiShift = 12ull;// Get the highest 52 bits
static const auto kUtilpPxiMask = 0x1ffull;// Use  9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const auto kUtilpPpiMask = 0x3ffffull;// Use 18 bits; 0b0000_0000_0000_0000_0011_1111_1111_1111_1111
static const auto kUtilpPdiMask = 0x7ffffffull;// Use 27 bits; 0b0000_0000_0111_1111_1111_1111_1111_1111_1111
static const auto kUtilpPtiMask = 0xfffffffffull;// Use 36 bits; 0b1111_1111_1111_1111_1111_1111_1111_1111_1111

// Base addresses of page structures. Use !pte to obtain them.
static const auto kUtilpPdeBasePae = 0xc0600000;
static const auto kUtilpPteBasePae = 0xc0000000;

static const auto kUtilpPdiShiftPae = 21;// Get the highest 11 bits
static const auto kUtilpPtiShiftPae = 12;// Get the highest 20 bits
static const auto kUtilpPdiMaskPae = 0x7ff;// Use 11 bits; 0b0000_0000_0000_0000_0000_0000_0111_1111_1111
static const auto kUtilpPtiMaskPae = 0xfffff;// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
