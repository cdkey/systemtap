
/*============================================================================

This C header file is part of the SoftFloat IEEE Floating-Point Arithmetic

Copyright 2011, 2012, 2013, 2014, 2015, 2016, 2017 The Regents of the
University of California.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions, and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions, and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the University nor the names of its contributors may
    be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS", AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE
DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=============================================================================*/

#ifndef primitives_h
#define primitives_h 1
#define primitives_h 1

// #include <stdbool.h>
// #include <stdint.h>
#include "softfloat/primitiveTypes.h"

#ifndef softfloat_shortShiftRightJam64
/*----------------------------------------------------------------------------
| Shifts 'a' right by the number of bits given in 'dist', which must be in
| the range 1 to 63.  If any nonzero bits are shifted off, they are "jammed"
| into the least-significant bit of the shifted value by setting the least-
| significant bit to 1.  This shifted-and-jammed value is returned.
*----------------------------------------------------------------------------*/
#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist )
    { return a>>dist | ((a & (((uint_fast64_t) 1<<dist) - 1)) != 0); }
#else
uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam32
/*----------------------------------------------------------------------------
| Shifts 'a' right by the number of bits given in 'dist', which must not
| be zero.  If any nonzero bits are shifted off, they are "jammed" into the
| least-significant bit of the shifted value by setting the least-significant
| bit to 1.  This shifted-and-jammed value is returned.
|   The value of 'dist' can be arbitrarily large.  In particular, if 'dist' is
| greater than 32, the result will be either 0 or 1, depending on whether 'a'
| is zero or nonzero.
*----------------------------------------------------------------------------*/
#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE uint32_t softfloat_shiftRightJam32( uint32_t a, uint_fast16_t dist )
{
    return
        (dist < 31) ? a>>dist | ((uint32_t) (a<<(-dist & 31)) != 0) : (a != 0);
}
#else
uint32_t softfloat_shiftRightJam32( uint32_t a, uint_fast16_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam64
/*----------------------------------------------------------------------------
| Shifts 'a' right by the number of bits given in 'dist', which must not
| be zero.  If any nonzero bits are shifted off, they are "jammed" into the
| least-significant bit of the shifted value by setting the least-significant
| bit to 1.  This shifted-and-jammed value is returned.
|   The value of 'dist' can be arbitrarily large.  In particular, if 'dist' is
| greater than 64, the result will be either 0 or 1, depending on whether 'a'
| is zero or nonzero.
*----------------------------------------------------------------------------*/
#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)
INLINE uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist )
{
    return
        (dist < 63) ? a>>dist | ((uint64_t) (a<<(-dist & 63)) != 0) : (a != 0);
}
#else
uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist );
#endif
#endif

#ifndef softfloat_shortShiftRightM
/*----------------------------------------------------------------------------
| Shifts the N-bit unsigned integer pointed to by 'aPtr' right by the number
| of bits given in 'dist', where N = 'size_words' * 32.  The value of 'dist'
| must be in the range 1 to 31.  Any nonzero bits shifted off are lost.  The
| shifted N-bit result is stored at the location pointed to by 'zPtr'.  Each
| of 'aPtr' and 'zPtr' points to a 'size_words'-long array of 32-bit elements
| that concatenate in the platform's normal endian order to form an N-bit
| integer.
*----------------------------------------------------------------------------*/
void
 softfloat_shortShiftRightM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shortShiftRight128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_shortShiftRightM' with
| 'size_words' = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_shortShiftRight128M( aPtr, dist, zPtr ) softfloat_shortShiftRightM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftRightJamM
/*----------------------------------------------------------------------------
| Shifts the N-bit unsigned integer pointed to by 'aPtr' right by the number
| of bits given in 'dist', where N = 'size_words' * 32.  The value of 'dist'
| must be in the range 1 to 31.  If any nonzero bits are shifted off, they are
| "jammed" into the least-significant bit of the shifted value by setting the
| least-significant bit to 1.  This shifted-and-jammed N-bit result is stored
| at the location pointed to by 'zPtr'.  Each of 'aPtr' and 'zPtr' points
| to a 'size_words'-long array of 32-bit elements that concatenate in the
| platform's normal endian order to form an N-bit integer.
*----------------------------------------------------------------------------*/
void
 softfloat_shortShiftRightJamM(
     uint_fast8_t, const uint32_t *, uint_fast8_t, uint32_t * );
#endif

#ifndef softfloat_shiftRightJamM
/*----------------------------------------------------------------------------
| Shifts the N-bit unsigned integer pointed to by 'aPtr' right by the number
| of bits given in 'dist', where N = 'size_words' * 32.  The value of 'dist'
| must not be zero.  If any nonzero bits are shifted off, they are "jammed"
| into the least-significant bit of the shifted value by setting the least-
| significant bit to 1.  This shifted-and-jammed N-bit result is stored
| at the location pointed to by 'zPtr'.  Each of 'aPtr' and 'zPtr' points
| to a 'size_words'-long array of 32-bit elements that concatenate in the
| platform's normal endian order to form an N-bit integer.
|   The value of 'dist' can be arbitrarily large.  In particular, if 'dist'
| is greater than N, the stored result will be either 0 or 1, depending on
| whether the original N bits are all zeros.
*----------------------------------------------------------------------------*/
void
 softfloat_shiftRightJamM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftRightJam96M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_shiftRightJamM' with
| 'size_words' = 3 (N = 96).
*----------------------------------------------------------------------------*/
#define softfloat_shiftRightJam96M( aPtr, dist, zPtr ) softfloat_shiftRightJamM( 3, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftRightJam128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_shiftRightJamM' with
| 'size_words' = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_shiftRightJam128M( aPtr, dist, zPtr ) softfloat_shiftRightJamM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftLeftM
/*----------------------------------------------------------------------------
| Shifts the N-bit unsigned integer pointed to by 'aPtr' left by the number
| of bits given in 'dist', where N = 'size_words' * 32.  The value of 'dist'
| must be in the range 1 to 31.  Any nonzero bits shifted off are lost.  The
| shifted N-bit result is stored at the location pointed to by 'zPtr'.  Each
| of 'aPtr' and 'zPtr' points to a 'size_words'-long array of 32-bit elements
| that concatenate in the platform's normal endian order to form an N-bit
| integer.
*----------------------------------------------------------------------------*/
void
 softfloat_shortShiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftLeftM
/*----------------------------------------------------------------------------
| Shifts the N-bit unsigned integer pointed to by 'aPtr' left by the number
| of bits given in 'dist', where N = 'size_words' * 32.  The value of 'dist'
| must not be zero.  Any nonzero bits shifted off are lost.  The shifted
| N-bit result is stored at the location pointed to by 'zPtr'.  Each of 'aPtr'
| and 'zPtr' points to a 'size_words'-long array of 32-bit elements that
| concatenate in the platform's normal endian order to form an N-bit integer.
|   The value of 'dist' can be arbitrarily large.  In particular, if 'dist' is
| greater than N, the stored result will be 0.
*----------------------------------------------------------------------------*/
void
 softfloat_shiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftLeft128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_shiftLeftM' with
| 'size_words' = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_shiftLeft128M( aPtr, dist, zPtr ) softfloat_shiftLeftM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_countLeadingZeros64
/*----------------------------------------------------------------------------
| Returns the number of leading 0 bits before the most-significant 1 bit of
| 'a'.  If 'a' is zero, 64 is returned.
*----------------------------------------------------------------------------*/
uint_fast8_t softfloat_countLeadingZeros64( uint64_t a );
#endif

extern const uint16_t softfloat_approxRecip_1k0s[16];
extern const uint16_t softfloat_approxRecip_1k1s[16];

#ifndef softfloat_approxRecip32_1
/*----------------------------------------------------------------------------
| Returns an approximation to the reciprocal of the number represented by 'a',
| where 'a' is interpreted as an unsigned fixed-point number with one integer
| bit and 31 fraction bits.  The 'a' input must be "normalized", meaning that
| its most-significant bit (bit 31) must be 1.  Thus, if A is the value of
| the fixed-point interpretation of 'a', then 1 <= A < 2.  The returned value
| is interpreted as a pure unsigned fraction, having no integer bits and 32
| fraction bits.  The approximation returned is never greater than the true
| reciprocal 1/A, and it differs from the true reciprocal by at most 2.006 ulp
| (units in the last place).
*----------------------------------------------------------------------------*/
#ifdef SOFTFLOAT_FAST_DIV64TO32
#define softfloat_approxRecip32_1( a ) ((uint32_t) (UINT64_C( 0x7FFFFFFFFFFFFFFF ) / (uint32_t) (a)))
#else
uint32_t softfloat_approxRecip32_1( uint32_t a );
#endif
#endif

extern const uint16_t softfloat_approxRecipSqrt_1k0s[16];
extern const uint16_t softfloat_approxRecipSqrt_1k1s[16];

#ifndef softfloat_approxRecipSqrt32_1
/*----------------------------------------------------------------------------
| Returns an approximation to the reciprocal of the square root of the number
| represented by 'a', where 'a' is interpreted as an unsigned fixed-point
| number either with one integer bit and 31 fraction bits or with two integer
| bits and 30 fraction bits.  The format of 'a' is determined by 'oddExpA',
| which must be either 0 or 1.  If 'oddExpA' is 1, 'a' is interpreted as
| having one integer bit, and if 'oddExpA' is 0, 'a' is interpreted as having
| two integer bits.  The 'a' input must be "normalized", meaning that its
| most-significant bit (bit 31) must be 1.  Thus, if A is the value of the
| fixed-point interpretation of 'a', it follows that 1 <= A < 2 when 'oddExpA'
| is 1, and 2 <= A < 4 when 'oddExpA' is 0.
|   The returned value is interpreted as a pure unsigned fraction, having
| no integer bits and 32 fraction bits.  The approximation returned is never
| greater than the true reciprocal 1/sqrt(A), and it differs from the true
| reciprocal by at most 2.06 ulp (units in the last place).  The approximation
| returned is also always within the range 0.5 to 1; thus, the most-
| significant bit of the result is always set.
*----------------------------------------------------------------------------*/
uint32_t softfloat_approxRecipSqrt32_1( unsigned int oddExpA, uint32_t a );
#endif

#ifndef softfloat_mul64To128M
/*----------------------------------------------------------------------------
| Multiplies 'a' and 'b' and stores the 128-bit product at the location
| pointed to by 'zPtr'.  Argument 'zPtr' points to an array of four 32-bit
| elements that concatenate in the platform's normal endian order to form a
| 128-bit integer.
*----------------------------------------------------------------------------*/
void softfloat_mul64To128M( uint64_t a, uint64_t b, uint32_t *zPtr );
#endif

#ifndef softfloat_negXM
/*----------------------------------------------------------------------------
| Replaces the N-bit unsigned integer pointed to by 'zPtr' by the
| 2s-complement of itself, where N = 'size_words' * 32.  Argument 'zPtr'
| points to a 'size_words'-long array of 32-bit elements that concatenate in
| the platform's normal endian order to form an N-bit integer.
*----------------------------------------------------------------------------*/
void softfloat_negXM( uint_fast8_t size_words, uint32_t *zPtr );
#endif

#ifndef softfloat_negX128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_negXM' with 'size_words'
| = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_negX128M( zPtr ) softfloat_negXM( 4, zPtr )
#endif

#ifndef softfloat_addM
/*----------------------------------------------------------------------------
| Adds the two N-bit integers pointed to by 'aPtr' and 'bPtr', where N =
| 'size_words' * 32.  The addition is modulo 2^N, so any carry out is lost.
| The N-bit sum is stored at the location pointed to by 'zPtr'.  Each of
| 'aPtr', 'bPtr', and 'zPtr' points to a 'size_words'-long array of 32-bit
| elements that concatenate in the platform's normal endian order to form an
| N-bit integer.
*----------------------------------------------------------------------------*/
void
 softfloat_addM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_add128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_addM' with 'size_words'
| = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_add128M( aPtr, bPtr, zPtr ) softfloat_addM( 4, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_subM
/*----------------------------------------------------------------------------
| Subtracts the two N-bit integers pointed to by 'aPtr' and 'bPtr', where N =
| 'size_words' * 32.  The subtraction is modulo 2^N, so any borrow out (carry
| out) is lost.  The N-bit difference is stored at the location pointed to by
| 'zPtr'.  Each of 'aPtr', 'bPtr', and 'zPtr' points to a 'size_words'-long
| array of 32-bit elements that concatenate in the platform's normal endian
| order to form an N-bit integer.
*----------------------------------------------------------------------------*/
void
 softfloat_subM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_sub128M
/*----------------------------------------------------------------------------
| This function or macro is the same as 'softfloat_subM' with 'size_words'
| = 4 (N = 128).
*----------------------------------------------------------------------------*/
#define softfloat_sub128M( aPtr, bPtr, zPtr ) softfloat_subM( 4, aPtr, bPtr, zPtr )
#endif

#endif
