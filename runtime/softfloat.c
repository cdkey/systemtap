/*============================================================================

This C source file is part of the SoftFloat IEEE Floating-Point Arithmetic
Package, Release 3e, by John R. Hauser.

Copyright 2011, 2012, 2013, 2014 The Regents of the University of California.
All rights reserved.

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

//#include <stdbool.h>
//#include <stdint.h>
#include "softfloat/platform.h"
#include "softfloat/internals.h"
#include "softfloat.h"
#include "softfloat/specialize.h"
#include "softfloat/primitives.h"
#include "softfloat/primitiveTypes.h"

#ifndef THREAD_LOCAL
#define THREAD_LOCAL
#endif

THREAD_LOCAL uint_fast8_t softfloat_roundingMode = softfloat_round_near_even;
THREAD_LOCAL uint_fast8_t softfloat_detectTininess = init_detectTininess;
THREAD_LOCAL uint_fast8_t softfloat_exceptionFlags = 0;

THREAD_LOCAL uint_fast8_t extF80_roundingPrecision = 80;

#ifndef softfloat_countLeadingZeros64

#define softfloat_countLeadingZeros64 softfloat_countLeadingZeros64

uint_fast8_t softfloat_countLeadingZeros64( uint64_t a )
{
    uint_fast8_t count;
    uint32_t a32;

    count = 0;
    a32 = a>>32;
    if ( ! a32 ) {
        count = 32;
        a32 = a;
    }
    /*------------------------------------------------------------------------
    | From here, result is current count + count leading zeros of `a32'.
    *------------------------------------------------------------------------*/
    if ( a32 < 0x10000 ) {
        count += 16;
        a32 <<= 16;
    }
    if ( a32 < 0x1000000 ) {
        count += 8;
        a32 <<= 8;
    }
    count += softfloat_countLeadingZeros8[a32>>24];
    return count;

}

#endif

#ifndef softfloat_shortShiftRightJamM

void
 softfloat_shortShiftRightJamM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 )
{
    uint_fast8_t uNegDist;
    unsigned int index, lastIndex;
    uint32_t partWordZ, wordA;

    uNegDist = -dist;
    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    wordA = aPtr[index];
    partWordZ = wordA>>dist;
    if ( partWordZ<<dist != wordA ) partWordZ |= 1;
    while ( index != lastIndex ) {
        wordA = aPtr[index + wordIncr];
        zPtr[index] = wordA<<(uNegDist & 31) | partWordZ;
        index += wordIncr;
        partWordZ = wordA>>dist;
    }
    zPtr[index] = partWordZ;

}

#endif

#ifndef softfloat_shiftRightJamM

#define softfloat_shiftRightJamM softfloat_shiftRightJamM

void
 softfloat_shiftRightJamM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 )
{
    uint32_t wordJam, wordDist, *ptr=0;
    uint_fast8_t i, innerDist;

    wordJam = 0;
    wordDist = dist>>5;
    if ( wordDist ) {
        if ( size_words < wordDist ) wordDist = size_words;
        ptr = (uint32_t *) (aPtr + indexMultiwordLo( size_words, wordDist ));
        i = wordDist;
        do {
            wordJam = *ptr++;
            if ( wordJam ) break;
            --i;
        } while ( i );
        ptr = zPtr;
    }
    if ( wordDist < size_words ) {
        aPtr += indexMultiwordHiBut( size_words, wordDist );
        innerDist = dist & 31;
        if ( innerDist ) {
            softfloat_shortShiftRightJamM(
                size_words - wordDist,
                aPtr,
                innerDist,
                zPtr + indexMultiwordLoBut( size_words, wordDist )
            );
            if ( ! wordDist ) goto wordJam;
        } else {
            aPtr += indexWordLo( size_words - wordDist );
            ptr = zPtr + indexWordLo( size_words );
            for ( i = size_words - wordDist; i; --i ) {
                *ptr = *aPtr;
                aPtr += wordIncr;
                ptr += wordIncr;
            }
        }
        ptr = zPtr + indexMultiwordHi( size_words, wordDist );
    }
    do {
        *ptr++ = 0;
        --wordDist;
    } while ( wordDist );
 wordJam:
    if ( wordJam ) zPtr[indexWordLo( size_words )] |= 1;

}

#endif


#ifndef softfloat_shiftRightJam64

uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist )
{

    return
        (dist < 63) ? a>>dist | ((uint64_t) (a<<(-dist & 63)) != 0) : (a != 0);

}

#endif

/*----------------------------------------------------------------------------
| Raises the exceptions specified by 'flags'.  Floating-point traps can be
| defined here if desired.  It is currently not possible for such a trap
| to substitute a result value.  If traps are not implemented, this routine
| should be simply 'softfloat_exceptionFlags |= flags;'.
*----------------------------------------------------------------------------*/
void softfloat_raiseFlags( uint_fast8_t flags )
{

    softfloat_exceptionFlags |= flags;

}

float64_t
 softfloat_roundPackToF64( bool sign, int_fast16_t exp, uint_fast64_t sig )
{
    uint_fast8_t roundingMode;
    bool roundNearEven;
    uint_fast16_t roundIncrement, roundBits;
    bool isTiny;
    uint_fast64_t uiZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    roundingMode = softfloat_roundingMode;
    roundNearEven = (roundingMode == softfloat_round_near_even);
    roundIncrement = 0x200;
    if ( ! roundNearEven && (roundingMode != softfloat_round_near_maxMag) ) {
        roundIncrement =
            (roundingMode
                 == (sign ? softfloat_round_min : softfloat_round_max))
                ? 0x3FF
                : 0;
    }
    roundBits = sig & 0x3FF;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( 0x7FD <= (uint16_t) exp ) {
        if ( exp < 0 ) {
            /*----------------------------------------------------------------
            *----------------------------------------------------------------*/
            isTiny =
                (softfloat_detectTininess == softfloat_tininess_beforeRounding)
                    || (exp < -1)
                    || (sig + roundIncrement < UINT64_C( 0x8000000000000000 ));
            sig = softfloat_shiftRightJam64( sig, -exp );
            exp = 0;
            roundBits = sig & 0x3FF;
            if ( isTiny && roundBits ) {
                softfloat_raiseFlags( softfloat_flag_underflow );
            }
        } else if (
            (0x7FD < exp)
                || (UINT64_C( 0x8000000000000000 ) <= sig + roundIncrement)
        ) {
            /*----------------------------------------------------------------
            *----------------------------------------------------------------*/
            softfloat_raiseFlags(
                softfloat_flag_overflow | softfloat_flag_inexact );
            uiZ = packToF64UI( sign, 0x7FF, 0 ) - ! roundIncrement;
            goto uiZ;
        }
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    sig = (sig + roundIncrement)>>10;
    if ( roundBits ) {
        softfloat_exceptionFlags |= softfloat_flag_inexact;
#ifdef SOFTFLOAT_ROUND_ODD
        if ( roundingMode == softfloat_round_odd ) {
            sig |= 1;
            goto packReturn;
        }
#endif
    }
    sig &= ~(uint_fast64_t) (! (roundBits ^ 0x200) & roundNearEven);
    if ( ! sig ) exp = 0;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 packReturn:
    uiZ = packToF64UI( sign, exp, sig );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

float64_t
 softfloat_normRoundPackToF64( bool sign, int_fast16_t exp, uint_fast64_t sig  
)
{
    int_fast8_t shiftDist;
    union ui64_f64 uZ;

    shiftDist = softfloat_countLeadingZeros64( sig ) - 1;
    exp -= shiftDist;
    if ( (10 <= shiftDist) && ((unsigned int) exp < 0x7FD) ) {
        uZ.ui = packToF64UI( sign, sig ? exp : 0, sig<<(shiftDist - 10) );
        return uZ.f;
    } else {
        return softfloat_roundPackToF64( sign, exp, sig<<shiftDist );
    }

}

#ifndef softfloat_shortShiftRightJam64

uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist )
{

    return a>>dist | ((a & (((uint_fast64_t) 1<<dist) - 1)) != 0);

}

#endif

uint_fast64_t
 softfloat_roundMToUI64(
     bool sign, uint32_t *extSigPtr, uint_fast8_t roundingMode, bool exact )
{
    uint64_t sig;
    uint32_t sigExtra;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    sig =
        (uint64_t) extSigPtr[indexWord( 3, 2 )]<<32
            | extSigPtr[indexWord( 3, 1 )];
    sigExtra = extSigPtr[indexWordLo( 3 )];
    if (
        (roundingMode == softfloat_round_near_maxMag)
            || (roundingMode == softfloat_round_near_even)
    ) {
        if ( 0x80000000 <= sigExtra ) goto increment;
    } else {
        if ( sign ) {
            if ( !(sig | sigExtra) ) return 0;
            if ( roundingMode == softfloat_round_min ) goto invalid;
#ifdef SOFTFLOAT_ROUND_ODD
            if ( roundingMode == softfloat_round_odd ) goto invalid;
#endif
        } else {
            if ( (roundingMode == softfloat_round_max) && sigExtra ) {
 increment:
                ++sig;
                if ( !sig ) goto invalid;
                if (
                    (sigExtra == 0x80000000)
                        && (roundingMode == softfloat_round_near_even)
                ) {
                    sig &= ~(uint_fast64_t) 1;
                }
            }
        }
    }
    if ( sign && sig ) goto invalid;
    if ( sigExtra ) {
#ifdef SOFTFLOAT_ROUND_ODD
        if ( roundingMode == softfloat_round_odd ) sig |= 1;
#endif
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return sig;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return sign ? ui64_fromNegOverflow : ui64_fromPosOverflow;

}

int_fast64_t
 softfloat_roundMToI64(
     bool sign, uint32_t *extSigPtr, uint_fast8_t roundingMode, bool exact )
{
    uint64_t sig;
    uint32_t sigExtra;
    union { uint64_t ui; int64_t i; } uZ;
    int64_t z;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    sig =
        (uint64_t) extSigPtr[indexWord( 3, 2 )]<<32
            | extSigPtr[indexWord( 3, 1 )];
    sigExtra = extSigPtr[indexWordLo( 3 )];
    if (
        (roundingMode == softfloat_round_near_maxMag)
            || (roundingMode == softfloat_round_near_even)
    ) {
        if ( 0x80000000 <= sigExtra ) goto increment;
    } else {
        if (
            sigExtra
                && (sign
                        ? (roundingMode == softfloat_round_min)
#ifdef SOFTFLOAT_ROUND_ODD
                              || (roundingMode == softfloat_round_odd)
#endif
                        : (roundingMode == softfloat_round_max))
        ) {
 increment:
            ++sig;
            if ( !sig ) goto invalid;
            if (
                (sigExtra == 0x80000000)
                    && (roundingMode == softfloat_round_near_even)
            ) {
                sig &= ~(uint_fast64_t) 1;
            }
        }
    }
    uZ.ui = sign ? -sig : sig;
    z = uZ.i;
    if ( z && ((z < 0) ^ sign) ) goto invalid;
    if ( sigExtra ) {
#ifdef SOFTFLOAT_ROUND_ODD
        if ( roundingMode == softfloat_round_odd ) z |= 1;
#endif
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return z;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return sign ? i64_fromNegOverflow : i64_fromPosOverflow;

}

/*----------------------------------------------------------------------------
| Conversion from int/unsigned int to floating point and vice versa.
 ----------------------------------------------------------------------------*/

float64_t i64_to_f64( int64_t a )
{
    bool sign;
    union ui64_f64 uZ;
    uint_fast64_t absA;

    sign = (a < 0);
    if ( ! (a & UINT64_C( 0x7FFFFFFFFFFFFFFF )) ) {
        uZ.ui = sign ? packToF64UI( 1, 0x43E, 0 ) : 0;
        return uZ.f;
    }
    absA = sign ? -(uint_fast64_t) a : (uint_fast64_t) a;
    return softfloat_normRoundPackToF64( sign, 0x43C, absA );
}

int_fast64_t f64_to_i64( float64_t a, uint_fast8_t roundingMode, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
#ifdef SOFTFLOAT_FAST_INT64
    struct uint64_extra sigExtra;
#else
    uint32_t extSig[3];
#endif

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    sign = signF64UI( uiA );
    exp  = expF64UI( uiA );
    sig  = fracF64UI( uiA );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( exp ) sig |= UINT64_C( 0x0010000000000000 );
    shiftDist = 0x433 - exp;
#ifdef SOFTFLOAT_FAST_INT64
    if ( shiftDist <= 0 ) {
        if ( shiftDist < -11 ) goto invalid;
        sigExtra.v = sig<<-shiftDist;
        sigExtra.extra = 0;
    } else {
        sigExtra = softfloat_shiftRightJam64Extra( sig, 0, shiftDist );
    }
    return
        softfloat_roundToI64(
            sign, sigExtra.v, sigExtra.extra, roundingMode, exact );
#else
    extSig[indexWord( 3, 0 )] = 0;
    if ( shiftDist <= 0 ) {
        if ( shiftDist < -11 ) goto invalid;
        sig <<= -shiftDist;
        extSig[indexWord( 3, 2 )] = sig>>32;
        extSig[indexWord( 3, 1 )] = sig;
    } else {
        extSig[indexWord( 3, 2 )] = sig>>32;
        extSig[indexWord( 3, 1 )] = sig;
        softfloat_shiftRightJam96M( extSig, shiftDist, extSig );
    }
    return softfloat_roundMToI64( sign, extSig, roundingMode, exact );
#endif
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return
        (exp == 0x7FF) && fracF64UI( uiA ) ? i64_fromNaN
            : sign ? i64_fromNegOverflow : i64_fromPosOverflow;

}

/*----------------------------------------------------------------------------
| Converts the common NaN pointed to by 'aPtr' into a 64-bit floating-point
| NaN, and returns the bit pattern of this value as an unsigned integer.
*----------------------------------------------------------------------------*/
uint_fast64_t softfloat_commonNaNToF64UI( const struct commonNaN *aPtr )
{
    return
        (uint_fast64_t) aPtr->sign<<63 | UINT64_C( 0x7FF8000000000000 )
            | aPtr->v64>>12;
}

/*----------------------------------------------------------------------------
| Assuming 'uiA' has the bit pattern of a 64-bit floating-point NaN, converts
| this NaN to the common NaN form, and stores the resulting common NaN at the
| location pointed to by 'zPtr'.  If the NaN is a signaling NaN, the invalid
| exception is raised.
*----------------------------------------------------------------------------*/
void softfloat_f64UIToCommonNaN( uint_fast64_t uiA, struct commonNaN *zPtr )
{
    if ( softfloat_isSigNaNF64UI( uiA ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
    }
    zPtr->sign = uiA>>63;
    zPtr->v64  = uiA<<12;
    zPtr->v0   = 0;
}

/*----------------------------------------------------------------------------
| Interpreting 'uiA' and 'uiB' as the bit patterns of two 64-bit floating-
| point values, at least one of which is a NaN, returns the bit pattern of
| the combined NaN result.  If either 'uiA' or 'uiB' has the pattern of a
| signaling NaN, the invalid exception is raised.
*----------------------------------------------------------------------------*/
uint_fast64_t
 softfloat_propagateNaNF64UI( uint_fast64_t uiA, uint_fast64_t uiB )
{
    bool isSigNaNA;

    isSigNaNA = softfloat_isSigNaNF64UI( uiA );
    if ( isSigNaNA || softfloat_isSigNaNF64UI( uiB ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return (isSigNaNA ? uiA : uiB) | UINT64_C( 0x0008000000000000 );
    }
    return isNaNF64UI( uiA ) ? uiA : uiB;
}

/*------------------------------------------------------------------------
|Converting a fp to a str 
*------------------------------------------------------------------------*/

char* itoa(uint64_t val)
{
    int base = 10;
    static char buf[32] = {0};

    int i = 30;
    while (i != 0)
    {

        buf[i] = "0123456789abcdef"[val % base];
        val /= base;
        i--;
        if (!(val && i)) break;
    }

    return &buf[i+1];
}

void f64_to_str( char *result, int outlen, float64_t a, int precision )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool sign;
    uint_fast32_t exp;
    uint_fast64_t sig;
 
    char *iPart;
    char *fTemp;
    uint64_t fPart;
    uint64_t base;
    uint64_t temp;
    
    int lastNum;
    int numAfterLast;
    int i; 
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    sign = signF64UI( uiA );
    exp  = expF64UI( uiA );
    sig  = fracF64UI( uiA );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/

    if ( exp ) sig |= UINT64_C( 0x0010000000000000 );
    exp = exp - 1023;
    memset(result, '\0', outlen);
    if (sign) strcat(result, "-");
    iPart = itoa(sig >> (52 - exp));
    strcat(result, iPart);
    strcat(result, ".");
    fPart = sig & (((uint64_t)1 << (52 - exp)) - 1);
    base = (uint64_t)1 << (52 - exp);
    temp = 0;
    i = 0;
    while (i++ < precision-1)
    {
        fPart *= 10;
        fTemp = itoa(fPart/base);
        strcat(result, fTemp);
        fPart %= base;
    }

    fPart *= 10;
    lastNum = fPart/base;
    fPart %= base;

    numAfterLast = 0;

    if (fPart != 0)
    {
        fPart*= 10;
        numAfterLast = fPart/base;
    }

    if (numAfterLast >= 5) lastNum++;
    fTemp = itoa(lastNum);
    strcat(result, fTemp);
}

/*------------------------------------------------------------------------
| Converting string to 64 bit floating point 
| code logic from: 
| https://codereview.stackexchange.com/questions/158519/c-program-to-convert-string-to-floating-point
*------------------------------------------------------------------------*/
float64_t str_to_f64(const char *s)
{
    float64_t zero;
    float64_t one;
    float64_t ten;

    float64_t result;
    float64_t power;
    float64_t power2;/*The number following the E*/
    float64_t value;
    float64_t char_val;

    float64_t sign;
    int sign_val;

    float64_t powersign;
    int powersign_val; /*The sign following the E*/

    float64_t nan;
    
    int i;

    nan.v = defaultNaNF64UI;
    zero = i64_to_f64(0);
    one = i64_to_f64(1);
    ten = i64_to_f64(10);

    i = 0;
    sign_val = (s[i] == '-')? -1 : 1; /*The sign of the number*/
    sign = i64_to_f64(sign_val);

    if(s[i] == '-' || s[i] == '+')
    {
        ++i;
    }

    value = zero;
    for(; isdigit(s[i]); ++i)
    {
        char_val = i64_to_f64(s[i] - '0');
        value = f64_add(f64_mul(value, ten), char_val) ;
    }

    if(s[i] == '.')
    {
        ++i;
    }

    power = one;
    for(; isdigit(s[i]); ++i)
    {
	char_val = i64_to_f64(s[i] - '0');
        value = f64_add(f64_mul(value, ten), char_val);
        power = f64_mul(power, ten);
    }

    if(s[i] == 'e' || s[i] == 'E')
    {
        ++i;

        powersign_val = (s[i] == '-')? -1 : 1;
        powersign = i64_to_f64(powersign_val);

        if(s[i] == '-' || s[i] == '+')
          ++i;

        power2 = zero;
        for(; isdigit(s[i]); ++i)
          {
            char_val = i64_to_f64(s[i] - '0');
            power2 = f64_add(f64_mul(power2, ten), char_val);
          }

        if(powersign_val == -1)
          {
            while(f64_eq(power2, zero) == 0)
              {
                power = f64_mul(power, ten);
                power2 = f64_sub(power2, one); 
              }
          }
        else{
          while(f64_eq(power2, zero) == 0)
            {
              power = f64_div(power, ten);
              power2 = f64_sub(power2, one);
            }
        }
    }

    if(s[i] == '\0')
        return f64_mul(sign, f64_div(value, power));
    else
	return nan;
}

/*------------------------------------------------------------------------
| float64_t arithmetic helper functions
*------------------------------------------------------------------------*/
#ifndef softfloat_subM

void
 softfloat_subM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint_fast8_t borrow;
    uint32_t wordA, wordB;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    borrow = 0;
    for (;;) {
        wordA = aPtr[index];
        wordB = bPtr[index];
        zPtr[index] = wordA - wordB - borrow;
        if ( index == lastIndex ) break;
        borrow = borrow ? (wordA <= wordB) : (wordA < wordB);
        index += wordIncr;
    }
}

#endif

#ifndef softfloat_shortShiftRightM

void
 softfloat_shortShiftRightM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 )
{
    uint_fast8_t uNegDist;
    unsigned int index, lastIndex;
    uint32_t partWordZ, wordA;

    uNegDist = -dist;
    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    partWordZ = aPtr[index]>>dist;
    while ( index != lastIndex ) {
        wordA = aPtr[index + wordIncr];
        zPtr[index] = wordA<<(uNegDist & 31) | partWordZ;
        index += wordIncr;
        partWordZ = wordA>>dist;
    }
    zPtr[index] = partWordZ;
}

#endif

#ifndef softfloat_shortShiftLeftM

void
 softfloat_shortShiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 )
{
    uint_fast8_t uNegDist;
    unsigned int index, lastIndex;
    uint32_t partWordZ, wordA;

    uNegDist = -dist;
    index = indexWordHi( size_words );
    lastIndex = indexWordLo( size_words );
    partWordZ = aPtr[index]<<dist;
    while ( index != lastIndex ) {
        wordA = aPtr[index - wordIncr];
        zPtr[index] = partWordZ | wordA>>(uNegDist & 31);
        index -= wordIncr;
        partWordZ = wordA<<dist;
    }
    zPtr[index] = partWordZ;
}

#endif

#ifndef softfloat_shiftLeftM

#define softfloat_shiftLeftM softfloat_shiftLeftM

void
 softfloat_shiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 )
{
    uint32_t wordDist;
    uint_fast8_t innerDist;
    uint32_t *destPtr;
    uint_fast8_t i;

    wordDist = dist>>5;
    if ( wordDist < size_words ) {
        aPtr += indexMultiwordLoBut( size_words, wordDist );
        innerDist = dist & 31;
        if ( innerDist ) {
            softfloat_shortShiftLeftM(
                size_words - wordDist,
                aPtr,
                innerDist,
                zPtr + indexMultiwordHiBut( size_words, wordDist )
            );
            if ( ! wordDist ) return;
        } else {
            aPtr += indexWordHi( size_words - wordDist );
            destPtr = zPtr + indexWordHi( size_words );
            for ( i = size_words - wordDist; i; --i ) {
                *destPtr = *aPtr;
                aPtr -= wordIncr;
                destPtr -= wordIncr;
            }
        }
        zPtr += indexMultiwordLo( size_words, wordDist );
    } else {
        wordDist = size_words;
    }
    do {
        *zPtr++ = 0;
        --wordDist;
    } while ( wordDist );
}

#endif

#ifndef softfloat_negXM

void softfloat_negXM( uint_fast8_t size_words, uint32_t *zPtr )
{
    unsigned int index, lastIndex;
    uint_fast8_t carry;
    uint32_t word;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    carry = 1;
    for (;;) {
        word = ~zPtr[index] + carry;
        zPtr[index] = word;
        if ( index == lastIndex ) break;
        index += wordIncr;
        if ( word ) carry = 0;
    }
}

#endif

const uint16_t softfloat_approxRecipSqrt_1k0s[16] = {
    0xB4C9, 0xFFAB, 0xAA7D, 0xF11C, 0xA1C5, 0xE4C7, 0x9A43, 0xDA29,
    0x93B5, 0xD0E5, 0x8DED, 0xC8B7, 0x88C6, 0xC16D, 0x8424, 0xBAE1
};
const uint16_t softfloat_approxRecipSqrt_1k1s[16] = {
    0xA5A5, 0xEA42, 0x8C21, 0xC62D, 0x788F, 0xAA7F, 0x6928, 0x94B6,
    0x5CC7, 0x8335, 0x52A6, 0x74E2, 0x4A3E, 0x68FE, 0x432B, 0x5EFD
};

const uint16_t softfloat_approxRecip_1k0s[16] = {
    0xFFC4, 0xF0BE, 0xE363, 0xD76F, 0xCCAD, 0xC2F0, 0xBA16, 0xB201,
    0xAA97, 0xA3C6, 0x9D7A, 0x97A6, 0x923C, 0x8D32, 0x887E, 0x8417
};
const uint16_t softfloat_approxRecip_1k1s[16] = {
    0xF0F1, 0xD62C, 0xBFA1, 0xAC77, 0x9C0A, 0x8DDB, 0x8185, 0x76BA,
    0x6D3B, 0x64D4, 0x5D5C, 0x56B1, 0x50B6, 0x4B55, 0x4679, 0x4211
};



#ifdef SOFTFLOAT_FAST_INT64

float64_t
 softfloat_mulAddF64(
     uint_fast64_t uiA, uint_fast64_t uiB, uint_fast64_t uiC, uint_fast8_t op )
{
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    bool signB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    bool signC;
    int_fast16_t expC;
    uint_fast64_t sigC;
    bool signZ;
    uint_fast64_t magBits, uiZ;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
    struct uint128 sig128Z;
    uint_fast64_t sigZ;
    int_fast16_t expDiff;
    struct uint128 sig128C;
    int_fast8_t shiftDist;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    signB = signF64UI( uiB );
    expB  = expF64UI( uiB );
    sigB  = fracF64UI( uiB );
    signC = signF64UI( uiC ) ^ (op == softfloat_mulAdd_subC);
    expC  = expF64UI( uiC );
    sigC  = fracF64UI( uiC );
    signZ = signA ^ signB ^ (op == softfloat_mulAdd_subProd);
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA || ((expB == 0x7FF) && sigB) ) goto propagateNaN_ABC;
        magBits = expB | sigB;
        goto infProdArg;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN_ABC;
        magBits = expA | sigA;
        goto infProdArg;
    }
    if ( expC == 0x7FF ) {
        if ( sigC ) {
            uiZ = 0;
            goto propagateNaN_ZC;
        }
        uiZ = uiC;
        goto uiZ;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expA ) {
        if ( ! sigA ) goto zeroProd;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    if ( ! expB ) {
        if ( ! sigB ) goto zeroProd;
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expZ = expA + expB - 0x3FE;
    sigA = (sigA | UINT64_C( 0x0010000000000000 ))<<10;
    sigB = (sigB | UINT64_C( 0x0010000000000000 ))<<10;
    sig128Z = softfloat_mul64To128( sigA, sigB );
    if ( sig128Z.v64 < UINT64_C( 0x2000000000000000 ) ) {
        --expZ;
        sig128Z =
            softfloat_add128(
                sig128Z.v64, sig128Z.v0, sig128Z.v64, sig128Z.v0 );
    }
    if ( ! expC ) {
        if ( ! sigC ) {
            --expZ;
            sigZ = sig128Z.v64<<1 | (sig128Z.v0 != 0);
            goto roundPack;
        }
        normExpSig = softfloat_normSubnormalF64Sig( sigC );
        expC = normExpSig.exp;
        sigC = normExpSig.sig;
    }
    sigC = (sigC | UINT64_C( 0x0010000000000000 ))<<9;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expDiff = expZ - expC;
    if ( expDiff < 0 ) {
        expZ = expC;
        if ( (signZ == signC) || (expDiff < -1) ) {
            sig128Z.v64 = softfloat_shiftRightJam64( sig128Z.v64, -expDiff );
        } else {
            sig128Z =
                softfloat_shortShiftRightJam128( sig128Z.v64, sig128Z.v0, 1 );
        }
    } else if ( expDiff ) {
        sig128C = softfloat_shiftRightJam128( sigC, 0, expDiff );
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( signZ == signC ) {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( expDiff <= 0 ) {
            sigZ = (sigC + sig128Z.v64) | (sig128Z.v0 != 0);
        } else {
            sig128Z =
                softfloat_add128(
                    sig128Z.v64, sig128Z.v0, sig128C.v64, sig128C.v0 );
            sigZ = sig128Z.v64 | (sig128Z.v0 != 0);
        }
        if ( sigZ < UINT64_C( 0x4000000000000000 ) ) {
            --expZ;
            sigZ <<= 1;
        }
    } else {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( expDiff < 0 ) {
            signZ = signC;
            sig128Z = softfloat_sub128( sigC, 0, sig128Z.v64, sig128Z.v0 );
        } else if ( ! expDiff ) {
            sig128Z.v64 = sig128Z.v64 - sigC;
            if ( ! (sig128Z.v64 | sig128Z.v0) ) goto completeCancellation;
            if ( sig128Z.v64 & UINT64_C( 0x8000000000000000 ) ) {
                signZ = ! signZ;
                sig128Z = softfloat_sub128( 0, 0, sig128Z.v64, sig128Z.v0 );
            }
        } else {
            sig128Z =
                softfloat_sub128(
                    sig128Z.v64, sig128Z.v0, sig128C.v64, sig128C.v0 );
        }
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( ! sig128Z.v64 ) {
            expZ -= 64;
            sig128Z.v64 = sig128Z.v0;
            sig128Z.v0 = 0;
        }
        shiftDist = softfloat_countLeadingZeros64( sig128Z.v64 ) - 1;
        expZ -= shiftDist;
        if ( shiftDist < 0 ) {
            sigZ = softfloat_shortShiftRightJam64( sig128Z.v64, -shiftDist );
        } else {
            sig128Z =
                softfloat_shortShiftLeft128(
                    sig128Z.v64, sig128Z.v0, shiftDist );
            sigZ = sig128Z.v64;
        }
        sigZ |= (sig128Z.v0 != 0);
    }
 roundPack:
    return softfloat_roundPackToF64( signZ, expZ, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN_ABC:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto propagateNaN_ZC;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 infProdArg:
    if ( magBits ) {
        uiZ = packToF64UI( signZ, 0x7FF, 0 );
        if ( expC != 0x7FF ) goto uiZ;
        if ( sigC ) goto propagateNaN_ZC;
        if ( signZ == signC ) goto uiZ;
    }
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 propagateNaN_ZC:
    uiZ = softfloat_propagateNaNF64UI( uiZ, uiC );
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 zeroProd:
    uiZ = uiC;
    if ( ! (expC | sigC) && (signZ != signC) ) {
 completeCancellation:
        uiZ =
            packToF64UI(
                (softfloat_roundingMode == softfloat_round_min), 0, 0 );
    }
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

#else

float64_t
 softfloat_mulAddF64(
     uint_fast64_t uiA, uint_fast64_t uiB, uint_fast64_t uiC, uint_fast8_t op )
{
    bool signA;
    int_fast16_t expA;
    uint64_t sigA;
    bool signB;
    int_fast16_t expB;
    uint64_t sigB;
    bool signC;
    int_fast16_t expC;
    uint64_t sigC;
    bool signZ;
    uint64_t magBits, uiZ;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
    uint32_t sig128Z[4];
    uint64_t sigZ;
    int_fast16_t shiftDist, expDiff;
    uint32_t sig128C[4];
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    signB = signF64UI( uiB );
    expB  = expF64UI( uiB );
    sigB  = fracF64UI( uiB );
    signC = signF64UI( uiC ) ^ (op == softfloat_mulAdd_subC);
    expC  = expF64UI( uiC );
    sigC  = fracF64UI( uiC );
    signZ = signA ^ signB ^ (op == softfloat_mulAdd_subProd);
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA || ((expB == 0x7FF) && sigB) ) goto propagateNaN_ABC;
        magBits = expB | sigB;
        goto infProdArg;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN_ABC;
        magBits = expA | sigA;
        goto infProdArg;
    }
    if ( expC == 0x7FF ) {
        if ( sigC ) {
            uiZ = 0;
            goto propagateNaN_ZC;
        }
        uiZ = uiC;
        goto uiZ;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expA ) {
        if ( ! sigA ) goto zeroProd;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    if ( ! expB ) {
        if ( ! sigB ) goto zeroProd;
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expZ = expA + expB - 0x3FE;
    sigA = (sigA | UINT64_C( 0x0010000000000000 ))<<10;
    sigB = (sigB | UINT64_C( 0x0010000000000000 ))<<11;
    softfloat_mul64To128M( sigA, sigB, sig128Z );
    sigZ =
        (uint64_t) sig128Z[indexWord( 4, 3 )]<<32 | sig128Z[indexWord( 4, 2 )];
    shiftDist = 0;
    if ( ! (sigZ & UINT64_C( 0x4000000000000000 )) ) {
        --expZ;
        shiftDist = -1;
    }
    if ( ! expC ) {
        if ( ! sigC ) {
            if ( shiftDist ) sigZ <<= 1;
            goto sigZ;
        }
        normExpSig = softfloat_normSubnormalF64Sig( sigC );
        expC = normExpSig.exp;
        sigC = normExpSig.sig;
    }
    sigC = (sigC | UINT64_C( 0x0010000000000000 ))<<10;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expDiff = expZ - expC;
    if ( expDiff < 0 ) {
        expZ = expC;
        if ( (signZ == signC) || (expDiff < -1) ) {
            shiftDist -= expDiff;
            if ( shiftDist) {
                sigZ = softfloat_shiftRightJam64( sigZ, shiftDist );
            }
        } else {
            if ( ! shiftDist ) {
                softfloat_shortShiftRight128M( sig128Z, 1, sig128Z );
            }
        }
    } else {
        if ( shiftDist ) softfloat_add128M( sig128Z, sig128Z, sig128Z );
        if ( ! expDiff ) {
            sigZ =
                (uint64_t) sig128Z[indexWord( 4, 3 )]<<32
                    | sig128Z[indexWord( 4, 2 )];
        } else {
            sig128C[indexWord( 4, 3 )] = sigC>>32;
            sig128C[indexWord( 4, 2 )] = sigC;
            sig128C[indexWord( 4, 1 )] = 0;
            sig128C[indexWord( 4, 0 )] = 0;
            softfloat_shiftRightJam128M( sig128C, expDiff, sig128C );
        }
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( signZ == signC ) {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( expDiff <= 0 ) {
            sigZ += sigC;
        } else {
            softfloat_add128M( sig128Z, sig128C, sig128Z );
            sigZ =
                (uint64_t) sig128Z[indexWord( 4, 3 )]<<32
                    | sig128Z[indexWord( 4, 2 )];
        }
        if ( sigZ & UINT64_C( 0x8000000000000000 ) ) {
            ++expZ;
            sigZ = softfloat_shortShiftRightJam64( sigZ, 1 );
        }
    } else {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( expDiff < 0 ) {
            signZ = signC;
            if ( expDiff < -1 ) {
                sigZ = sigC - sigZ;
                if (
                    sig128Z[indexWord( 4, 1 )] || sig128Z[indexWord( 4, 0 )]
                ) {
                    sigZ = (sigZ - 1) | 1;
                }
                if ( ! (sigZ & UINT64_C( 0x4000000000000000 )) ) {
                    --expZ;
                    sigZ <<= 1;
                }
                goto roundPack;
            } else {
                sig128C[indexWord( 4, 3 )] = sigC>>32;
                sig128C[indexWord( 4, 2 )] = sigC;
                sig128C[indexWord( 4, 1 )] = 0;
                sig128C[indexWord( 4, 0 )] = 0;
                softfloat_sub128M( sig128C, sig128Z, sig128Z );
            }
        } else if ( ! expDiff ) {
            sigZ -= sigC;
            if (
                ! sigZ && ! sig128Z[indexWord( 4, 1 )]
                    && ! sig128Z[indexWord( 4, 0 )]
            ) {
                goto completeCancellation;
            }
            sig128Z[indexWord( 4, 3 )] = sigZ>>32;
            sig128Z[indexWord( 4, 2 )] = sigZ;
            if ( sigZ & UINT64_C( 0x8000000000000000 ) ) {
                signZ = ! signZ;
                softfloat_negX128M( sig128Z );
            }
        } else {
            softfloat_sub128M( sig128Z, sig128C, sig128Z );
            if ( 1 < expDiff ) {
                sigZ =
                    (uint64_t) sig128Z[indexWord( 4, 3 )]<<32
                        | sig128Z[indexWord( 4, 2 )];
                if ( ! (sigZ & UINT64_C( 0x4000000000000000 )) ) {
                    --expZ;
                    sigZ <<= 1;
                }
                goto sigZ;
            }
        }
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        shiftDist = 0;
        sigZ =
            (uint64_t) sig128Z[indexWord( 4, 3 )]<<32
                | sig128Z[indexWord( 4, 2 )];
        if ( ! sigZ ) {
            shiftDist = 64;
            sigZ =
                (uint64_t) sig128Z[indexWord( 4, 1 )]<<32
                    | sig128Z[indexWord( 4, 0 )];
        }
        shiftDist += softfloat_countLeadingZeros64( sigZ ) - 1;
        if ( shiftDist ) {
            expZ -= shiftDist;
            softfloat_shiftLeft128M( sig128Z, shiftDist, sig128Z );
            sigZ =
                (uint64_t) sig128Z[indexWord( 4, 3 )]<<32
                    | sig128Z[indexWord( 4, 2 )];
        }
    }
 sigZ:
    if ( sig128Z[indexWord( 4, 1 )] || sig128Z[indexWord( 4, 0 )] ) sigZ |= 1;
 roundPack:
    return softfloat_roundPackToF64( signZ, expZ - 1, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN_ABC:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto propagateNaN_ZC;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 infProdArg:
    if ( magBits ) {
        uiZ = packToF64UI( signZ, 0x7FF, 0 );
        if ( expC != 0x7FF ) goto uiZ;
        if ( sigC ) goto propagateNaN_ZC;
        if ( signZ == signC ) goto uiZ;
    }
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 propagateNaN_ZC:
    uiZ = softfloat_propagateNaNF64UI( uiZ, uiC );
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 zeroProd:
    uiZ = uiC;
    if ( ! (expC | sigC) && (signZ != signC) ) {
 completeCancellation:
        uiZ =
            packToF64UI(
                (softfloat_roundingMode == softfloat_round_min), 0, 0 );
    }
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

#endif

#ifndef softfloat_addM

void
 softfloat_addM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint_fast8_t carry;
    uint32_t wordA, wordZ;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    carry = 0;
    for (;;) {
        wordA = aPtr[index];
        wordZ = wordA + bPtr[index] + carry;
        zPtr[index] = wordZ;
        if ( index == lastIndex ) break;
        if ( wordZ != wordA ) carry = (wordZ < wordA);
        index += wordIncr;
    }
}

#endif

float64_t
 softfloat_addMagsF64( uint_fast64_t uiA, uint_fast64_t uiB, bool signZ )
{
    int_fast16_t expA;
    uint_fast64_t sigA;
    int_fast16_t expB;
    uint_fast64_t sigB;
    int_fast16_t expDiff;
    uint_fast64_t uiZ;
    int_fast16_t expZ;
    uint_fast64_t sigZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expA = expF64UI( uiA );
    sigA = fracF64UI( uiA );
    expB = expF64UI( uiB );
    sigB = fracF64UI( uiB );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expDiff = expA - expB;
    if ( ! expDiff ) {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( ! expA ) {
            uiZ = uiA + sigB;
            goto uiZ;
        }
        if ( expA == 0x7FF ) {
            if ( sigA | sigB ) goto propagateNaN;
            uiZ = uiA;
            goto uiZ;
        }
        expZ = expA;
        sigZ = UINT64_C( 0x0020000000000000 ) + sigA + sigB;
        sigZ <<= 9;
    } else {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        sigA <<= 9;
        sigB <<= 9;
        if ( expDiff < 0 ) {
            if ( expB == 0x7FF ) {
                if ( sigB ) goto propagateNaN;
                uiZ = packToF64UI( signZ, 0x7FF, 0 );
                goto uiZ;
            }
            expZ = expB;
            if ( expA ) {
                sigA += UINT64_C( 0x2000000000000000 );
            } else {
                sigA <<= 1;
            }
            sigA = softfloat_shiftRightJam64( sigA, -expDiff );
        } else {
            if ( expA == 0x7FF ) {
                if ( sigA ) goto propagateNaN;
                uiZ = uiA;
                goto uiZ;
            }
            expZ = expA;
            if ( expB ) {
                sigB += UINT64_C( 0x2000000000000000 );
            } else {
                sigB <<= 1;
            }
            sigB = softfloat_shiftRightJam64( sigB, expDiff );
        }
        sigZ = UINT64_C( 0x2000000000000000 ) + sigA + sigB;
        if ( sigZ < UINT64_C( 0x4000000000000000 ) ) {
            --expZ;
            sigZ <<= 1;
        }
    }
    return softfloat_roundPackToF64( signZ, expZ, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

float64_t
 softfloat_subMagsF64( uint_fast64_t uiA, uint_fast64_t uiB, bool signZ )
{
    int_fast16_t expA;
    uint_fast64_t sigA;
    int_fast16_t expB;
    uint_fast64_t sigB;
    int_fast16_t expDiff;
    uint_fast64_t uiZ;
    int_fast64_t sigDiff;
    int_fast8_t shiftDist;
    int_fast16_t expZ;
    uint_fast64_t sigZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expA = expF64UI( uiA );
    sigA = fracF64UI( uiA );
    expB = expF64UI( uiB );
    sigB = fracF64UI( uiB );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expDiff = expA - expB;
    if ( ! expDiff ) {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        if ( expA == 0x7FF ) {
            if ( sigA | sigB ) goto propagateNaN;
            softfloat_raiseFlags( softfloat_flag_invalid );
            uiZ = defaultNaNF64UI;
            goto uiZ;
        }
        sigDiff = sigA - sigB;
        if ( ! sigDiff ) {
            uiZ =
                packToF64UI(
                    (softfloat_roundingMode == softfloat_round_min), 0, 0 );
            goto uiZ;
        }
        if ( expA ) --expA;
        if ( sigDiff < 0 ) {
            signZ = ! signZ;
            sigDiff = -sigDiff;
        }
        shiftDist = softfloat_countLeadingZeros64( sigDiff ) - 11;
        expZ = expA - shiftDist;
        if ( expZ < 0 ) {
            shiftDist = expA;
            expZ = 0;
        }
        uiZ = packToF64UI( signZ, expZ, sigDiff<<shiftDist );
        goto uiZ;
    } else {
        /*--------------------------------------------------------------------
        *--------------------------------------------------------------------*/
        sigA <<= 10;
        sigB <<= 10;
        if ( expDiff < 0 ) {
            /*----------------------------------------------------------------
            *----------------------------------------------------------------*/
            signZ = ! signZ;
            if ( expB == 0x7FF ) {
                if ( sigB ) goto propagateNaN;
                uiZ = packToF64UI( signZ, 0x7FF, 0 );
                goto uiZ;
            }
            sigA += expA ? UINT64_C( 0x4000000000000000 ) : sigA;
            sigA = softfloat_shiftRightJam64( sigA, -expDiff );
            sigB |= UINT64_C( 0x4000000000000000 );
            expZ = expB;
            sigZ = sigB - sigA;
        } else {
            /*----------------------------------------------------------------
            *----------------------------------------------------------------*/
            if ( expA == 0x7FF ) {
                if ( sigA ) goto propagateNaN;
                uiZ = uiA;
                goto uiZ;
            }
            sigB += expB ? UINT64_C( 0x4000000000000000 ) : sigB;
            sigB = softfloat_shiftRightJam64( sigB, expDiff );
            sigA |= UINT64_C( 0x4000000000000000 );
            expZ = expA;
            sigZ = sigA - sigB;
        }
        return softfloat_normRoundPackToF64( signZ, expZ - 1, sigZ );
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

#ifndef softfloat_approxRecip32_1

uint32_t softfloat_approxRecip32_1( uint32_t a )
{
    int index;
    uint16_t eps, r0;
    uint32_t sigma0;
    uint_fast32_t r;
    uint32_t sqrSigma0;

    index = a>>27 & 0xF;
    eps = (uint16_t) (a>>11);
    r0 = softfloat_approxRecip_1k0s[index]
             - ((softfloat_approxRecip_1k1s[index] * (uint_fast32_t) eps)>>20);
    sigma0 = ~(uint_fast32_t) ((r0 * (uint_fast64_t) a)>>7);
    r = ((uint_fast32_t) r0<<16) + ((r0 * (uint_fast64_t) sigma0)>>24);
    sqrSigma0 = ((uint_fast64_t) sigma0 * sigma0)>>32;
    r += ((uint32_t) r * (uint_fast64_t) sqrSigma0)>>48;
    return r;
}

#endif

#ifndef softfloat_approxRecipSqrt32_1

uint32_t softfloat_approxRecipSqrt32_1( unsigned int oddExpA, uint32_t a )
{
    int index;
    uint16_t eps, r0;
    uint_fast32_t ESqrR0;
    uint32_t sigma0;
    uint_fast32_t r;
    uint32_t sqrSigma0;

    index = (a>>27 & 0xE) + oddExpA;
    eps = (uint16_t) (a>>12);
    r0 = softfloat_approxRecipSqrt_1k0s[index]
             - ((softfloat_approxRecipSqrt_1k1s[index] * (uint_fast32_t) eps)
                    >>20);
    ESqrR0 = (uint_fast32_t) r0 * r0;
    if ( ! oddExpA ) ESqrR0 <<= 1;
    sigma0 = ~(uint_fast32_t) (((uint32_t) ESqrR0 * (uint_fast64_t) a)>>23);
    r = ((uint_fast32_t) r0<<16) + ((r0 * (uint_fast64_t) sigma0)>>25);
    sqrSigma0 = ((uint_fast64_t) sigma0 * sigma0)>>32;
    r += ((uint32_t) ((r>>1) + (r>>3) - ((uint_fast32_t) r0<<14))
              * (uint_fast64_t) sqrSigma0)
             >>48;
    if ( ! (r & 0x80000000) ) r = 0x80000000;
    return r;
}

#endif

#ifndef softfloat_mul64To128M

void softfloat_mul64To128M( uint64_t a, uint64_t b, uint32_t *zPtr )
{
    uint32_t a32, a0, b32, b0;
    uint64_t z0, mid1, z64, mid;

    a32 = a>>32;
    a0 = a;
    b32 = b>>32;
    b0 = b;
    z0 = (uint64_t) a0 * b0;
    mid1 = (uint64_t) a32 * b0;
    mid = mid1 + (uint64_t) a0 * b32;
    z64 = (uint64_t) a32 * b32;
    z64 += (uint64_t) (mid < mid1)<<32 | mid>>32;
    mid <<= 32;
    z0 += mid;
    zPtr[indexWord( 4, 1 )] = z0>>32;
    zPtr[indexWord( 4, 0 )] = z0;
    z64 += (z0 < mid);
    zPtr[indexWord( 4, 3 )] = z64>>32;
    zPtr[indexWord( 4, 2 )] = z64;
}

#endif

struct exp16_sig64 softfloat_normSubnormalF64Sig( uint_fast64_t sig )
{
    int_fast8_t shiftDist;
    struct exp16_sig64 z;

    shiftDist = softfloat_countLeadingZeros64( sig ) - 11;
    z.exp = 1 - shiftDist;
    z.sig = sig<<shiftDist;
    return z;
}

/*------------------------------------------------------------------------
| float64_t arithmetic
*------------------------------------------------------------------------*/

float64_t f64_add( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signB;
#if ! defined INLINE_LEVEL || (INLINE_LEVEL < 2)
    float64_t (*magsFuncPtr)( uint_fast64_t, uint_fast64_t, bool );
#endif

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF64UI( uiB );
#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
    if ( signA == signB ) {
        return softfloat_addMagsF64( uiA, uiB, signA );
    } else {
        return softfloat_subMagsF64( uiA, uiB, signA );
    }
#else
    magsFuncPtr =
        (signA == signB) ? softfloat_addMagsF64 : softfloat_subMagsF64;
    return (*magsFuncPtr)( uiA, uiB, signA );
#endif

}

float64_t f64_sub( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signB;
#if ! defined INLINE_LEVEL || (INLINE_LEVEL < 2)
    float64_t (*magsFuncPtr)( uint_fast64_t, uint_fast64_t, bool );
#endif

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF64UI( uiB );
#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
    if ( signA == signB ) {
        return softfloat_subMagsF64( uiA, uiB, signA );
    } else {
        return softfloat_addMagsF64( uiA, uiB, signA );
    }
#else
    magsFuncPtr =
        (signA == signB) ? softfloat_subMagsF64 : softfloat_addMagsF64;
    return (*magsFuncPtr)( uiA, uiB, signA );
#endif
}


float64_t f64_mul( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    bool signZ;
    uint_fast64_t magBits;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
#ifdef SOFTFLOAT_FAST_INT64
    struct uint128 sig128Z;
#else
    uint32_t sig128Z[4];
#endif
    uint_fast64_t sigZ, uiZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF64UI( uiB );
    expB  = expF64UI( uiB );
    sigB  = fracF64UI( uiB );
    signZ = signA ^ signB;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA || ((expB == 0x7FF) && sigB) ) goto propagateNaN;
        magBits = expB | sigB;
        goto infArg;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN;
        magBits = expA | sigA;
        goto infArg;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expA ) {
        if ( ! sigA ) goto zero;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    if ( ! expB ) {
        if ( ! sigB ) goto zero;
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expZ = expA + expB - 0x3FF;
    sigA = (sigA | UINT64_C( 0x0010000000000000 ))<<10;
    sigB = (sigB | UINT64_C( 0x0010000000000000 ))<<11;
#ifdef SOFTFLOAT_FAST_INT64
    sig128Z = softfloat_mul64To128( sigA, sigB );
    sigZ = sig128Z.v64 | (sig128Z.v0 != 0);
#else
    softfloat_mul64To128M( sigA, sigB, sig128Z );
    sigZ =
        (uint64_t) sig128Z[indexWord( 4, 3 )]<<32 | sig128Z[indexWord( 4, 2 )];
    if ( sig128Z[indexWord( 4, 1 )] || sig128Z[indexWord( 4, 0 )] ) sigZ |= 1;
#endif
    if ( sigZ < UINT64_C( 0x4000000000000000 ) ) {
        --expZ;
        sigZ <<= 1;
    }
    return softfloat_roundPackToF64( signZ, expZ, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 infArg:
    if ( ! magBits ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        uiZ = defaultNaNF64UI;
    } else {
        uiZ = packToF64UI( signZ, 0x7FF, 0 );
    }
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 zero:
    uiZ = packToF64UI( signZ, 0, 0 );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

float64_t f64_mulAdd( float64_t a, float64_t b, float64_t c )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    union ui64_f64 uC;
    uint_fast64_t uiC;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    uC.f = c;
    uiC = uC.ui;
    return softfloat_mulAddF64( uiA, uiB, uiC, 0 );
}

float64_t f64_div( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    bool signZ;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
    uint32_t recip32, sig32Z, doubleTerm;
    uint_fast64_t rem;
    uint32_t q;
    uint_fast64_t sigZ;
    uint_fast64_t uiZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF64UI( uiB );
    expB  = expF64UI( uiB );
    sigB  = fracF64UI( uiB );
    signZ = signA ^ signB;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA ) goto propagateNaN;
        if ( expB == 0x7FF ) {
            if ( sigB ) goto propagateNaN;
            goto invalid;
        }
        goto infinity;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN;
        goto zero;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expB ) {
        if ( ! sigB ) {
            if ( ! (expA | sigA) ) goto invalid;
            softfloat_raiseFlags( softfloat_flag_infinite );
            goto infinity;
        }
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if ( ! expA ) {
        if ( ! sigA ) goto zero;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    expZ = expA - expB + 0x3FE;
    sigA |= UINT64_C( 0x0010000000000000 );
    sigB |= UINT64_C( 0x0010000000000000 );
    if ( sigA < sigB ) {
        --expZ;
        sigA <<= 11;
    } else {
        sigA <<= 10;
    }
    sigB <<= 11;
    recip32 = softfloat_approxRecip32_1( sigB>>32 ) - 2;
    sig32Z = ((uint32_t) (sigA>>32) * (uint_fast64_t) recip32)>>32;
    doubleTerm = sig32Z<<1;
    rem =
        ((sigA - (uint_fast64_t) doubleTerm * (uint32_t) (sigB>>32))<<28)
            - (uint_fast64_t) doubleTerm * ((uint32_t) sigB>>4);
    q = (((uint32_t) (rem>>32) * (uint_fast64_t) recip32)>>32) + 4;
    sigZ = ((uint_fast64_t) sig32Z<<32) + ((uint_fast64_t) q<<4);
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( (sigZ & 0x1FF) < 4<<4 ) {
        q &= ~7;
        sigZ &= ~(uint_fast64_t) 0x7F;
        doubleTerm = q<<1;
        rem =
            ((rem - (uint_fast64_t) doubleTerm * (uint32_t) (sigB>>32))<<28)
                - (uint_fast64_t) doubleTerm * ((uint32_t) sigB>>4);
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            sigZ -= 1<<7;
        } else {
            if ( rem ) sigZ |= 1;
        }
    }
    return softfloat_roundPackToF64( signZ, expZ, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 infinity:
    uiZ = packToF64UI( signZ, 0x7FF, 0 );
    goto uiZ;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 zero:
    uiZ = packToF64UI( signZ, 0, 0 );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}


float64_t f64_rem( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    struct exp16_sig64 normExpSig;
    uint64_t rem;
    int_fast16_t expDiff;
    uint32_t q, recip32;
    uint_fast64_t q64;
    uint64_t altRem, meanRem;
    bool signRem;
    uint_fast64_t uiZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    expB = expF64UI( uiB );
    sigB = fracF64UI( uiB );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA || ((expB == 0x7FF) && sigB) ) goto propagateNaN;
        goto invalid;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN;
        return a;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA < expB - 1 ) return a;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expB ) {
        if ( ! sigB ) goto invalid;
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if ( ! expA ) {
        if ( ! sigA ) return a;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    rem = sigA | UINT64_C( 0x0010000000000000 );
    sigB |= UINT64_C( 0x0010000000000000 );
    expDiff = expA - expB;
    if ( expDiff < 1 ) {
        if ( expDiff < -1 ) return a;
        sigB <<= 9;
        if ( expDiff ) {
            rem <<= 8;
            q = 0;
        } else {
            rem <<= 9;
            q = (sigB <= rem);
            if ( q ) rem -= sigB;
        }
    } else {
        recip32 = softfloat_approxRecip32_1( sigB>>21 );
        /*--------------------------------------------------------------------
        | Changing the shift of `rem' here requires also changing the initial
        | subtraction from `expDiff'.
        *--------------------------------------------------------------------*/
        rem <<= 9;
        expDiff -= 30;
        /*--------------------------------------------------------------------
        | The scale of `sigB' affects how many bits are obtained during each
        | cycle of the loop.  Currently this is 29 bits per loop iteration,
        | the maximum possible.
        *--------------------------------------------------------------------*/
        sigB <<= 9;
        for (;;) {
            q64 = (uint32_t) (rem>>32) * (uint_fast64_t) recip32;
            if ( expDiff < 0 ) break;
            q = (q64 + 0x80000000)>>32;
#ifdef SOFTFLOAT_FAST_INT64
            rem <<= 29;
#else
            rem = (uint_fast64_t) (uint32_t) (rem>>3)<<32;
#endif
            rem -= q * (uint64_t) sigB;
            if ( rem & UINT64_C( 0x8000000000000000 ) ) rem += sigB;
            expDiff -= 29;
        }
        /*--------------------------------------------------------------------
        | (`expDiff' cannot be less than -29 here.)
        *--------------------------------------------------------------------*/
        q = (uint32_t) (q64>>32)>>(~expDiff & 31);
        rem = (rem<<(expDiff + 30)) - q * (uint64_t) sigB;
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            altRem = rem + sigB;
            goto selectRem;
        }
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    do {
        altRem = rem;
        ++q;
        rem -= sigB;
    } while ( ! (rem & UINT64_C( 0x8000000000000000 )) );
 selectRem:
    meanRem = rem + altRem;
    if (
        (meanRem & UINT64_C( 0x8000000000000000 )) || (! meanRem && (q & 1))
    ) {
        rem = altRem;
    }
    signRem = signA;
    if ( rem & UINT64_C( 0x8000000000000000 ) ) {
        signRem = ! signRem;
        rem = -rem;
    }
    return softfloat_normRoundPackToF64( signRem, expB, rem );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto uiZ;
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}



float64_t f64_sqrt( float64_t a )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA, uiZ;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
    uint32_t sig32A, recipSqrt32, sig32Z;
    uint_fast64_t rem;
    uint32_t q;
    uint_fast64_t sigZ, shiftedSigZ;
    union ui64_f64 uZ;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( expA == 0x7FF ) {
        if ( sigA ) {
            uiZ = softfloat_propagateNaNF64UI( uiA, 0 );
            goto uiZ;
        }
        if ( ! signA ) return a;
        goto invalid;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( signA ) {
        if ( ! (expA | sigA) ) return a;
        goto invalid;
    }
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( ! expA ) {
        if ( ! sigA ) return a;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    /*------------------------------------------------------------------------
    | (`sig32Z' is guaranteed to be a lower bound on the square root of
    | `sig32A', which makes `sig32Z' also a lower bound on the square root of
    | `sigA'.)
    *------------------------------------------------------------------------*/
    expZ = ((expA - 0x3FF)>>1) + 0x3FE;
    expA &= 1;
    sigA |= UINT64_C( 0x0010000000000000 );
    sig32A = sigA>>21;
    recipSqrt32 = softfloat_approxRecipSqrt32_1( expA, sig32A );
    sig32Z = ((uint_fast64_t) sig32A * recipSqrt32)>>32;
    if ( expA ) {
        sigA <<= 8;
        sig32Z >>= 1;
    } else {
        sigA <<= 9;
    }
    rem = sigA - (uint_fast64_t) sig32Z * sig32Z;
    q = ((uint32_t) (rem>>2) * (uint_fast64_t) recipSqrt32)>>32;
    sigZ = ((uint_fast64_t) sig32Z<<32 | 1<<5) + ((uint_fast64_t) q<<3);
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( (sigZ & 0x1FF) < 0x22 ) {
        sigZ &= ~(uint_fast64_t) 0x3F;
        shiftedSigZ = sigZ>>6;
        rem = (sigA<<52) - shiftedSigZ * shiftedSigZ;
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            --sigZ;
        } else {
            if ( rem ) sigZ |= 1;
        }
    }
    return softfloat_roundPackToF64( 0, expZ, sigZ );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;
}

/*------------------------------------------------------------------------
| float64_t comparison funcions
*------------------------------------------------------------------------*/

bool f64_eq( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF64UI( uiA ) || isNaNF64UI( uiB ) ) {
        if (
            softfloat_isSigNaNF64UI( uiA ) || softfloat_isSigNaNF64UI( uiB )
        ) {
            softfloat_raiseFlags( softfloat_flag_invalid );
        }
        return false;
    }
    return (uiA == uiB) || ! ((uiA | uiB) & UINT64_C( 0x7FFFFFFFFFFFFFFF ));
}

/*less than or equal to*/
bool f64_le( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signA, signB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF64UI( uiA ) || isNaNF64UI( uiB ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return false;
    }
    signA = signF64UI( uiA );
    signB = signF64UI( uiB );
    return
        (signA != signB)
            ? signA || ! ((uiA | uiB) & UINT64_C( 0x7FFFFFFFFFFFFFFF ))
            : (uiA == uiB) || (signA ^ (uiA < uiB));
}

/*less than*/
bool f64_lt( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signA, signB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF64UI( uiA ) || isNaNF64UI( uiB ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return false;
    }
    signA = signF64UI( uiA );
    signB = signF64UI( uiB );
    return
        (signA != signB)
            ? signA && ((uiA | uiB) & UINT64_C( 0x7FFFFFFFFFFFFFFF ))
            : (uiA != uiB) && (signA ^ (uiA < uiB));
}
