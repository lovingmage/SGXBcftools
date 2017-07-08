/*
 * INTEL CONFIDENTIAL
 *
 * Copyright 2015 2016 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the source code ("Material") are owned
 * by Intel Corporation or its suppliers or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material may contain trade secrets and proprietary and confidential information of
 * Intel Corporation and its suppliers and licensors, and is protected by worldwide copyright and trade secret laws
 * and treaty provisions. No part of the Material may be used, copied, reproduced, modified, published, uploaded,
 * posted, transmitted, distributed, or disclosed in any way without Intel’s prior express written permission.
 * No license under any patent, copyright, trade secret or other intellectual property right is granted to or
 * conferred upon you by disclosure or delivery of the Materials, either expressly, by implication, inducement,
 * estoppel or otherwise. Any license under such intellectual property rights must be express and approved by Intel
 * in writing.
 *
 * Third Party trademarks are the property of their respective owners.
 *
 * Unless otherwise agreed by Intel in writing, you may not remove or alter this notice or any other notice embedded
 * in Materials by Intel or Intel’s suppliers or licensors in any way.
 */

#if !defined _BIGNUMBER_H_
#define _BIGNUMBER_H_

#include "ippcp.h"

#include <iostream>
#include <vector>
#include <iterator>
using namespace std;
/*
#ifdef __cplusplus
extern "C" {
#endif
*/
class BigNumber
{
public:
   BigNumber(Ipp32u value=0);
   BigNumber(Ipp32s value);
   BigNumber(const IppsBigNumState* pBN);
   BigNumber(const Ipp32u* pData, int length=1, IppsBigNumSGN sgn=IppsBigNumPOS);
   BigNumber(const BigNumber& bn);
   BigNumber(const char *s);
   virtual ~BigNumber();

   // set value
   void Set(const Ipp32u* pData, int length=1, IppsBigNumSGN sgn=IppsBigNumPOS);
   // conversion to IppsBigNumState
   friend IppsBigNumState* BN(const BigNumber& bn) {return bn.m_pBN;}
   operator IppsBigNumState* () const { return m_pBN; }

   // some useful constatns
   static const BigNumber& Zero();
   static const BigNumber& One();
   static const BigNumber& Two();

   // arithmetic operators probably need
   BigNumber& operator = (const BigNumber& bn);
   BigNumber& operator += (const BigNumber& bn);
   BigNumber& operator -= (const BigNumber& bn);
   BigNumber& operator *= (Ipp32u n);
   BigNumber& operator *= (const BigNumber& bn);
   BigNumber& operator /= (const BigNumber& bn);
   BigNumber& operator %= (const BigNumber& bn);
   friend BigNumber operator + (const BigNumber& a, const BigNumber& b);
   friend BigNumber operator - (const BigNumber& a, const BigNumber& b);
   friend BigNumber operator * (const BigNumber& a, const BigNumber& b);
   friend BigNumber operator * (const BigNumber& a, Ipp32u);
   friend BigNumber operator % (const BigNumber& a, const BigNumber& b);
   friend BigNumber operator / (const BigNumber& a, const BigNumber& b);

   // modulo arithmetic
   BigNumber Modulo(const BigNumber& a) const;
   BigNumber ModAdd(const BigNumber& a, const BigNumber& b) const;
   BigNumber ModSub(const BigNumber& a, const BigNumber& b) const;
   BigNumber ModMul(const BigNumber& a, const BigNumber& b) const;
   BigNumber InverseAdd(const BigNumber& a) const;
   BigNumber InverseMul(const BigNumber& a) const;

   // comparisons
   friend bool operator < (const BigNumber& a, const BigNumber& b);
   friend bool operator > (const BigNumber& a, const BigNumber& b);
   friend bool operator == (const BigNumber& a, const BigNumber& b);
   friend bool operator != (const BigNumber& a, const BigNumber& b);
   friend bool operator <= (const BigNumber& a, const BigNumber& b) {return !(a>b);}
   friend bool operator >= (const BigNumber& a, const BigNumber& b) {return !(a<b);}

   // easy tests
   bool IsOdd() const;
   bool IsEven() const { return !IsOdd(); }

   // size of BigNumber
   int MSB() const;
   int LSB() const;
   int BitSize() const { return MSB()+1; }
   int DwordSize() const { return (BitSize()+31)>>5;}
   friend int Bit(const vector<Ipp32u>& v, int n);

   // conversion and output
   void num2hex( string& s ) const; // convert to hex string
   void num2vec( vector<Ipp32u>& v ) const; // convert to 32-bit word vector
   friend ostream& operator << (ostream& os, const BigNumber& a);

protected:
   bool create(const Ipp32u* pData, int length, IppsBigNumSGN sgn=IppsBigNumPOS);
   int compare(const BigNumber& ) const;
   IppsBigNumState* m_pBN;
};

// convert bit size into 32-bit words
#define BITSIZE_WORD(n) ((((n)+31)>>5))
/*
#ifdef __cplusplus
}
#endif
*/

#endif // _BIGNUMBER_H_