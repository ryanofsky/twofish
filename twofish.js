//----------------------------------------------------------------------------
// TwoFish Encryption Scheme
// Ported from original C reference code (c) CounterPane Labs
// http://www.counterpane.com/twofish.html
//

TwoFish = new Object; // All functions and variables placed in 'TwoFish' object
                      // to avoid name collisions

TwoFish.MODE_ECB = 1     /* Are we ciphering in ECB mode? */
TwoFish.MODE_CBC = 2     /* Are we ciphering in CBC mode? */
TwoFish.MODE_CFB1 = 3     /* Are we ciphering in 1-bit CFB mode? */

TwoFish.BLOCK_SIZE      = 128  /* number of bits per block */
TwoFish.MAX_ROUNDS      =  16  /* max # rounds (for allocating subkey array) */
TwoFish.ROUNDS_128      =  16  /* default number of rounds for 128-bit keys*/
TwoFish.ROUNDS_192      =  16  /* default number of rounds for 192-bit keys*/
TwoFish.ROUNDS_256      =  16  /* default number of rounds for 256-bit keys*/
TwoFish.MAX_KEY_BITS    = 256  /* max number of bits of key */
TwoFish.MIN_KEY_BITS    = 128  /* min number of bits of key (zero pad) */
TwoFish.input_WHITEN    = 0  /* subkey array indices */
TwoFish.OUTPUT_WHITEN    = (TwoFish.input_WHITEN + TwoFish.BLOCK_SIZE/32)
TwoFish.ROUND_SUBKEYS    = (TwoFish.OUTPUT_WHITEN + TwoFish.BLOCK_SIZE/32)  /* use 2 * (# rounds) */
TwoFish.TOTAL_SUBKEYS    = (TwoFish.ROUND_SUBKEYS + 2*TwoFish.MAX_ROUNDS)

/* for computing subkeys */
TwoFish.SK_STEP = 0x02020202 |0;
TwoFish.SK_BUMP = 0x01010101 |0;
TwoFish.SK_ROTL = 9;

/* Reed-Solomon code parameters: (12,8) reversible code
  g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
   where a = primitive root of field generator 0x14D */

TwoFish.RS_GF_FDBK = 0x14D;    /* field generator */

function TwoFish_RS_rem(x)
{ 
  var b  = (x >>> 24);
  var g2 = ((b << 1) ^ ((b & 0x80) ? TwoFish.RS_GF_FDBK : 0 )) & 0xFF; //dword
  var g3 = ((b >>> 1) & 0x7F) ^ ((b & 1) ? TwoFish.RS_GF_FDBK >>> 1 : 0 ) ^ g2; //dword
  return (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
}
TwoFish.RS_rem = TwoFish_RS_rem;  

/*  Macros for the MDS matrix
*  The MDS matrix is (using primitive polynomial 169):
*      01  EF  5B  5B
*      5B  EF  EF  01
*      EF  5B  01  EF
*      EF  01  EF  5B
*----------------------------------------------------------------
* More statistical properties of this matrix (from MDS.EXE output):
*
* Min Hamming weight (one byte difference) =  8. Max=26.  Total =  1020.
* Prob[8]:      7    23    42    20    52    95    88    94   121   128    91
*             102    76    41    24     8     4     1     3     0     0     0
* Runs[8]:      2     4     5     6     7     8     9    11
* MSBs[8]:      1     4    15     8    18    38    40    43
* HW= 8: 05040705 0A080E0A 14101C14 28203828 50407050 01499101 A080E0A0 
* HW= 9: 04050707 080A0E0E 10141C1C 20283838 40507070 80A0E0E0 C6432020 07070504 
*        0E0E0A08 1C1C1410 38382820 70705040 E0E0A080 202043C6 05070407 0A0E080E 
*        141C101C 28382038 50704070 A0E080E0 4320C620 02924B02 089A4508 
* Min Hamming weight (two byte difference) =  3. Max=28.  Total = 390150.
* Prob[3]:      7    18    55   149   270   914  2185  5761 11363 20719 32079
*           43492 51612 53851 52098 42015 31117 20854 11538  6223  2492  1033
* MDS OK, ROR:   6+  7+  8+  9+ 10+ 11+ 12+ 13+ 14+ 15+ 16+
*               17+ 18+ 19+ 20+ 21+ 22+ 23+ 24+ 25+ 26+
*/
TwoFish.MDS_GF_FDBK = 0x169;  /* primitive polynomial for GF(256)*/

function TwoFish_LFSR1(x)
{
  return ((x >>> 1) ^ ((x & 0x01) ? TwoFish.MDS_GF_FDBK/2 : 0)) & 0xFF;
}
TwoFish.LFSR1 = TwoFish_LFSR1;

function TwoFish_LFSR2(x)
{ 
  return ((x >>> 2) ^ ((x & 0x02) ? TwoFish.MDS_GF_FDBK/2 : 0) ^ ((x & 0x01) ? TwoFish.MDS_GF_FDBK/4 : 0)) & 0xFF;
}
TwoFish.LFSR2 = TwoFish_LFSR2;

function TwoFish_Mx_1(x)
{
  return x & 0xFF;
}
TwoFish.Mx_1 = TwoFish_Mx_1;

function TwoFish_Mx_X(x) /* 5B */
{
  return x ^ TwoFish.LFSR2(x);
}
TwoFish.Mx_X = TwoFish_Mx_X;

function TwoFish_Mx_Y(x) /* EF */
{
  return x ^ TwoFish.LFSR1(x) ^ TwoFish.LFSR2(x);
}
TwoFish.Mx_Y = TwoFish_Mx_Y;

TwoFish.Mul_1  = TwoFish.Mx_1; //moved
TwoFish.Mul_X = TwoFish.Mx_X;
TwoFish.Mul_Y = TwoFish.Mx_Y;

TwoFish.M00 = TwoFish.Mul_1;
TwoFish.M01 = TwoFish.Mul_Y;
TwoFish.M02 = TwoFish.Mul_X;
TwoFish.M03 = TwoFish.Mul_X;

TwoFish.M10 = TwoFish.Mul_X;
TwoFish.M11 = TwoFish.Mul_Y;
TwoFish.M12 = TwoFish.Mul_Y;
TwoFish.M13 = TwoFish.Mul_1;

TwoFish.M20 = TwoFish.Mul_Y;
TwoFish.M21 = TwoFish.Mul_X;
TwoFish.M22 = TwoFish.Mul_1;
TwoFish.M23 = TwoFish.Mul_Y;

TwoFish.M30 = TwoFish.Mul_Y;
TwoFish.M31 = TwoFish.Mul_1;
TwoFish.M32 = TwoFish.Mul_Y;
TwoFish.M33 = TwoFish.Mul_X;

/*  Define the fixed p0/p1 permutations used in keyed S-box lookup.  
  By changing the following constant definitions for P_ij, the S-boxes will
  automatically get changed in all the Twofish source code. Note that P_i0 is
  the "outermost" 8x8 permutation applied.  See the f32() function to see
  how these constants are to be  used.
*/
TwoFish.P_00 = 1;          /* "outermost" permutation */
TwoFish.P_01 = 0;
TwoFish.P_02 = 0;
TwoFish.P_03 = (TwoFish.P_01^1) & 0xFF;      /* "extend" to larger key sizes */
TwoFish.P_04 = 1;

TwoFish.P_10 = 0;
TwoFish.P_11 = 0;
TwoFish.P_12 = 1;
TwoFish.P_13 = (TwoFish.P_11^1) & 0xFF;
TwoFish.P_14 = 0;

TwoFish.P_20 = 1;
TwoFish.P_21 = 1;
TwoFish.P_22 = 0;
TwoFish.P_23 = (TwoFish.P_21^1) & 0xFF;
TwoFish.P_24 = 0;

TwoFish.P_30 = 0;
TwoFish.P_31 = 1;
TwoFish.P_32 = 1;
TwoFish.P_33 = (TwoFish.P_31^1) & 0xFF;
TwoFish.P_34 = 1;

/* fixed 8x8 permutation S-boxes */

/***********************************************************************
*  07:07:14  05/30/98  [4x4]  TestCnt=256. keySize=128. CRC=4BD14D9E.
* maxKeyed:  dpMax = 18. lpMax =100. fixPt =  8. skXor =  0. skDup =  6. 
* log2(dpMax[ 6..18])=   --- 15.42  1.33  0.89  4.05  7.98 12.05
* log2(lpMax[ 7..12])=  9.32  1.01  1.16  4.23  8.02 12.45
* log2(fixPt[ 0.. 8])=  1.44  1.44  2.44  4.06  6.01  8.21 11.07 14.09 17.00
* log2(skXor[ 0.. 0])
* log2(skDup[ 0.. 6])=   ---  2.37  0.44  3.94  8.36 13.04 17.99
***********************************************************************/
TwoFish.P8x8 = 
/*  p0:   */
/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   1  1  1  0.         */
/* 817D6F320B59ECA4.ECB81235F4A6709D.BA5E6D90C8F32471.D7F4126E9B3085CA. */
/* Karnaugh maps:
*  0111 0001 0011 1010. 0001 1001 1100 1111. 1001 1110 0011 1110. 1101 0101 1111 1001. 
*  0101 1111 1100 0100. 1011 0101 0010 0000. 0101 1000 1100 0101. 1000 0111 0011 0010. 
*  0000 1001 1110 1101. 1011 1000 1010 0011. 0011 1001 0101 0000. 0100 0010 0101 1011. 
*  0111 0100 0001 0110. 1000 1011 1110 1001. 0011 0011 1001 1101. 1101 0101 0000 1100. 
*/
new Array(
  new Array(
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0),
/*  p1:   */
/*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   2  0  0  1.         */
/* 28BDF76E31940AC5.1E2B4C376DA5F908.4C75169A0ED82B3F.B951C3DE647F208A. */
/* Karnaugh maps:
*  0011 1001 0010 0111. 1010 0111 0100 0110. 0011 0001 1111 0100. 1111 1000 0001 1100. 
*  1100 1111 1111 1010. 0011 0011 1110 0100. 1001 0110 0100 0011. 0101 0110 1011 1011. 
*  0010 0100 0011 0101. 1100 1000 1000 1110. 0111 1111 0010 0110. 0000 1010 0000 0011. 
*  1101 1000 0010 0001. 0110 1001 1110 0101. 0001 0100 0101 0111. 0011 1011 1111 0010. 
*/
  new Array(
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
  ));

TwoFish.FEISTEL = false;    /* true -> use Feistel version (slow) */

/* number of rounds for various key sizes: 128, 192, 256 */
TwoFish.numRounds = new Array(0,TwoFish.ROUNDS_128,TwoFish.ROUNDS_192,TwoFish.ROUNDS_256);

/*
+*****************************************************************************
*
* Function Name:  f32
*
* Function:      Run four bytes through keyed S-boxes and apply MDS matrix
*
* Arguments:    x      =  input to f function
*          k32      =  pointer to key dwords
*          keyLen    =  total key length (k32 --> keyLey/2 bits)
*
* Return:      The output of the keyed permutation applied to x.
*
* Notes:
*  This function is a keyed 32-bit permutation.  It is the major building
*  block for the Twofish round function, including the four keyed 8x8 
*  permutations and the 4x4 MDS matrix multiply.  This function is used
*  both for generating round subkeys and within the round function on the
*  block being encrypted.  
*
*  This version is fairly slow and pedagogical, although a smartcard would
*  probably perform the operation exactly this way in firmware.   For
*  ultimate performance, the entire operation can be completed with four
*  lookups into four 256x32-bit tables, with three dword xors.
*
*  The MDS matrix is defined in TwoFish.H.  To multiply by Mij, just use the
*  macro Mij(x).
*
-****************************************************************************/
function TwoFish_f32(x,k32,keyLen)
{
  var b = x;
  
  /* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
  /* Note that each byte goes through a different combination of S-boxes.*/
  
  switch (Math.floor((keyLen + 63)/64) & 3)
  {
    case 0:    /* 256 bits of key */
      b = DWORD(TwoFish.P8x8[TwoFish.P_04][BYTE(b,0)] ^ BYTE(k32[3],0),
                TwoFish.P8x8[TwoFish.P_14][BYTE(b,1)] ^ BYTE(k32[3],1),
                TwoFish.P8x8[TwoFish.P_24][BYTE(b,2)] ^ BYTE(k32[3],2),
                TwoFish.P8x8[TwoFish.P_34][BYTE(b,3)] ^ BYTE(k32[3],3));
                  
      /* fall thru, having pre-processed b[0]..b[3] with k32[3] */
    case 3:    /* 192 bits of key */
      b = DWORD(TwoFish.P8x8[TwoFish.P_03][BYTE(b,0)] ^ BYTE(k32[2],0),
                TwoFish.P8x8[TwoFish.P_13][BYTE(b,1)] ^ BYTE(k32[2],1),
                TwoFish.P8x8[TwoFish.P_23][BYTE(b,2)] ^ BYTE(k32[2],2),
                TwoFish.P8x8[TwoFish.P_33][BYTE(b,3)] ^ BYTE(k32[2],3));
      /* fall thru, having pre-processed b[0]..b[3] with k32[2] */
    case 2:    /* 128 bits of key */
      b = DWORD(TwoFish.P8x8[TwoFish.P_00][TwoFish.P8x8[TwoFish.P_01][TwoFish.P8x8[TwoFish.P_02][BYTE(b,0)] ^ BYTE(k32[1],0)] ^ BYTE(k32[0],0)],
                TwoFish.P8x8[TwoFish.P_10][TwoFish.P8x8[TwoFish.P_11][TwoFish.P8x8[TwoFish.P_12][BYTE(b,1)] ^ BYTE(k32[1],1)] ^ BYTE(k32[0],1)],
                TwoFish.P8x8[TwoFish.P_20][TwoFish.P8x8[TwoFish.P_21][TwoFish.P8x8[TwoFish.P_22][BYTE(b,2)] ^ BYTE(k32[1],2)] ^ BYTE(k32[0],2)],
                TwoFish.P8x8[TwoFish.P_30][TwoFish.P8x8[TwoFish.P_31][TwoFish.P8x8[TwoFish.P_32][BYTE(b,3)] ^ BYTE(k32[1],3)] ^ BYTE(k32[0],3)]);
    }

  /* Now perform the MDS matrix multiply inline. */
  return ((TwoFish.M00(BYTE(b,0)) ^ TwoFish.M01(BYTE(b,1)) ^ TwoFish.M02(BYTE(b,2)) ^ TwoFish.M03(BYTE(b,3)))       ) ^
         ((TwoFish.M10(BYTE(b,0)) ^ TwoFish.M11(BYTE(b,1)) ^ TwoFish.M12(BYTE(b,2)) ^ TwoFish.M13(BYTE(b,3))) << 8  ) ^
         ((TwoFish.M20(BYTE(b,0)) ^ TwoFish.M21(BYTE(b,1)) ^ TwoFish.M22(BYTE(b,2)) ^ TwoFish.M23(BYTE(b,3))) << 16 ) ^
         ((TwoFish.M30(BYTE(b,0)) ^ TwoFish.M31(BYTE(b,1)) ^ TwoFish.M32(BYTE(b,2)) ^ TwoFish.M33(BYTE(b,3))) << 24 );
}
TwoFish.f32 = TwoFish_f32;

/*
+*****************************************************************************
*
* Function Name:  RS_MDS_Encode
*
* Function:      Use (12,8) Reed-Solomon code over GF(256) to produce
*          a key S-box dword from two key material dwords.
*
* Arguments:    k0  =  1st dword
*          k1  =  2nd dword
*
* Return:      Remainder polynomial generated using RS code
*
* Notes:
*  Since this computation is done only once per reKey per 64 bits of key,
*  the performance impact of this routine is imperceptible. The RS code
*  chosen has "simple" coefficients to allow smartcard/hardware implementation
*  without lookup tables.
*
-****************************************************************************/
function TwoFish_RS_MDS_Encode(k0,k1)
{
  var r = 0;
  for (var i=0;i<2;i++)
  {
    r ^= (i) ? k0 : k1;      /* merge in 32 more key bits */
    for (j=0;j<4;j++)        /* shift one byte at a time */
      r = TwoFish.RS_rem(r);        
  }
  return r;
}
TwoFish.RS_MDS_Encode = TwoFish_RS_MDS_Encode

/*
+*****************************************************************************
*
* Function Name:  makeKey
*
* Function:      Initialize the Twofish key schedule
*
* Arguments:    key      =  ptr to keyInstance to be initialized
*          direction  =  DIR_ENCRYPT or DIR_DECRYPT
*          keyLen    =  # bits of key text at *keyMaterial
*          keyMaterial  =  ptr to hex ASCII chars representing key bits
*
* Return:      TRUE on success
*          else error code (e.g., BAD_KEY_DIR)
*
* Notes:
*  This parses the key bits from keyMaterial.  No crypto stuff happens here.
*  The function reKey() is called to actually build the key schedule after
*  the keyMaterial has been parsed.
*
-****************************************************************************/
function TwoFish_Key(keyMaterial)
{
  var keyLen = keyMaterial.getlength();
  
  if ((keyLen > TwoFish.MAX_KEY_BITS) || (keyLen < 8))  
    alert("BAD_KEY_MAT, length must be valid");
  
  this.keyLen = (keyLen+63) & ~63; /* Length of the key, round up to multiple of 64 */
  this.numRounds = TwoFish.numRounds[Math.floor((keyLen-1)/64)]; /* number of rounds in cipher */
  this.key32 = new Array(TwoFish.MAX_KEY_BITS/32);  /* actual key bits, in dwords */
 
  for (var i=0;i<this.keyLen/32;i++)  
    this.key32[i]= keyMaterial[i];
  
  for (var i=Math.floor(this.keyLen/32);i<TwoFish.MAX_KEY_BITS/32;i++)  /* zero unused bits */
    this.key32[i]= 0;    

  this.sboxKeys = new Array(TwoFish.MAX_KEY_BITS/64);/* key bits used for S-boxes */
  this.subKeys = new Array(TwoFish.TOTAL_SUBKEYS);  /* round subkeys, input/output whitening bits */
  //this.sBox8x32 = MultiArray(4,256);
  
  this.reKey = TwoFish_Key_reKey;
  return this.reKey();      /* generate round subkeys */
};
TwoFish.Key = TwoFish_Key;

/*
+*****************************************************************************
*
* Function Name:  reKey
*
* Function:      Initialize the Twofish key schedule from key32
*
* Arguments:    key      =  ptr to keyInstance to be initialized
*
* Return:      TRUE on success
*
* Notes:
*  Here we precompute all the round subkeys, although that is not actually
*  required.  For example, on a smartcard, the round subkeys can 
*  be generated on-the-fly  using f32()
*
-****************************************************************************/
function TwoFish_Key_reKey()
{
  var k64Cnt;
  var subkeyCnt = TwoFish.ROUND_SUBKEYS + 2*this.numRounds;
  var k32e = new Array(TwoFish.MAX_KEY_BITS/64); /* even/odd key dwords */
  var k32o = new Array(TwoFish.MAX_KEY_BITS/64); 

  if ((this.keyLen % 64 != 0) || (this.keyLen < TwoFish.MIN_KEY_BITS))
    alert("BAD_KEY_INSTANCE. Key passed is not valid.");
  if (subkeyCnt > TwoFish.TOTAL_SUBKEYS)
    alert("BAD_KEY_INSTANCE. Key passed is not valid.");

  k64Cnt=Math.floor((this.keyLen+63)/64);    /* round up to next multiple of 64 bits */
  for (var i=0;i<k64Cnt;i++)
  {            /* split into even/odd key dwords */
    k32e[i]=this.key32[2*i  ];
    k32o[i]=this.key32[2*i+1];
    /* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
    this.sboxKeys[k64Cnt-1-i] = TwoFish.RS_MDS_Encode(k32e[i],k32o[i]); /* reverse order */
  }

  /*DWORD*/ var  A,B;
  for (var i=0;i<subkeyCnt/2;i++)          /* compute round subkeys for PHT */
  {
    A = TwoFish.f32(i*TwoFish.SK_STEP              ,k32e,this.keyLen);  /* A uses even key dwords */
    B = TwoFish.f32(i*TwoFish.SK_STEP+TwoFish.SK_BUMP,k32o,this.keyLen);  /* B uses odd  key dwords */
    B = ROL(B,8);
    this.subKeys[2*i  ] = (A+B)|0;      /* combine with a PHT */
    this.subKeys[2*i+1] = ROL(A+2*B,TwoFish.SK_ROTL);
  }
  return true;
}

/*
+*****************************************************************************
*
* Function Name:  cipherInit
*
* Function:      Initialize the Twofish cipher in a given mode
*
* Arguments:    cipher    =  ptr to cipherInstance to be initialized
*          mode    =  MODE_ECB, MODE_CBC, or MODE_CFB1
*          IV      =  ptr to hex ASCII test representing IV bytes
*
* Return:      TRUE on success
*          else error code (e.g., BAD_CIPHER_MODE)
*
-****************************************************************************/
function TwoFish_Cipher(mode,IV)
{
  if ((mode != TwoFish.MODE_ECB) && (mode != TwoFish.MODE_CBC) && (mode != TwoFish.MODE_CFB1))
    alert("BAD_CIPHER_MODE, Invalid cipher mode");

  this.mode = mode;                           /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
  this.iv32 = new BinData(TwoFish.BLOCK_SIZE/32); /* CBC IV bytes arranged as dwords */
  
  if ((mode != TwoFish.MODE_ECB) && (IV))  /* parse the IV */
  {
    for (var i=0;i<TwoFish.BLOCK_SIZE/32;i++)  
      this.iv32[i] = IV[i];
  }
};
TwoFish.Cipher = TwoFish_Cipher;


/*
+*****************************************************************************
*
* Function Name:  blockEncrypt
*
* Function:      Encrypt block(s) of data using Twofish
*
* Arguments:    cipher    =  ptr to already initialized cipherInstance
*          key      =  ptr to already initialized keyInstance
*          input    =  ptr to data blocks to be encrypted
*          inputLen  =  # bits to encrypt (multiple of blockSize)
*          outBuffer  =  ptr to where to put encrypted blocks
*
* Return:      # bits ciphered (>= 0)
*          else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*     If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*     an error BAD_input_LEN is returned.  In CFB1 mode, all block 
*     sizes can be supported.
*
-****************************************************************************/
function TwoFish_Encrypt(cipher,key,input)
{
  var rounds=key.numRounds;              /* number of rounds */
  
  var outBuffer = new BinData();
  var oldlength = input.getlength();
  var inputLen =  cipher.mode == TwoFish.MODE_CFB1 ? oldlength : Math.ceil(oldlength/TwoFish.BLOCK_SIZE)*TwoFish.BLOCK_SIZE;
  input.setlength(inputLen);

  var x = new BinData(TwoFish.BLOCK_SIZE/32,32); /* temp data */

  if (!cipher)
    alert("BAD_CIPHER_STATE. Cipher in wrong state (e.g., not initialized).");
  if (!key)
    alert("BAD_KEY_INSTANCE. Key passed is not valid.");
  if ((rounds < 2) || (rounds > TwoFish.MAX_ROUNDS) || (rounds&1))
    alert("BAD_KEY_INSTANCE. Key passed is not valid");

  if (cipher.mode == TwoFish.MODE_CFB1)
  {  /* use recursion here to handle CFB, one block at a time */
    input.setalign(8);
    outBuffer.setalign(8);
    x.setalign(8);
    cipher.iv32.setalign(8);
    cipher.mode = TwoFish.MODE_ECB;	/* do encryption in ECB */
    for (var n=0;n<inputLen;n++)
    {
      var n8 = Math.floor(n/8);
      x = TwoFish_Encrypt(cipher,key,cipher.iv32);
      var bit = 0x80 >>> (n & 7);/* which bit position in byte */
      var ctBit = (input.get(n8) & bit) ^ ((x.get(0) & 0x80) >> (n&7));
      outBuffer.set(n8,(outBuffer.get(n8) & ~ bit) | ctBit);
      var carry = ctBit >>> (7 - (n&7));
      for (var i=TwoFish.BLOCK_SIZE/8-1;i>=0;i--)
      {
        bit = cipher.iv32.get(i) >>> 7;	/* save next "carry" from shift */
        cipher.iv32.set(i,(cipher.iv32.get(i) << 1) ^ carry);
        carry = bit;
      };
    };
    cipher.mode = TwoFish.MODE_CFB1;	/* restore mode for next time */
    outBuffer.setlength(inputLen);
    input.setlength(oldlength);
    return outBuffer;
  };

  /* here for ECB, CBC modes */
  for(var n=0; n<inputLen; n+=TwoFish.BLOCK_SIZE) //also increments input, output in original source
  {
    for (var i=0;i<TwoFish.BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */
    {
      x[i]=input[i+n/32] ^ key.subKeys[TwoFish.input_WHITEN+i];
      if (cipher.mode == TwoFish.MODE_CBC)
        x[i] ^= cipher.iv32[i];
    }
   
    for (var r=0;r<rounds;r++)      /* main Twofish encryption loop */
    {  
      if(TwoFish.FEISTEL)
      {
        var t0 = TwoFish.f32(ROR(x[0],  Math.floor((r+1)/2)),key.sboxKeys,key.keyLen);
        var t1 = TwoFish.f32(ROL(x[1],8+(r+1)/2),key.sboxKeys,key.keyLen);
										/* PHT, round keys */
        x[2]^= ROL(t0 +   t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r  ],Math.floor(r/2)  );
        x[3]^= ROR(t0 + 2*t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r+1],Math.floor(r/2)+1);
      }
      else //not feistel
      {
        var t0 = TwoFish.f32(    x[0]   ,key.sboxKeys,key.keyLen);
        var t1 = TwoFish.f32(ROL(x[1],8),key.sboxKeys,key.keyLen);

        x[3] = ROL(x[3],1);
        x[2]^= t0 +   t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
        x[3]^= t0 + 2*t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r+1];
        x[2] = ROR(x[2],1);
      };
       
      if (r < rounds-1)            /* swap for next round */
      {
        var tmp = x[0]; x[0]= x[2]; x[2] = tmp;
            tmp = x[1]; x[1]= x[3]; x[3] = tmp;
      }
    };
    
    if(TwoFish.FEISTEL)
    {
      x[0] = ROR(x[0],8);                     /* "final permutation" */
      x[1] = ROL(x[1],8);
      x[2] = ROR(x[2],8);
      x[3] = ROL(x[3],8);
    };

    for (i=0;i<TwoFish.BLOCK_SIZE/32;i++)	/* copy out, with whitening */
    {
      outBuffer[i+n/32] = x[i] ^ key.subKeys[TwoFish.OUTPUT_WHITEN+i];
      if (cipher.mode == TwoFish.MODE_CBC)
        cipher.iv32[i] = outBuffer[i+n/32];
    };
  }
  outBuffer.setlength(inputLen);
  input.setlength(oldlength);
  return outBuffer;
}
TwoFish.Encrypt = TwoFish_Encrypt;

/*
+*****************************************************************************
*
* Function Name:  blockDecrypt
*
* Function:      Decrypt block(s) of data using Twofish
*
* Arguments:    cipher    =  ptr to already initialized cipherInstance
*          key      =  ptr to already initialized keyInstance
*          input    =  ptr to data blocks to be decrypted
*          inputLen  =  # bits to encrypt (multiple of blockSize)
*          outBuffer  =  ptr to where to put decrypted blocks
*
* Return:      # bits ciphered (>= 0)
*          else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*     If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*     an error BAD_input_LEN is returned.  In CFB1 mode, all block 
*     sizes can be supported.
*
-****************************************************************************/
function TwoFish_Decrypt(cipher,key,input)
{
  var rounds=key.numRounds;  /* number of rounds */
  var oldlength = input.getlength();
  var inputLen = cipher.mode == TwoFish.MODE_CFB1 ? oldlength : Math.ceil(oldlength/TwoFish.BLOCK_SIZE)*TwoFish.BLOCK_SIZE;
  input.setlength(inputLen);
  
  var outBuffer = new BinData();
  var x = new BinData(TwoFish.BLOCK_SIZE/32,32);  /* temp data */

  if (!cipher)
    alert("BAD_CIPHER_STATE. Cipher in wrong state (e.g., not initialized).");
  if (!key)
    alert("BAD_KEY_INSTANCE. Key passed is not valid.");
  if ((rounds < 2) || (rounds > TwoFish.MAX_ROUNDS) || (rounds&1))
    alert("BAD_KEY_INSTANCE. Key passed is not valid.");

  if (cipher.mode == TwoFish.MODE_CFB1)
  {  /* use blockEncrypt here to handle CFB, one block at a time */
    input.setalign(8);
    outBuffer.setalign(8);
    x.setalign(8);
    cipher.iv32.setalign(8);
    cipher.mode = TwoFish.MODE_ECB;  /* do encryption in ECB */
    for (var n=0;n<inputLen;n++)
    {
      var n8 = Math.floor(n/8);
      x = TwoFish_Encrypt(cipher,key,cipher.iv32);
      var bit    = 0x80 >>> (n & 7);
      var ctBit = input.get(n8) & bit;
      outBuffer.set(n8,outBuffer.get(n8) & ~ bit) | (ctBit ^ ((x.get(0) & 0x80) >> (n&7)));
      var carry = ctBit >>> (7 - (n&7));
      for (var i=TwoFish.BLOCK_SIZE/8-1;i>=0;i--)
      {
          bit = cipher.iv32.get(i) >>> 7;  /* save next "carry" from shift */
          cipher.iv32.set(i,(cipher.iv32.get(i) << 1) ^ carry);
          carry = bit;
      };
    };
    cipher.mode = TwoFish.MODE_CFB1;  /* restore mode for next time */
    input.setlength(oldlength);
    outBuffer.setlength(inputLen);
    return outBuffer;
  };

  /* here for ECB, CBC modes */
  for (var n=0;n<inputLen;n+=TwoFish.BLOCK_SIZE)
  {
    for (i=0;i<TwoFish.BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */
      x[i]=input[i+n/32] ^ key.subKeys[TwoFish.OUTPUT_WHITEN+i];

    for (var r=rounds-1;r>=0;r--)      /* main Twofish decryption loop */
    {
      var t0 = TwoFish.f32(    x[0]   ,key.sboxKeys,key.keyLen);
      var t1 = TwoFish.f32(ROL(x[1],8),key.sboxKeys,key.keyLen);

      x[2] = ROL(x[2],1);
      x[2]^= t0 +   t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
      x[3]^= t0 + 2*t1 + key.subKeys[TwoFish.ROUND_SUBKEYS+2*r+1];
      x[3] = ROR(x[3],1);

      if (r)                  /* unswap, except for last round */
      {
        var t0   = x[0]; x[0]= x[2]; x[2] = t0;  
        var t1   = x[1]; x[1]= x[3]; x[3] = t1;
      }
    }

    for (i=0;i<TwoFish.BLOCK_SIZE/32;i++)  /* copy out, with whitening */
    {
      x[i] ^= key.subKeys[TwoFish.input_WHITEN+i];
      if (cipher.mode == TwoFish.MODE_CBC)
      {
        x[i] ^= cipher.iv32[i];
        cipher.iv32[i] = input[i+n/32];
      }
      outBuffer[i+n/32] = x[i];
    };
  }
  input.setlength(oldlength);
  outBuffer.setlength(inputLen);
  return outBuffer;
}
TwoFish.Decrypt = TwoFish_Decrypt

// End of TwoFish Port
