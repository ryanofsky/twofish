//----------------------------------------------------------------------------
// General Functions

function hex(n)
{
  var digits = new String("0123456789ABCDEF");
  var rtrn = "0x";
  for(var i = 7; i >= 0; --i)
    rtrn = rtrn + digits.charAt((n >>> (i*4)) & 0xF);
  return rtrn;
};

function ROR(x,n)
{
  return (x >>> (n & 0x1F)) | (x << (32-(n & 0x1F)));
}

function ROL(x,n)
{
  return (x <<  (n & 0x1F)) | (x >>> (32-(n & 0x1F)));
}

function DWORD(a,b,c,d)
{
  return ((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff)
};

function BSWAP(dw)
{
    return (((dw << 24) & 0xff000000) | ((dw << 8) & 0xff0000)
            | ((dw >> 8 ) & 0xff00) | ((dw >>> 24) & 0xff));
}

function BYTE(dw,pos) // extract byte
{
  pos &= 3;
  return (dw >>> (24-8*pos)) & 0xFF;
};

function cBYTE(dw,pos,thebyte) // change byte
{
  return (dw & ~(0xFF << (24-8*pos))) || (thebyte << (24-8*pos));
};

function mBYTE(dw) // make byte
{
  return dw & 0xFF;
}

function _makearray(args,level)
{
  var a = new Array(args[level]);
  if(level+1 < args.length)
    for(var i = 0; i < args[level]; i++)
      a[i] = _makearray(args,level+1);
  return a;    
};

function MultiArray()
{
  return _makearray(arguments,0);
};

function read(n,bits,decimal,signed)
{
  n -= 0;
  if (bits==32 || !decimal || (!signed))
    return n & (0xFFFFFFFF >>> (32-bits));
  else 
    return ((n&0x80000000)>>>(32-bits)) | (n&(0x7FFFFFFF>>>(32-bits)));
};

function print(n,bits,decimal,signed)
{
  var rtrn = new String();
  n |= 0;

  if (!bits)
    rtrn += n;
  else if(!decimal)
  {
    var digits = new String("0123456789ABCDEF");
    rtrn += "0x";
    for(var i = Math.ceil(bits/4)-1; i >= 0; --i)
      rtrn += digits.charAt((n >>> (i*4)) & 0xF);
    return rtrn;
  }
  else if (bits==32 && !signed && n<0)
    rtrn += 1.0+0xFFFFFFFF+n;
  else if (signed)
    rtrn += (n << (32-bits)) >> (32-bits);//(n)-(1<<bits);
  else //unsigned or signed 32 already<0;
    rtrn += n;
  return rtrn;  
};

//----------------------------------------------------------------------------
// BinData class

function BinData(length,width) // hack constructor
{
  if (!length) length = 0;
  if (!width) width = 32;
  var a = new Array(Math.ceil(width*length/32));

  a.getlength = BinData_getlength;
  a.setlength = BinData_setlength;
  a.setdirect = BinData_setdirect;
  a.checksum = BinData_checksum;
  a.sha1 = BinData_sha1;
  a.sha1pad = BinData_sha1pad;
  a.sha1ex = BinData_sha1ex;
  a.setalign = BinData_setalign;
  a.get = BinData_get;
  a.set = BinData_set;
  a.getstring = BinData_getstring;
  a.setstring = BinData_setstring;
  a.getBase64 = BinData_getBase64;
  a.setBase64 = BinData_setBase64;
  a.getHexNibbles = BinData_getHexNibbles;
  a.setHexNibbles = BinData_setHexNibbles;
  a.getlength = BinData_getlength;
  a.copy = BinData_copy;
  a.setlist = BinData_setlist;
  a.getlist = BinData_getlist;
  a.setalign(width);
  return a;
}

/*
function BinData(length,width) // normal constructor that doesn't work
{
  if (!length) length = 0;
  if (!width) width = 32;
  this._baseclass = Array;
  this._baseclass(Math.ceil(width*length/32));
  this.setalign = BinData_setalign;
  this.get = BinData_get;
  .
  .
  .
  this.setalign(width);
}
BinData.prototype = new Array();
*/

function BinData_getlength()
{
  return this._length ? this._length : 32*this.length;
};

function BinData_setlength(length,zeroafter) // arguments in bits
{
  this._length = length;
  if (!(zeroafter>0)) zeroafter = length;
  if (length >= 0) 
  {
    var A = Math.ceil(length/32);
    var B = Math.ceil(zeroafter/32);
    this.length = A; // array is truncated or grown to neccesary length
    this[B-1] &= 0xFFFFFFFF << (32-zeroafter%32);
    for(var i = B; i < A; i++) // array is cleared zeroeafter to length
      this[i] = 0;
  }
};

function BinData_setdirect()
{
  for(var i = 0; i < arguments.length; i++)
    this[i] = arguments[i];
}

function BinData_checksum_roll(x,width,n)
{
  return (x << n) | (x >>> (width-n));
}
function BinData_checksum(start,end) // arguments are BinData positions
{
  var width = this._width;
  var shift = width==7 ? 3 : 7 % width;
  var result = start*end;
  for(var i=start; i<end; i++)
  {
    result ^= BinData_checksum_roll(result+this.get(i),width,shift);
  }
  return result & this._mask;  
}  

// SHA-1 Hash Algorithm
// Paper: http://www.itl.nist.gov/div897/pubs/fip180-1.htm
// Implementations: ftp://ftp.funet.fi/pub/crypt/hash/sha

function BinData_SHA_S(n,X) // circular left shift
{
  return (X << (n & 0x1F)) | (X >>> (32-(n & 0x1F)));
}

function BinData_SHA_f(t,B,C,D) // magic function
{
  if (0 <= t && t <= 19)
    return (B&C) | (!B & D);
  else if (20 <= t && t <= 39)
    return B^C^D;
  else if (40 <= t && t <= 59)
    return (B&C) | (B&D) | (C&D);
  else if (60 <= t && t <= 79)
    return B^C^D;
}
function BinData_SHA_k(t) // magic constants
{
  if (0 <= t && t <= 19)
    return 0x5A827999|0;
  else if (20 <= t && t <= 39)
    return 0x6ED9EBA1|0;
  else if (40 <= t && t <= 59)
    return 0x8F1BBCDC|0;
  else if (60 <= t && t <= 79)
    return 0xCA62C1D6|0;
}

function BinData_sha1()
{
  var length = this.getlength()
  if (length % 512 != 0) return null;

  var H = new BinData(5)
  var W = new Array(16);

  H.setdirect(0x67452301|0, 0xEFCDAB89|0, 0x98BADCFE|0, 0x10325476|0, 0xC3D2E1F0|0);
  
  for(var b=0; b < length/32; b+=16)
  {
    var A = H[0];
    var B = H[1];
    var C = H[2];
    var D = H[3];
    var E = H[4];

    for(var t=0; t<80; t++)
    {
       if (t<16)
         W[t] = this[b+t];        
       else
         W[t&15] = BinData_SHA_S(1,W[15&(t+13)] ^ W[15&(t+8)] ^ W[15&(t+2)] ^ W[15&t]);

       var TEMP = 0|(BinData_SHA_S(5,A) + BinData_SHA_f(t,B,C,D) + E + W[15&t] + BinData_SHA_k(t));
       E = D;
       D = C;
       C = BinData_SHA_S(30,B);
       B = A;
       A = TEMP; 
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
  }
  for(var i = 0; i < 5; i++)
    H[i] |= 0;
  return H; 
};

function BinData_sha1pad() // length goes up to multiple of 512, special SHA-1 padding
{
  var oldlength = this.getlength();
  
  var A = Math.floor(oldlength/32);
  var B = 32-oldlength % 32;
  this[A] &= B==32 ? 0 : 0xFFFFFFFF << B
  this[A] |= 1 << (B-1);

  var C = Math.ceil((oldlength+1+64)/512)*16;

  for(var i=A+1; i<C-1; i++)
    this[i] = 0;
  this[C-1] = oldlength;
  this._length = C*32;
}
  
function BinData_sha1ex(bits) // get combined sha-1 results
{
  var oldlength = this.getlength();
  var result = new BinData();
  var resultlen = 0;
  while(resultlen < bits)
  {
    this.sha1pad();
    var sig = this.sha1();
    var length = this.getlength();
    for(i=0; i < 5; i++)
    {
      this[i+length/32] = sig[i];
      result[i+resultlen/32] = sig[i];
    }
    resultlen += 160;
  }
  result.setlength(bits);
  this.setlength(oldlength);
  return result;
}

function BinData_setalign(width,offset)
{
  this._width = width ? width : 32;
  this._offset = offset ? offset : 0;
  this._mask = 0xFFFFFFFF >>> (32-this._width);
};

function BinData_get(pos)
{
  pos = pos*this._width + this._offset;
  var shift = 32-(pos % 32)-this._width; // endpoint relative to [intstart+1]
  var intstart = (pos + shift + this._width)/32 - 1;
  if (shift < 0)
    return this._mask & ((this[intstart]<<-shift) | (this[intstart+1]>>>shift+32));
  else  
    return this._mask & (this[intstart] >>> shift);
};

function BinData_set(pos,val)
{
  pos = pos*this._width + this._offset;
  val &= this._mask;
  var shift = 32-(pos % 32)-this._width;
  var intstart = (pos + shift + this._width)/32 - 1;
  if (shift<0)
  {
    this[intstart]   &= ~(this._mask>>>-shift);
    this[intstart+1] &= ~(this._mask<<shift+32);
    this[intstart]   |= val>>>-shift;
    this[intstart+1] |= (val<<shift+32);
  }
  else 
  {
    this[intstart]   &= ~(this._mask<<shift);
    this[intstart]   |= val<<shift;
  }
};

function BinData_setstring(pos,charsize,str) // returns next usable position
{
  var oldwidth = this._width;
  var oldoffset = this._offset;
  var len = str.length;
  this.setalign(charsize,pos*oldwidth);
 
  for(var i = 0; i < len; i++)
    this.set(i,str.charCodeAt(i));

  this.set(len,0);
  
  this.setalign(oldwidth,oldoffset);
  return pos + Math.ceil(charsize*(len+1)/oldwidth)
}

function BinData_getstring(pos,charsize,len)
{
  var oldwidth = this._width;
  var oldoffset = this._offset;
  var str = new String();
  this.setalign(charsize,pos*oldwidth);

  var stopatnull = len ? false : true;

  if(!len || (len*charsize+this._offset>this.getlength()))
    len = Math.floor((this.getlength()-this._offset)/charsize);

  for(var i = 0; (i < len); i++)
  {
    var c = this.get(i);
    if (stopatnull && c==0) break;
    str += String.fromCharCode(this.get(i))
  }

  this.setalign(oldwidth,oldoffset);
  return str;
}

function BinData_setBase64(str)
{
   this.setalign(6);
   var len = str.length;
   var p = 0;
   for(var i = 0; i < len; i++)
   {
     var j = str.charCodeAt(i);
     if (65 <= j && j <= 90)
       j -= 65;
     else if(97 <= j && j <= 122)
       j-= 71;
     else if(48 <= j && j <= 57)
       j+= 4;     
     else if(j == 43)
       j = 62;
     else if(j == 47)
       j = 63;
     else
       continue;
     this.set(p,j);  
     p++;
   }         
   this.setalign();
   this.setlength(p*6);
   return true;
}

function BinData_getBase64()
{
  var b64 = new String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
  var str = new String();
  var oldwidth = this._width;
  var oldoffset = this._offset;

  this.setalign(6,0);
  var l = Math.ceil(this.getlength()/6);

  for(var i = 0; i < l; i++)
     str += b64.charAt(this.get(i));
   
  this.setalign(oldwidth,oldoffset)
  return str;
}

function BinData_setHexNibbles(str)
{
   this.setalign(4);
   var p = 0;
   for(var i = 0; i < str.length; i++)
   {
     var j = str.charCodeAt(i);
     if(48 <= j && j <= 57)
       j -= 48;
     else if (65 <= j && j <= 70)
       j -= 55;
     else if (97 <= j && j <= 102)
       j -= 87;
     else
       continue;
     this.set(p,j-48);
     p++;
   }         
   this.setalign();
   this.setlength(4*p);
   return true;
}

function BinData_getHexNibbles(wordlength,linelength)
{
  if (!wordlength) wordlength = 0;
  linelength *= wordlength;
  
  var hex = new String("0123456789ABCDEF");
  var str = new String();

  var oldwidth = this._width;
  var oldoffset = this._offset;
  this.setalign(4);
  var l = Math.ceil(this.getlength()/4)-1;

  for(var i = 0; i < l; i++)
  {
     str += hex.charAt(this.get(i));
     if (wordlength > 0)
     {
       if ((linelength>0) && (i % linelength == linelength-1))
         str += "\n";
       else if (i % wordlength == wordlength-1) 
         str += " ";
     };
  }; 
  str += hex.charAt(this.get(l));
    
  this.setalign(oldwidth,oldoffset)
  return str;
}

function BinData_copy(bd)
{
  this.length = bd.length;
  this._length = bd._length;
  this.setalign(bd._width,bd._offset);
  for(var i = 0; i < len; i++)
  {
    this[i] = bd[i];
  }
}

function BinData_getlist(bits,decimal,signed)
{
  var oldwidth = this._width;
  var oldoffset = this._offset;

  this.setalign(bits);
  var len = Math.ceil(this.getlength()/bits);
  var str = new String();
  
  if (len>0) str += print(this.get(0),bits,decimal,signed)
  for(var i = 1; i < len; i++)
  {
    str += ", "
    str += print(this.get(i),bits,decimal,signed);
  }
  this.setalign(oldwidth,oldoffset);
  return str;
}

function BinData_setlist(str, bits,decimal,signed)
{
  this.setalign(bits);
  var len = str.length;
  var number = null;
  var prefix = false;
  var decimal = false;
  var pos = 0;
  var c0 = 0<len ? str.charCodeAt(0) : 0;
  for(var i=0; i<=len; i++)
  {
    var c1 = i+1 < len ? str.charCodeAt(i+1) : 0;
    if(number)
    {
      if ((c0>=48 && c0<=57) || (!decimal && (c0>=65&&c0<=70)))
      {  
        number += String.fromCharCode(c0);
        prefix = false;
      }
      else 
      {
        if (!prefix)
        {
          this.set(pos,read(number,bits,decimal,signed));
          pos++
        }
        number = null;
      }
    }
    else
    {
      if (c0==48 && c1==120)
      {
        number = new String("0x");
        decimal = false;
        prefix = true;
        i++;
        c1 = i+1 < len ? str.charCodeAt(i+1) : 0;
      }
      else if(c0==45)
      {
        number = new String("-");
        decimal = true;
        prefix = true;
      }
      else if (c0>=48 && c0<=57)
      {
        number = new String();
        number += String.fromCharCode(c0);
        decimal = true;
        prefix = false;
      }
    }
  c0 = c1;
  }
  this.setlength(pos*bits);
};
