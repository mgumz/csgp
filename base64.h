#ifndef _BASE64_H_
#define _BASE64_H_

/*------------------------------------------------------------------*\

       file: base64.h
      about: implements base64-encoding
     author: mathias gumz <mg@2hoch5.com>
    license: see LICENSE.txt

\*------------------------------------------------------------------*/

// the last char is the padding char, it's usually
// the '=' sign.
extern const unsigned char base64_std_table[64+1];

// returns the bytes needed to base64-encode 'n' bytes 
// of input, including padding
extern int base64_encoded_len(unsigned int n);

// encodes 'n' bytes of in' into 'out' by using the 
// 64+1(padding) bytes of 'table' via the base64-algorithm
extern int base64_encode(unsigned char* out, unsigned char* in, unsigned int n, const unsigned char table[64+1]);

#endif
