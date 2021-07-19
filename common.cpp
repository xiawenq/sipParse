//
// Created by xiawq on 2021/7/19.
//

#include "common.h"

int8_t unhex(char b) {
    if ('0' <= b && b <= '9')
        return b - '0';
    if ('a' <= b && b <= 'f')
        return b - 'a' + 10;
    if ('A' <= b && b <= 'F')
        return b - 'A' + 10;
    return 0;
}

bool lookAheadWSP(char *data, char *p, char* pe) {
    return p+2 < pe && (*(p+2) == ' ' || *(p+2) == '\t');
}

Addr** lastAddr(Addr** addrp) {
    if (*addrp == 0) {
        return addrp;
    }
    else {
        return lastAddr(&(*addrp)->Next);
    }
}

bool whitespacec(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}