#pragma once
#include "def.h"

#include <stdio.h>
#include <string.h>


class debug {
public:
    bool rdtscCheck();

    bool checkPEB();

    bool checkDebug();
};
extern debug antiDebug;