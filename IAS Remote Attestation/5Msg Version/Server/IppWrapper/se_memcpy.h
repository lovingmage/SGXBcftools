//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

/*
 *	This file is to wrapper memory operation related API that is different from windows to linux.
*/
#pragma once

#ifndef _SE_MEMCPY_H_ 
#define _SE_MEMCPY_H_

#include <string.h>

#if defined(__GNUC__)

/* memcpy_s always return 0 under Linux */

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

static inline errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

#endif /* __GNUC__ */

#endif /* _SE_MEMCPY_H_ */
