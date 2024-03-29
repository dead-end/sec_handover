/*
 * MIT License
 *
 * Copyright (c) 2021 dead-end
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SH_COMMONS_H_
#define SH_COMMONS_H_

#include <stdio.h>

//
// definition of the print_debug macro.
//
#ifdef DEBUG
#define DEBUG_OUT stdout
#define print_debug(fmt, ...) fprintf(DEBUG_OUT, "DEBUG - " fmt, ##__VA_ARGS__)
#define print_debug_str(fmt) fprintf(DEBUG_OUT, "DEBUG - " fmt)
#define DEBUG_PARAM
#else
#define print_debug(fmt, ...)
#define print_debug_str(fmt)
#define DEBUG_PARAM __attribute__((unused))
#endif

//
// definition of the print_error macro
//
#define print_error(fmt, ...) fprintf(stderr, "ERROR - " fmt, ##__VA_ARGS__)
#define print_error_str(fmt) fprintf(stderr, "ERROR - " fmt)

/******************************************************************************
 * Definition of the error logging macro.
 *****************************************************************************/

#define log_error(fmt, ...) \
    fprintf(stderr, "ERROR %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);

#define log_error_str(fmt) \
    fprintf(stderr, "ERROR %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__);

/******************************************************************************
 * Definition of the exit logging macro, which terminates the program.
 *****************************************************************************/

#define log_exit(fmt, ...)                                                                      \
    fprintf(stderr, "FATAL %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    exit(EXIT_FAILURE)

#define log_exit_str(fmt)                                                        \
    fprintf(stderr, "FATAL %s:%d:%s() " fmt "\n", __FILE__, __LINE__, __func__); \
    exit(EXIT_FAILURE)

/******************************************************************************
 * default buffer size.
 *****************************************************************************/

#define BUFFER_SIZE 1024

#define SMALL_BUFFER_SIZE 256

#define MAX_LINE 1024

#endif /* SH_COMMONS_H_ */
