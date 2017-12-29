/*
 * commons.h
 *
 *  Created on: Aug 13, 2017
 *      Author: dead-end
 */

#ifndef SH_COMMONS_H_
#define SH_COMMONS_H_

//
// definition of the print_debug macro.
//
#ifdef DEBUG
#define DEBUG_OUT stdout
#define print_debug(fmt, ...) fprintf(DEBUG_OUT, "DEBUG - " fmt, ##__VA_ARGS__)
#define print_debug_str(fmt)  fprintf(DEBUG_OUT, "DEBUG - " fmt)
#else
#define print_debug(fmt, ...)
#define print_debug_str(fmt)
#endif

//
// definition of the print_error macro
//
#define print_error(fmt, ...) fprintf(stderr, "ERROR - " fmt, ##__VA_ARGS__)
#define print_error_str(fmt)  fprintf(stderr, "ERROR - " fmt)

//
// default buffer size
//
#define BUFFER_SIZE 1024

#define SMALL_BUFFER_SIZE 256

#define MAX_LINE 1024

#endif /* SH_COMMONS_H_ */
