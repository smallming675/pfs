#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

typedef enum { LOG_INFO, LOG_WARN, LOG_ERROR, LOG_DEBUG } LogLevel;

void log_msg(LogLevel level, const char *fmt, ...);

#endif /* LOGGER_H */
