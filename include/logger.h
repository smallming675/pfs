#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

typedef enum { LOG_INFO, LOG_WARN, LOG_ERROR, LOG_DEBUG } LogLevel;

extern LogLevel g_log_level;

void set_log_level(LogLevel level);
LogLevel log_level_from_str(const char *level_str);
void log_msg(LogLevel level, const char *fmt, ...);

#endif /* LOGGER_H */
