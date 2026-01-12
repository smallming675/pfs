#include "logger.h"
#include <stdarg.h>
#include <string.h>
#include <time.h>

LogLevel g_log_level = LOG_INFO;

static const char *lvl_str(LogLevel lvl) {
  switch (lvl) {
  case LOG_INFO:
    return "INFO";
  case LOG_WARN:
    return "WARN";
  case LOG_ERROR:
    return "ERROR";
  case LOG_DEBUG:
    return "DEBUG";
  }
  return "";
}

void set_log_level(LogLevel level) { g_log_level = level; }

LogLevel log_level_from_str(const char *level_str) {
  if (strcmp(level_str, "DEBUG") == 0) {
    return LOG_DEBUG;
  } else if (strcmp(level_str, "INFO") == 0) {
    return LOG_INFO;
  } else if (strcmp(level_str, "WARN") == 0) {
    return LOG_WARN;
  } else if (strcmp(level_str, "ERROR") == 0) {
    return LOG_ERROR;
  } else
    return LOG_INFO; 
}

void log_msg(LogLevel level, const char *fmt, ...) {
  if (level < g_log_level) {
    return;
  }
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  char ts[64];
  strftime(ts, sizeof(ts), "%F %T", &tm);

  fprintf(stderr, "[%s] %s: ", ts, lvl_str(level));
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}
