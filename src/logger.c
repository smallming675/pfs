#include "logger.h"
#include <stdarg.h>
#include <string.h>
#include <time.h>

LogLevel g_log_level = LOG_INFO;

#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"

static const char *lvl_str(LogLevel lvl) {
  switch (lvl) {
  case LOG_INFO:
    return COLOR_GREEN "INFO" COLOR_RESET;
  case LOG_WARN:
    return COLOR_YELLOW "WARN" COLOR_RESET;
  case LOG_ERROR:
    return COLOR_RED "ERROR" COLOR_RESET;
  case LOG_DEBUG:
    return COLOR_BLUE "DEBUG" COLOR_RESET;
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
  fputs(COLOR_RESET "\n", stderr);
}
