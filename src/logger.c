#include "logger.h"
#include <stdarg.h>
#include <time.h>

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

void log_msg(LogLevel level, const char *fmt, ...) {
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
