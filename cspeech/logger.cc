/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2014, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * logger.cc
 *
 */
#include "cspeech.h"
#include "cspeech_private.h"

#include <stdio.h>
#include <stdarg.h>

static int default_logging_callback(cspeech_log_level_t log_level, const char *id, const char *file, int line, const char *log_message)
{
	puts(log_message);
}

static cspeech_logging_callback logger = default_logging_callback;

void _cspeech_log_printf(cspeech_log_level_t log_level, const char *id, const char *file, int line, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  if (logger) {
    char message[1024];
	vsnprintf(message, sizeof(message), format, ap);
    logger(log_level, id, file, line, message);
  }
  va_end(ap);
}

void cspeech_set_logger(cspeech_logging_callback l)
{
	logger = l;
}
