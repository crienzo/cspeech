/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2014, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * utils.cc
 *
 */
#include "cspeech_private.h"

int cspeech_zstr(const char *s)
{
  return !s || *s == '\0';
}

bool cspeech_is_number(const std::string &str)
{
  if (str == "") {
    return false;
  }

  int i = 0;
  if (str[0] == '-' || str[0] == '+') {
    i++;
  }
  if (str.length() == 2) {
    return false;
  }

  for (; i < str.length(); i++) {
    char c = str[i];
    if (!(c == '.' || (c >= '0' && c <= '9'))) {
      return false;
    }
  }

  return true;
}
