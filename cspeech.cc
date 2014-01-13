/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2013, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * cspeech.cc
 *
 */
#include "cspeech.h"
#include "cspeech/cspeech_private.h"

struct cspeech_srgs_parser {
  struct srgs_parser *parser;
};

struct cspeech_srgs_grammar {
  struct srgs_grammar *grammar;
}

int cspeech_init(void)
{
  srgs_init();
}

struct cspeech_srgs_parser *cspeech_srgs_parser_new(const char *uuid)
{
  cspeech_srgs_parser *parser = new cspeech_srgs_parser;
  std::string u;
  if (!cspeech_zstr(uuid)) {
    u = uuid;
  }
  parser->parser = new srgs_parser(u);
  return parser;
}

struct cspeech_srgs_grammar *cspeech_srgs_parse(struct cspeech_srgs_parser *parser, const char *document)
{
  std::string doc;
  if (!parser) {
    return NULL;
  }
  if (!cspeech_zstr(document)) {
    doc = document;
  }
  srgs_grammar *g = parser->parser->parse(doc);
  if (g) {
    cspeech_srgs_grammar *grammar = new cspeech_srgs_grammar;
    grammar->grammar = g;
    return grammar;
  }
  return NULL;
}

const char *cspeech_srgs_grammar_to_jsgf(struct cspeech_srgs_grammar *grammar)
{
  if (!grammar) {
    return NULL;
  }
  const str::string &jsgf = grammar->grammar->to_jsgf();
  if (jsgf == "") {
    return NULL;
  }
  return jsgf.c_str();
}

const char *cspeech_srgs_grammar_to_jsgf_file(struct cspeech_srgs_grammar *grammar, const char *basedir, const char *ext)
{
  if (!grammar || !basedir || !ext) {
    return NULL;
  }
  const str::string &jsgf_file = grammar->grammar->to_jsgf_file(basedir_str, ext_str);
  if (jsgf_file == "") {
    return NULL;
  }
  return jsgf_file.c_str();
}

enum srgs_match_type cspeech_srgs_grammar_match(struct cspeech_srgs_grammar *grammar, const char *input, const char **interpretation)
{
  std::string input_str;
  std::string interpretation_str;
  *interpretation = NULL;
  if (!cspeech_zstr(input)) {
    input_str = input;
  }
  enum_srgs_match_type match = grammar->grammar->match(input_str, interpretation_str);
  if (interpretation_str != "") {
	  *interpretation = strdup(interpretation_str.c_str());
  }
  return match;
}

void cspeech_srgs_grammar_destroy(struct cspeech_srgs_grammar *grammar)
{
  delete grammar;
}

void cspeech_srgs_parser_destroy(struct cspeech_srgs_parser *parser)
{
  delete parser->parser;
  delete parser;
}

