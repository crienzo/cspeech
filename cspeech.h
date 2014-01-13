/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2013, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * cspeech.h
 *
 */

#ifndef CSPEECH_H_
#define CSPEECH_H_

extern "C" {

/* logging */

typedef enum {
  CSPEECH_LOG_DEBUG = 7,
  CSPEECH_LOG_INFO = 6,
  CSPEECH_LOG_NOTICE = 5,
  CSPEECH_LOG_WARNING = 4,
  CSPEECH_LOG_ERROR = 3,
  CSPEECH_LOG_CRIT = 2,
  CSPEECH_LOG_ALERT = 1,
} cspeech_log_level_t;

typedef int (*cspeech_logging_callback)(void *context, cspeech_log_level_t log_level, const char *log_message, ...);


/* NLSML */

enum nlsml_match_type {
  NMT_BAD_XML,
  NMT_MATCH,
  NMT_NOINPUT,
  NMT_NOMATCH
};

extern int nlsml_init(void);
enum nlsml_match_type nlsml_parse(const char *result, const char *uuid);
iks *nlsml_normalize(const char *result);
extern iks *nlsml_create_dtmf_match(const char *digits, const char *interpretation);

/* SRGS */

struct srgs_parser;
struct srgs_grammar;

enum srgs_match_type {
  /** invalid input */
  SMT_NO_MATCH,
  /** matches, can accept more input */
  SMT_MATCH,
  /** not yet a match, but valid input so far */
  SMT_MATCH_PARTIAL,
  /** matches, cannot accept more input */
  SMT_MATCH_END
};

extern int srgs_init(void);
extern struct srgs_parser *srgs_parser_new(const char *uuid);
extern struct srgs_grammar *srgs_parse(struct srgs_parser *parser, const char *document);
extern const char *srgs_grammar_to_regex(struct srgs_grammar *grammar);
extern const char *srgs_grammar_to_jsgf(struct srgs_grammar *grammar);
extern const char *srgs_grammar_to_jsgf_file(struct srgs_grammar *grammar, const char *basedir, const char *ext);
extern enum srgs_match_type srgs_grammar_match(struct srgs_grammar *grammar, const char *input, const char **interpretation);
extern void srgs_parser_destroy(struct srgs_parser *parser);

}

#endif // CSPEECH_H_
