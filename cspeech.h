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

#ifdef __cplusplus
extern "C" {
#endif

int cspeech_init(void);

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

#if 0
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
#endif

/* SRGS */

struct cspeech_srgs_parser;
struct cspeech_srgs_grammar;

enum cspeech_srgs_match_type {
  /** invalid input */
  CSMT_NO_MATCH,
  /** matches, can accept more input */
  CSMT_MATCH,
  /** not yet a match, but valid input so far */
  CSMT_MATCH_PARTIAL,
  /** matches, cannot accept more input */
  CSMT_MATCH_END
};

struct cspeech_srgs_parser *cspeech_srgs_parser_new(const char *uuid);
struct cspeech_srgs_grammar *srgs_parse(struct cspeech_srgs_parser *parser, const char *document);
const char *cspeech_srgs_to_regex(struct cspeech_srgs_grammar *grammar);
const char *cspeech_srgs_to_jsgf(struct cspeech_srgs_grammar *grammar);
const char *cspeech_srgs_to_jsgf_file(struct cspeech_srgs_grammar *grammar, const char *basedir, const char *ext);
enum cspeech_srgs_match_type srgs_grammar_match(struct cspeech_srgs_grammar *grammar, const char *input, const char **interpretation);
void cspeech_srgs_grammar_destroy(struct cspeech_srgs_grammar *grammar);
void cspeech_srgs_parser_destroy(struct cspeech_srgs_parser *parser);

#ifdef __cplusplus
}
#endif

#endif // CSPEECH_H_
