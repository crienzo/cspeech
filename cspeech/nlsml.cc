/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2013, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * nlsml.c
 *
 */

#include <iksemel.h>
#include <map>
#include <stdlib.h>
#include <string.h>
#include <sstream>

#include "cspeech.h"
#if 0
struct nlsml_parser;

/** function to handle tag attributes */
typedef int (* tag_attribs_fn)(struct nlsml_parser *, char **);
/** function to handle tag CDATA */
typedef int (* tag_cdata_fn)(struct nlsml_parser *, char *, size_t);

/**
 * Tag definition
 */
struct tag_def {
  tag_attribs_fn attribs_fn;
  tag_cdata_fn cdata_fn;
  bool is_root;
  std::map<const char *,const char *> children_tags;
};

/**
 * library configuration
 */
static struct {
  /** true if initialized */
  bool init;
  /** Mapping of tag name to definition */
  std::map<const char *,struct tag_def *> tag_defs;
  /** Callback for logging messages **/
  int (*logging_callback)(void *context, cspeech_log_level_t log_level, const char *log_message, ...);
} globals;

/**
 * The node in the XML tree
 */
struct nlsml_node {
  /** tag name */
  const char *name;
  /** tag definition */
  struct tag_def *tag_def;
  /** parent to this node */
  struct nlsml_node *parent;
};

/**
 * The SAX parser state
 */
struct nlsml_parser {
  /** current node */
  struct nlsml_node *cur;
  /** optional UUID for logging */
  const char *uuid;
  /** true if a match exists */
  int match;
  /** true if noinput */
  int noinput;
  /** true if nomatch */
  int nomatch;
};

/**
 * Add a definition for a tag
 * @param tag the name
 * @param attribs_fn the function to handle the tag attributes
 * @param cdata_fn the function to handler the tag CDATA
 * @param children_tags comma-separated list of valid child tag names
 * @return the definition
 */
static struct tag_def *add_tag_def(const char *tag, tag_attribs_fn attribs_fn, tag_cdata_fn cdata_fn, const char *children_tags)
{
  struct tag_def *def = (struct tag_def *) malloc(sizeof(tag_def));
  if (!cspeech_zstr(children_tags)) {
    std::string tags_string(children_tags);
    std::stringstream ss(tags_string);
    std::string item;
    while (std::getline(ss, item, ',')) {
      def->children_tags[item.c_str()] = item.c_str();
    }
  }
  def->attribs_fn = attribs_fn;
  def->cdata_fn = cdata_fn;
  def->is_root = false;
  globals.tag_defs[tag] = def;
  return def;
}

/**
 * Add a definition for a root tag
 * @param tag the name
 * @param attribs_fn the function to handle the tag attributes
 * @param cdata_fn the function to handler the tag CDATA
 * @param children_tags comma-separated list of valid child tag names
 * @return the definition
 */
static struct tag_def *add_root_tag_def(const char *tag, tag_attribs_fn attribs_fn, tag_cdata_fn cdata_fn, const char *children_tags)
{
  struct tag_def *def = add_tag_def(tag, attribs_fn, cdata_fn, children_tags);
  def->is_root = true;
  return def;
}

/**
 * Handle tag attributes
 * @param parser the parser
 * @param name the tag name
 * @param atts the attributes
 * @return IKS_OK if OK IKS_BADXML on parse failure
 */
static int process_tag(struct nlsml_parser *parser, const char *name, char **atts)
{
  struct nlsml_node *cur = parser->cur;
  if (cur->tag_def->is_root && cur->parent == NULL) {
    /* no parent for ROOT tags */
    return cur->tag_def->attribs_fn(parser, atts);
  } else if (!cur->tag_def->is_root && cur->parent) {
    /* check if this child is allowed by parent node */
    struct tag_def *parent_def = cur->parent->tag_def;
    if (parent_def->children_tags.count("ANY") > 0 ||
      parent_def->children_tags.count(name) > 0) {
      return cur->tag_def->attribs_fn(parser, atts);
    } else {
      if(globals.logging_callback) {
        globals.logging_callback(&parser, CSPEECH_LOG_INFO, "<%s> cannot be a child of <%s>\n", name, cur->parent->name);
      }
    }
  } else if (cur->tag_def->is_root && cur->parent != NULL) {
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_INFO, "<%s> must be the root element\n", name);
    }
  } else {
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_INFO, "<%s> cannot be a root element\n", name);
    }
  }
  return IKS_BADXML;
}

/**
 * Handle tag attributes that are ignored
 * @param parser the parser
 * @param atts the attributes
 * @return IKS_OK
 */
static int process_attribs_ignore(struct nlsml_parser *parser, char **atts)
{
  return IKS_OK;
}

/**
 * Handle CDATA that is ignored
 * @param parser the parser
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_OK
 */
static int process_cdata_ignore(struct nlsml_parser *parser, char *data, size_t len)
{
  return IKS_OK;
}

/**
 * Handle CDATA that is not allowed
 * @param parser the parser
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_BADXML if any printable characters
 */
static int process_cdata_bad(struct nlsml_parser *parser, char *data, size_t len)
{
  int i;
  for (i = 0; i < len; i++) {
    if (isgraph(data[i])) {
      if(globals.logging_callback) {
        globals.logging_callback(&parser, CSPEECH_LOG_INFO, "Unexpected CDATA for <%s>\n", parser->cur->name);
      }
      return IKS_BADXML;
    }
  }
  return IKS_OK;
}

/**
 * Handle CDATA with match text
 * @param parser the parser
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_OK
 */
static int process_cdata_match(struct nlsml_parser *parser, char *data, size_t len)
{
  int i;
  for (i = 0; i < len; i++) {
    if (isgraph(data[i])) {
      parser->match++;
      return IKS_OK;
    }
  }
  return IKS_OK;
}

/**
 * Handle nomatch
 * @param parser the parser
 * @param atts the attributes
 * @return IKS_OK
 */
static int process_nomatch(struct nlsml_parser *parser, char **atts)
{
  parser->nomatch++;
  return IKS_OK;
}

/**
 * Handle noinput
 * @param parser the parser
 * @param atts the attributes
 * @return IKS_OK
 */
static int process_noinput(struct nlsml_parser *parser, char **atts)
{
  parser->noinput++;
  return IKS_OK;
}

/**
 * Process a tag
 */
static int tag_hook(void *user_data, char *name, char **atts, int type)
{
  int result = IKS_OK;
  struct nlsml_parser *parser = (struct nlsml_parser *)user_data;

  if (type == IKS_OPEN || type == IKS_SINGLE) {
    struct nlsml_node *child_node = (struct nlsml_node *) malloc(sizeof(*child_node));
    child_node->name = name;
    child_node->tag_def = globals.tag_defs[name];
    if (!child_node->tag_def) {
      child_node->tag_def = globals.tag_defs["ANY"];
    }
    child_node->parent = parser->cur;
    parser->cur = child_node;
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_DEBUG, "<%s>\n", name);
    }
    result = process_tag(parser, name, atts);
  }

  if (type == IKS_CLOSE || type == IKS_SINGLE) {
    struct nlsml_node *node = parser->cur;
    parser->cur = node->parent;
    free(node);
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_DEBUG, "</%s>\n", name);
    }
  }

  return result;
}

/**
 * Process cdata
 * @param user_data the parser
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_OK
 */
static int cdata_hook(void *user_data, char *data, size_t len)
{
  struct nlsml_parser *parser = (struct nlsml_parser *)user_data;
  if (!parser) {
    if(globals.logging_callback) {
      globals.logging_callback(NULL, CSPEECH_LOG_INFO, "Missing parser\n");
    }
    return IKS_BADXML;
  }
  if (parser->cur) {
    struct tag_def *def = parser->cur->tag_def;
    if (def) {
      return def->cdata_fn(parser, data, len);
    }
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_INFO, "Missing definition for <%s>\n", parser->cur->name);
    }
    return IKS_BADXML;
  }
  return IKS_OK;
}

/**
 * Parse the result, looking for noinput/nomatch/match
 * @param result the NLSML result to parse
 * @param uuid optional UUID for logging
 * @return true if successful
 */
enum nlsml_match_type nlsml_parse(const char *result, const char *uuid)
{
  struct nlsml_parser parser = { 0 };
  parser.uuid = uuid;
  if (!cspeech_zstr(result)) {
    iksparser *p = iks_sax_new(&parser, tag_hook, cdata_hook);
    if (iks_parse(p, result, 0, 1) == IKS_OK) {
      /* check result */
      if (parser.match) {
        return NMT_MATCH;
      }
      if (parser.nomatch) {
        return NMT_NOMATCH;
      }
      if (parser.noinput) {
        return NMT_NOINPUT;
      }
      if(globals.logging_callback) {
        globals.logging_callback(&parser, CSPEECH_LOG_INFO, "NLSML result does not have match/noinput/nomatch!\n");
      }
    } else {
      if(globals.logging_callback) {
        globals.logging_callback(&parser, CSPEECH_LOG_INFO, "Failed to parse NLSML!\n");
      }
    }
    iks_parser_delete(p);
  } else {
    if(globals.logging_callback) {
      globals.logging_callback(&parser, CSPEECH_LOG_INFO, "Missing NLSML result\n");
    }
  }
  return NMT_BAD_XML;
}

#define NLSML_NS "http://www.ietf.org/xml/ns/mrcpv2"

/**
 * Makes NLSML result to conform to mrcpv2
 * @param result the potentially non-conforming result
 * @return the conforming result
 */
iks *nlsml_normalize(const char *result)
{
  iks *result_xml = NULL;
  iksparser *p = iks_dom_new(&result_xml);
  if (iks_parse(p, result, 0, 1) == IKS_OK && result_xml) {
    /* for now, all that is needed is to set the proper namespace */
    iks_insert_attrib(result_xml, "xmlns", NLSML_NS);
  } else {
    /* unexpected ... */
    if(globals.logging_callback) {
      globals.logging_callback(NULL, CSPEECH_LOG_INFO, "Failed to normalize NLSML result: %s\n", result);
    }
    if (result_xml) {
      iks_delete(result_xml);
    }
  }
  iks_parser_delete(p);
  return result_xml;
}

/**
 * @return true if digit is a DTMF
 */
static int isdtmf(const char digit)
{
  switch(digit) {
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
  case '*':
  case '#':
  case 'a':
  case 'A':
  case 'b':
  case 'B':
  case 'c':
  case 'C':
  case 'd':
  case 'D':
    return 1;
  }
  return 0;
}

/**
 * Construct an NLSML result for digit match
 * @param digits the matching digits
 * @param interpretation the optional digit interpretation
 * @return the NLSML <result>
 */
iks *nlsml_create_dtmf_match(const char *digits, const char *interpretation)
{
  iks *result = iks_new("result");
  iks_insert_attrib(result, "xmlns", NLSML_NS);
  iks_insert_attrib(result, "xmlns:xf", "http://www.w3.org/2000/xforms");
  if (!cspeech_zstr(digits)) {
    int first = 1;
    int i;
    int num_digits = strlen(digits);
    std::stringstream stream;
    const char *utterance;

    iks *interpretation_node = iks_insert(result, "interpretation");
    iks *input_node = iks_insert(interpretation_node, "input");
    iks *instance_node = iks_insert(interpretation_node, "instance");
    iks_insert_attrib(input_node, "mode", "dtmf");
    iks_insert_attrib(input_node, "confidence", "100");

    for (i = 0; i < num_digits; i++) {
      if (isdtmf(digits[i])) {
        if (first) {
          stream << digits[i];
          first = 0;
        } else {
          stream << " " << digits[i];
        }
      }
    }
    utterance = stream.str().c_str();
    iks_insert_cdata(input_node, utterance, strlen(utterance));

    if (cspeech_zstr(interpretation)) {
      iks_insert_cdata(instance_node, utterance, strlen(utterance));
    } else {
      iks_insert_cdata(instance_node, interpretation, strlen(interpretation));
    }
  }
  return result;
}

/**
 * Initialize NLSML parser.  This function is not thread safe.
 */
int nlsml_init(void)
{
  if (globals.init) {
    return 1;
  }

  globals.init = true;
  globals.logging_callback = NULL;

  add_root_tag_def("result", process_attribs_ignore, process_cdata_ignore, "interpretation");
  add_tag_def("interpretation", process_attribs_ignore, process_cdata_ignore, "input,model,xf:model,instance,xf:instance");
  add_tag_def("input", process_attribs_ignore, process_cdata_match, "input,nomatch,noinput");
  add_tag_def("noinput", process_noinput, process_cdata_bad, "");
  add_tag_def("nomatch", process_nomatch, process_cdata_ignore, "");
  add_tag_def("model", process_attribs_ignore, process_cdata_ignore, "ANY");
  add_tag_def("xf:model", process_attribs_ignore, process_cdata_ignore, "ANY");
  add_tag_def("instance", process_attribs_ignore, process_cdata_ignore, "ANY");
  add_tag_def("xf:instance", process_attribs_ignore, process_cdata_ignore, "ANY");
  add_tag_def("ANY", process_attribs_ignore, process_cdata_ignore, "ANY");

  return 1;
}
#endif

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
