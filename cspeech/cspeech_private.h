/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2013-2014, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * cspeech_private.h
 *
 */
#ifndef CSPEECH_PRIVATE_H
#define CSPEECH_PRIVATE_H

#include <map>
#include <string>
#include <vector>

#include "cspeech.h"

struct srgs_node;
struct srgs_grammar;
struct srgs_parser;

/** function to handle tag attributes */
typedef int (* tag_attribs_fn)(srgs_grammar *, char **);
/** function to handle tag CDATA */
typedef int (* tag_cdata_fn)(srgs_grammar *, const std::string &);


/**
 * Tag definition
 */
struct tag_definition {
  tag_attribs_fn attribs_fn;
  tag_cdata_fn cdata_fn;
  bool is_root;
  std::map<std::string, std::string> children_tags;
};

/**
 * SRGS node types
 */
enum srgs_node_type {
  /** anything */
  SNT_ANY,
  /** <grammar> */
  SNT_GRAMMAR,
  /** <rule> */
  SNT_RULE,
  /** <one-of> */
  SNT_ONE_OF,
  /** <item> */
  SNT_ITEM,
  /** <ruleref> unresolved reference to node */
  SNT_UNRESOLVED_REF,
  /** <ruleref> resolved reference to node */
  SNT_REF,
  /** <item> string */
  SNT_STRING,
  /** <tag> */
  SNT_TAG,
  /** <lexicon> */
  SNT_LEXICON,
  /** <example> */
  SNT_EXAMPLE,
  /** <token> */
  SNT_TOKEN,
  /** <meta> */
  SNT_META,
  /** <metadata> */
  SNT_METADATA
};

/**
 * <rule> value
 */
struct rule_value {
  bool is_public;
  std::string id;
  std::string regex;
};

/**
 * <item> value
 */
struct item_value {
  int repeat_min;
  int repeat_max;
  std::string weight;
  int tag;
};

/**
 * <ruleref> value
 */
struct ref_value {
  srgs_node *node;
  std::string uri;
};

/**
 * A node in the SRGS parse tree
 */
struct srgs_node {
  /** Name of node */
  std::string name;
  /** Type of node */
  srgs_node_type type;
  /** Node value */
  struct {
    std::string root;
    std::string str;
    ref_value ref;
    rule_value rule;
    item_value item;
  } value;
  /** parent node */
  srgs_node *parent;
  /** child node */
  srgs_node *child;
  /** sibling node */
  srgs_node *next;
  /** number of child nodes */
  int num_children;
  /** tag handling data */
  tag_definition *tag_def;
  /** True if node has been inspected for loops */
  bool visited;
};

/**
 * A parsed grammar
 */
struct srgs_grammar {
  srgs_grammar(const std::string &uuid);
  ~srgs_grammar();
  pcre *get_compiled_regex(void);
  srgs_match_type match(const std::string &input, std::string &interpretation);
  const std::string &to_regex(void);
  const std::string &to_jsgf(void);
  const std::string &to_jsgf_file(const std::string &basedir, const std::string &ext);

  /** current node being parsed */
  srgs_node *cur;
  /** rule names mapped to node */
  std::map<std::string, srgs_node *> rules;
  /** possible matching tags */
  std::vector<std::string> tags;
  /** grammar encoding */
  std::string encoding;
  /** grammar language */
  std::string language;
  /** true if digit grammar */
  int digit_mode;
  /** grammar parse tree root */
  srgs_node *root;
  /** root rule */
  srgs_node *root_rule;
  /** compiled grammar regex */
  pcre *compiled_regex;
  /** grammar in regex format */
  std::string regex;
  /** grammar in JSGF format */
  std::string jsgf;
  /** grammar as JSGF file */
  std::string jsgf_file_name;
  /** synchronizes access to this grammar */
  //pthread_mutex_t *mutex;
  /** optional uuid for logging */
  std::string uuid;
};

/**
 * The SRGS SAX parser
 */
struct srgs_parser {
  srgs_parser(const std::string &uuid);
  ~srgs_parser();
  srgs_grammar *parse(const std::string &document);

  /** grammar cache */
  std::map<std::string, srgs_grammar *> cache;
  /** cache mutex */
  //switch_mutex_t *mutex;
  /** optional uuid for logging */
  std::string uuid;
};

#endif
