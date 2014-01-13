/*
 * cspeech - Speech document (SSML, SRGS, NLSML) modelling and matching for C
 * Copyright (C) 2013-2014, Grasshopper
 *
 * License: MIT
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * srgs.cc -- Transforms SRGS into regex rules
 *
 */

#include <iksemel.h>
#include <pcre.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sstream>
#include <climits>

#include "cspeech_private.h"
#include "cspeech.h"

#define MAX_RECURSION 100

/**
 * library configuration
 */
static struct {
  /** true if initialized */
  bool init;
  /** Mapping of tag name to definition */
  std::map<std::string, tag_definition *> tag_defs;
} globals;


/**
 * Convert entity name to node type
 * @param name of entity
 * @return the type or ANY
 */
static srgs_node_type string_to_node_type(const std::string &name)
{
  if (name == "grammar") {
    return SNT_GRAMMAR;
  }
  if (name == "item") {
    return SNT_ITEM;
  }
  if (name == "one-of") {
    return SNT_ONE_OF;
  }
  if (name == "ruleref") {
    return SNT_UNRESOLVED_REF;
  }
  if (name =="rule") {
    return SNT_RULE;
  }
  if (name == "tag") {
    return SNT_TAG;
  }
  if (name == "lexicon") {
    return SNT_LEXICON;
  }
  if (name == "example") {
    return SNT_EXAMPLE;
  }
  if (name == "token") {
    return SNT_TOKEN;
  }
  if (name == "meta") {
    return SNT_META;
  }
  if (name == "metadata") {
    return SNT_METADATA;
  }
  return SNT_ANY;
}

/**
 * Log node
 */
void srgs_node::log_node_open(void)
{
  switch (type) {
    case SNT_ANY:
    case SNT_METADATA:
    case SNT_META:
    case SNT_TOKEN:
    case SNT_EXAMPLE:
    case SNT_LEXICON:
    case SNT_TAG:
    case SNT_ONE_OF:
    case SNT_GRAMMAR:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "<%s>\n", name.c_str());
      return;
    case SNT_RULE:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "<rule id='%s' scope='%s'>\n", value.rule.id.c_str(), value.rule.is_public ? "public" : "private");
      return;
    case SNT_ITEM:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "<item repeat='%i'>\n", value.item.repeat_min);
      return;
    case SNT_UNRESOLVED_REF:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "<ruleref (unresolved) uri='%s'\n", value.ref.uri.c_str());
      return;
    case SNT_REF:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "<ruleref uri='#%s'>\n", value.ref.node->value.rule.id.c_str());
      return;
    case SNT_STRING:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "%s\n", value.str.c_str());
      return;
  }
}

/**
 * Log node
 */
void srgs_node::log_node_close(void)
{
  switch (type) {
    case SNT_GRAMMAR:
    case SNT_RULE:
    case SNT_ONE_OF:
    case SNT_ITEM:
    case SNT_REF:
    case SNT_TAG:
    case SNT_LEXICON:
    case SNT_EXAMPLE:
    case SNT_TOKEN:
    case SNT_META:
    case SNT_METADATA:
    case SNT_ANY:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "</%s>\n", name.c_str());
      return;
    case SNT_UNRESOLVED_REF:
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "</ruleref (unresolved)>\n");
      return;
    case SNT_STRING:
      return;
  }
}

/**
 * @return the last sibling of node
 */
srgs_node *srgs_node::get_last_sibling(void)
{
  if (next) {
    return next->get_last_sibling();
  }
  return this;
}

/**
 * Add child node
 * @param name the child node name
 * @param type the child node type
 * @return the child node
 */
srgs_node *srgs_node::insert(const std::string &name, srgs_node_type type)
{
  srgs_node *sibling = child ? child->get_last_sibling() : 0;
  srgs_node *new_child = new srgs_node(name, type);
  num_children++;
  new_child->parent = this;
  if (sibling) {
    sibling->next = new_child;
  } else {
    child = new_child;
  }
  return new_child;
}

/**
 * Add string child node
 * @param str string to add - this function does not copy the string
 * @return the string child node
 */
srgs_node *srgs_node::insert_string(const std::string &str)
{
  srgs_node *new_child = insert(str, SNT_STRING);
  new_child->value.str = str;
  return new_child;
}

/**
 * Add a definition for a tag
 * @param tag the name
 * @param attribs_fn the function to handle the tag attributes
 * @param cdata_fn the function to handler the tag CDATA
 * @param children_tags comma-separated list of valid child tag names
 * @return the definition
 */
static tag_definition *add_tag_def(const std::string &tag, tag_attribs_fn attribs_fn, tag_cdata_fn cdata_fn, const std::string &children_tags)
{
  tag_definition *def = new tag_definition;
  if (children_tags != "") {
    std::stringstream ss(children_tags);
    std::string item;
    while (std::getline(ss, item, ',')) {
      def->children_tags[item] = item;
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
static struct tag_definition *add_root_tag_def(const std::string &tag, tag_attribs_fn attribs_fn, tag_cdata_fn cdata_fn, const std::string &children_tags)
{
  tag_definition *def = add_tag_def(tag, attribs_fn, cdata_fn, children_tags);
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
static int process_tag(struct srgs_grammar *grammar, const char *name, char **atts)
{
  struct srgs_node *cur = grammar->cur;
  if (cur->tag_def->is_root && cur->parent == 0) {
    /* no parent for ROOT tags */
    return cur->tag_def->attribs_fn(grammar, atts);
  } else if (!cur->tag_def->is_root && cur->parent) {
    /* check if this child is allowed by parent node */
    tag_definition *parent_def = cur->parent->tag_def;
    if (parent_def->children_tags.count("ANY") > 0 ||
      parent_def->children_tags.count(name) > 0) {
      return cur->tag_def->attribs_fn(grammar, atts);
    } else {
      cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<%s> cannot be a child of <%s>\n", name, cur->parent->name.c_str());
    }
  } else if (cur->tag_def->is_root && cur->parent != 0) {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<%s> must be the root element\n", name);
  } else {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<%s> cannot be a root element\n", name);
  }
  return IKS_BADXML;
}

/**
 * Handle tag attributes that are ignored
 * @param grammar the grammar
 * @param atts the attributes
 * @return IKS_OK
 */
static int process_attribs_ignore(struct srgs_grammar *grammar, char **atts)
{
  return IKS_OK;
}

/**
 * Handle CDATA that is ignored
 * @param grammar the grammar
 * @param data the CDATA
 * @return IKS_OK
 */
static int process_cdata_ignore(struct srgs_grammar *grammar, const std::string &data)
{
  return IKS_OK;
}

/**
 * Handle CDATA that is not allowed
 * @param grammar the grammar
 * @param data the CDATA
 * @return IKS_BADXML if any printable characters
 */
static int process_cdata_bad(struct srgs_grammar *grammar, const std::string &data)
{
  int i;
  for (i = 0; i < data.size(); i++) {
    if (isgraph(data[i])) {
      cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Unexpected CDATA for <%s>\n", grammar->cur->name.c_str());
      return IKS_BADXML;
    }
  }
  return IKS_OK;
}

/**
 * Process <rule> attributes
 * @param grammar the grammar state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_rule(struct srgs_grammar *grammar, char **atts)
{
  srgs_node *rule = grammar->cur;
  rule->value.rule.is_public = 0;
  rule->value.rule.id = "";
  if (atts) {
    int i = 0;
    while (atts[i]) {
      if (!strcmp("scope", atts[i])) {
        rule->value.rule.is_public = !cspeech_zstr(atts[i + 1]) && !strcmp("public", atts[i + 1]);
      } else if (!strcmp("id", atts[i])) {
        if (!cspeech_zstr(atts[i + 1])) {
          rule->value.rule.id = std::string(atts[i + 1]);
        }
      }
      i += 2;
    }
  }

  if (rule->value.rule.id == "") {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Missing rule ID: %s\n", rule->value.rule.id.c_str());
    return IKS_BADXML;
  }

  if (grammar->rules.count(rule->value.rule.id) > 0) {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Duplicate rule ID: %s\n", rule->value.rule.id.c_str());
    return IKS_BADXML;
  }
  grammar->rules[rule->value.rule.id] = rule;

  return IKS_OK;
}

/**
 * Process <ruleref> attributes
 * @param grammar the grammar state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_ruleref(srgs_grammar *grammar, char **atts)
{
  srgs_node *ruleref = grammar->cur;
  if (atts) {
    int i = 0;
    while (atts[i]) {
      if (!strcmp("uri", atts[i])) {
        char *uri = atts[i + 1];
        if (cspeech_zstr(uri)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Empty <ruleref> uri\n");
          return IKS_BADXML;
        }
        /* only allow local reference */
        if (uri[0] != '#' || strlen(uri) < 2) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Only local rule refs allowed\n");
          return IKS_BADXML;
        }
        ruleref->value.ref.uri = std::string(uri);
        return IKS_OK;
      }
      i += 2;
    }
  }
  return IKS_OK;
}

/**
 * Process <item> attributes
 * @param grammar the grammar state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_item(struct srgs_grammar *grammar, char **atts)
{
  srgs_node *item = grammar->cur;
  item->value.item.repeat_min = 1;
  item->value.item.repeat_max = 1;
  item->value.item.weight = "";
  if (atts) {
    int i = 0;
    while (atts[i]) {
      if (!strcmp("repeat", atts[i])) {
        /* repeats of 0 are not supported by this code */
        char *repeat = atts[i + 1];
        if (cspeech_zstr(repeat)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Empty <item> repeat atribute\n");
          return IKS_BADXML;
        }
        if (cspeech_is_number(repeat)) {
          /* single number */
          int repeat_val = atoi(repeat);
          if (repeat_val < 1) {
            cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<item> repeat must be >= 0\n");
            return IKS_BADXML;
          }
          item->value.item.repeat_min = repeat_val;
          item->value.item.repeat_max = repeat_val;
        } else {
          /* range */
          std::string min = repeat;
          std::string max;
          std::string::size_type max_pos = min.find("-");
          if (max_pos != std::string::npos) {
            max = min.substr(max_pos + 1);
          } else {
            cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<item> repeat must be a number or range\n");
            return IKS_BADXML;
          }
          if (cspeech_is_number(min) && (cspeech_is_number(max) || max == "")) {
            int min_val = atoi(min.c_str());
            int max_val = max == "" ? INT_MAX : atoi(max.c_str());
            /* max must be >= min and > 0
               min must be >= 0 */
            if ((max_val <= 0) || (max_val < min_val) || (min_val < 0)) {
              cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<item> repeat range invalid\n");
              return IKS_BADXML;
            }
            item->value.item.repeat_min = min_val;
            item->value.item.repeat_max = max_val;
          } else {
            cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<item> repeat range is not a number\n");
            return IKS_BADXML;
          }
        }
      } else if (!strcmp("weight", atts[i])) {
        const char *weight = atts[i + 1];
        if (cspeech_zstr(weight) || !cspeech_is_number(weight) || atof(weight) < 0) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<item> weight is not a number >= 0\n");
          return IKS_BADXML;
        }
        item->value.item.weight = std::string(weight);
      }
      i += 2;
    }
  }
  return IKS_OK;
}

/**
 * Process <grammar> attributes
 * @param grammar the grammar state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_grammar(srgs_grammar *grammar, char **atts)
{
  if (grammar->root) {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Only one <grammar> tag allowed\n");
    return IKS_BADXML;
  }
  grammar->root = grammar->cur;
  if (atts) {
    int i = 0;
    while (atts[i]) {
      if (!strcmp("mode", atts[i])) {
        char *mode = atts[i + 1];
        if (cspeech_zstr(mode)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<grammar> mode is missing\n");
          return IKS_BADXML;
        }
        grammar->digit_mode = !strcasecmp(mode, "dtmf");
      } else if (!strcmp("encoding", atts[i])) {
        char *encoding = atts[i + 1];
        if (cspeech_zstr(encoding)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<grammar> encoding is empty\n");
          return IKS_BADXML;
        }
        grammar->encoding = std::string(encoding);
      } else if (!strcmp("language", atts[i])) {
        char *language = atts[i + 1];
        if (cspeech_zstr(language)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<grammar> language is empty\n");
          return IKS_BADXML;
        }
        grammar->language = std::string(language);
      } else if (!strcmp("root", atts[i])) {
        char *root = atts[i + 1];
        if (cspeech_zstr(root)) {
          cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "<grammar> root is empty\n");
          return IKS_BADXML;
        }
        grammar->cur->value.root = std::string(root);
      }
      i += 2;
    }
  }
  return IKS_OK;
}

/**
 * Process a tag
 */
static int tag_hook(void *user_data, char *name, char **atts, int type)
{
  int result = IKS_OK;
  srgs_grammar *grammar = (srgs_grammar *)user_data;

  if (type == IKS_OPEN || type == IKS_SINGLE) {
    srgs_node_type ntype = string_to_node_type(name);
    if (grammar->cur) {
      grammar->cur = grammar->cur->insert(name, ntype);
    } else {
      grammar->cur = new srgs_node(name, ntype);
    }
    std::map<std::string, tag_definition *>::iterator i;
    i = globals.tag_defs.find(name);
    if (i == globals.tag_defs.end()) {
      grammar->cur->tag_def = globals.tag_defs["ANY"];
    } else {
      grammar->cur->tag_def = i->second;
    }
    result = process_tag(grammar, name, atts);
    grammar->cur->log_node_open();
  }

  if (type == IKS_CLOSE || type == IKS_SINGLE) {
    grammar->cur->log_node_close();
    grammar->cur = grammar->cur->get_parent();
  }

  return result;
}

/**
 * Process <tag> CDATA
 * @param grammar the grammar
 * @param data the CDATA
 * @return IKS_OK
 */
static int process_cdata_tag(srgs_grammar *grammar, const std::string &data)
{
  srgs_node *item = grammar->cur->parent;
  if (item && item->type == SNT_ITEM && data != "") {
    /* grammar gets the tag name, item gets the unique tag number */
	grammar->tags.push_back(data);
    item->value.item.tag = grammar->tags.size();
  }
  return IKS_OK;
}

/**
 * Process CDATA grammar tokens
 * @param grammar the grammar
 * @param data the CDATA
 * @return IKS_OK
 */
static int process_cdata_tokens(srgs_grammar *grammar, const std::string &data)
{
  srgs_node *string_node = grammar->cur;
  if (grammar->digit_mode) {
    for (int i = 0; i < data.size(); i++) {
      if (isdigit(data[i]) || data[i] == '#' || data[i] == '*') {
        string_node = string_node->insert_string(data.substr(i, 1));
        string_node->log_node_open();
      }
    }
  } else {
    std::string data_dup = data;
    std::string::size_type begin = data_dup.find_first_not_of(" \t");
    std::string::size_type end = data_dup.find_last_not_of(" \t");
    if (begin != std::string::npos && begin != end) {
      data_dup = data_dup.substr(begin, end);
      string_node = string_node->insert_string(data_dup);
    }
  }
  return IKS_OK;
}

/**
 * Process cdata
 * @param user_data the grammar
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_OK
 */
static int cdata_hook(void *user_data, char *data, size_t len)
{
  srgs_grammar *grammar = (srgs_grammar *)user_data;
  if (!grammar) {
    cspeech_log_printf(CSPEECH_LOG_INFO, 0, "Missing grammar\n");
    return IKS_BADXML;
  }
  if (grammar->cur && data && len) {
    if (grammar->cur->tag_def) {
      return grammar->cur->tag_def->cdata_fn(grammar, std::string(data, len));
    }
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Missing definition for <%s>\n", grammar->cur->name.c_str());
    return IKS_BADXML;
  }
  return IKS_OK;
}

/**
 * Create a node in the grammar tree
 */
srgs_node::srgs_node(const std::string &name, srgs_node_type type) :
  name(name),
  type(type),
  parent(0),
  child(0),
  next(0),
  num_children(0),
  tag_def(0),
  visited(false)
{
}

/**
 * Create a node in the grammar tree
 */
srgs_node::srgs_node() :
  type(SNT_ANY),
  parent(0),
  child(0),
  next(0),
  num_children(0),
  tag_def(0),
  visited(false)
{
}

/**
 * Destroy the tree
 */
srgs_node::~srgs_node()
{
  /* TODO */
}

/**
 * Create a new parsed grammar
 * @param parser
 */
srgs_grammar::srgs_grammar(const std::string &uuid) :
  cur(0),
  digit_mode(false),
  root(0),
  root_rule(0),
  compiled_regex(0),
  uuid(uuid)
{
}

/**
 * Grammar destructor
 */
srgs_grammar::~srgs_grammar() {
  if (compiled_regex) {
    pcre_free(compiled_regex);
  }
  if (jsgf_file_name != "") {
    unlink(jsgf_file_name.c_str());
  }
  if (root) {
    delete root;
  }
}

/**
 * Create a new parser.
 * @param uuid optional uuid for logging
 */
srgs_parser::srgs_parser(const std::string &uuid) : 
  uuid(uuid)
{
  //switch_mutex_init(&parser->mutex, SWITCH_MUTEX_NESTED);
}

/**
 * Destroy the parser.
 */
srgs_parser::~srgs_parser()
{
}

/**
 * Create regexes
 * @param grammar the grammar
 * @param node root node
 * @return 1 if successful
 */
static int create_regexes(srgs_grammar *grammar, srgs_node *node, std::stringstream &stream)
{
  node->log_node_open();
  switch (node->type) {
    case SNT_GRAMMAR:
      if (node->child) {
        int num_rules = 0;
        srgs_node *child = node->child;
        if (grammar->root_rule) {
          std::stringstream new_stream;
          if (!create_regexes(grammar, grammar->root_rule, new_stream)) {
            return 0;
          }
          grammar->regex = "^";
          grammar->regex += grammar->root_rule->value.rule.regex;
          grammar->regex += "$";
        } else {
          std::stringstream new_stream;
          if (node->num_children > 1) {
            new_stream << "^(?:";
          } else {
            new_stream << "^";
          }
          for (; child; child = child->next) {
            if (!create_regexes(grammar, child, new_stream)) {
              return 0;
            }
            if (child->type == SNT_RULE && child->value.rule.is_public) {
              if (num_rules > 0) {
                new_stream << "|";
              }
              new_stream << child->value.rule.regex;
              num_rules++;
            }
          }
          if (node->num_children > 1) {
            new_stream << ")$";
          } else {
            new_stream << "$";
          }
          grammar->regex = new_stream.str();
        }
        cspeech_log_printf(CSPEECH_LOG_DEBUG, grammar->uuid.c_str(), "document regex = %s\n", grammar->regex.c_str());
      }
      break;
    case SNT_RULE:
      if (node->value.rule.regex != "") {
        return 1;
      } else if (node->child) {
        srgs_node *item = node->child;
        std::stringstream new_stream;
        for (; item; item = item->next) {
          if (!create_regexes(grammar, item, new_stream)) {
            cspeech_log_printf(CSPEECH_LOG_DEBUG, grammar->uuid.c_str(), "%s regex failed = %s\n", node->value.rule.id.c_str(), node->value.rule.regex.c_str());
            return 0;
          }
        }
        node->value.rule.regex = new_stream.str();
        cspeech_log_printf(CSPEECH_LOG_DEBUG, grammar->uuid.c_str(), "%s regex = %s\n", node->value.rule.id.c_str(), node->value.rule.regex.c_str());
      }
      break;
    case SNT_STRING: {
      int i;
      for (i = 0; i < node->value.str.length(); i++) {
        switch (node->value.str[i]) {
          case '[':
          case '\\':
          case '^':
          case '$':
          case '.':
          case '|':
          case '?':
          case '*':
          case '+':
          case '(':
          case ')':
            /* escape special PCRE regex characters */
            stream << "\\";
            stream.put(node->value.str[i]);
            break;
          default:
            stream.put(node->value.str[i]);
            break;
        }
      }
      if (node->child) {
        if (!create_regexes(grammar, node->child, stream)) {
          return 0;
        }
      }
      break;
    }
    case SNT_ITEM:
      if (node->child) {
        srgs_node *item = node->child;
        if (node->value.item.repeat_min != 1 || node->value.item.repeat_max != 1 || node->value.item.tag) {
          if (node->value.item.tag) {
            stream << "(?P<" << node->value.item.tag << ">";
          } else {
            stream << "(?:";
          }
        }
        for(; item; item = item->next) {
          if (!create_regexes(grammar, item, stream)) {
            return 0;
          }
        }
        if (node->value.item.repeat_min != 1 || node->value.item.repeat_max != 1) {
          if (node->value.item.repeat_min != node->value.item.repeat_max) {
            if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == INT_MAX) {
              stream << ")*";
            } else if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == 1) {
              stream << ")?";
            } else if (node->value.item.repeat_min == 1 && node->value.item.repeat_max == INT_MAX) {
              stream << ")+";
            } else if (node->value.item.repeat_max == INT_MAX) {
              stream << "){" << node->value.item.repeat_min << ",1000}";
            } else {
              stream << "){" << node->value.item.repeat_min << "," << node->value.item.repeat_max << "}";
            }
          } else {
            stream << "){" << node->value.item.repeat_min << "}";
          }
        } else if (node->value.item.tag) {
          stream << ")";
        }
      }
      break;
    case SNT_ONE_OF:
      if (node->child) {
        srgs_node *item = node->child;
        if (node->num_children > 1) {
          stream << "(?:";
        }
        for (; item; item = item->next) {
          if (item != node->child) {
            stream << "|";
          }
          if (!create_regexes(grammar, item, stream)) {
            return 0;
          }
        }
        if (node->num_children > 1) {
          stream << ")";
        }
      }
      break;
    case SNT_REF: {
      srgs_node *rule = node->value.ref.node;
      if (rule->value.rule.regex == "") {
        std::stringstream new_stream;
        cspeech_log_printf(CSPEECH_LOG_DEBUG, grammar->uuid.c_str(), "ruleref: create %s regex\n", rule->value.rule.id.c_str());
        if (!create_regexes(grammar, rule, new_stream)) {
          return 0;
        }
      }
      stream << rule->value.rule.regex;
      break;
    }
    case SNT_ANY:
    default:
      /* ignore */
      return 1;
  }
  node->log_node_close();
  return 1;
}

/**
 * Compile regex
 */
pcre *srgs_grammar::get_compiled_regex(void)
{
  int erroffset = 0;
  const char *errptr = "";
  int options = 0;
  std::string regex;

  //switch_mutex_lock(grammar->mutex);
  if (!compiled_regex) {
	regex = to_regex();
    if (regex != "" && !(compiled_regex = pcre_compile(regex.c_str(), options, &errptr, &erroffset, NULL))) {
      cspeech_log_printf(CSPEECH_LOG_WARNING, uuid.c_str(), "Failed to compile grammar regex: %s\n", regex.c_str());
    }
  }
  //switch_mutex_unlock(grammar->mutex);
  return compiled_regex;
}

/**
 * Resolve all unresolved references and detect loops.
 * @param grammar the grammar
 * @param node the current node
 * @param level the recursion level
 */
static int resolve_refs(srgs_grammar *grammar, srgs_node *node, int level)
{
  node->log_node_open();
  if (node->visited) {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Loop detected.\n");
    return 0;
  }
  node->visited = 1;

  if (level > MAX_RECURSION) {
    cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Recursion too deep.\n");
    return 0;
  }

  if (node->type == SNT_GRAMMAR && node->value.root == "") {
    std::map<std::string, srgs_node *>::iterator i;
    i = grammar->rules.find(node->value.root);
    if (i == grammar->rules.end()) {
      cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Root rule not found: %s\n", node->value.root.c_str());
      return 0;
    }
    grammar->root_rule = i->second;
  }

  if (node->type == SNT_UNRESOLVED_REF) {
    /* resolve reference to local rule- drop first character # from URI */
    std::map<std::string, srgs_node *>::iterator i;
    i = grammar->rules.find(node->value.ref.uri.substr(1));
    if (i == grammar->rules.end()) {
      cspeech_log_printf(CSPEECH_LOG_INFO, grammar->uuid.c_str(), "Local rule not found: %s\n", node->value.ref.uri.c_str());
      return 0;
    }

    /* link to rule */
    node->type = SNT_REF;
    node->value.ref.node = i->second;
  }

  /* travel through rule to detect loops */
  if (node->type == SNT_REF) {
    if (!resolve_refs(grammar, node->value.ref.node, level + 1)) {
      return 0;
    }
  }

  /* resolve children refs */
  if (node->child) {
    srgs_node *child = node->child;
    for (; child; child = child->next) {
      if (!resolve_refs(grammar, child, level + 1)) {
        return 0;
      }
    }
  }

  node->visited = 0;
  node->log_node_close();
  return 1;
}

/**
 * Parse the document into rules to match
 * @param document the document to parse
 * @return the parsed grammar if successful
 */
srgs_grammar *srgs_parser::parse(const std::string &document)
{
  srgs_grammar *grammar = 0;

  if (document == "") {
    cspeech_log_printf(CSPEECH_LOG_INFO, uuid.c_str(), "Missing grammar document\n");
    return 0;
  }

  /* check for cached grammar */
  //switch_mutex_lock(parser->mutex);
  std::map<std::string, srgs_grammar *>::iterator i = cache.find(document);
  if (i == cache.end()) {
    int result = 0;
    iksparser *p;
    cspeech_log_printf(CSPEECH_LOG_DEBUG, uuid.c_str(), "Parsing new grammar\n");
    grammar = new srgs_grammar(uuid);
    p = iks_sax_new(grammar, tag_hook, cdata_hook);
    if (iks_parse(p, document.c_str(), 0, 1) == IKS_OK) {
      if (grammar->root) {
        cspeech_log_printf(CSPEECH_LOG_DEBUG, uuid.c_str(), "Resolving references\n");
        if (resolve_refs(grammar, grammar->root, 0)) {
          result = 1;
        }
      } else {
        cspeech_log_printf(CSPEECH_LOG_INFO, uuid.c_str(), "Nothing to parse!\n");
      }
    }
    iks_parser_delete(p);
    if (result) {
      cache[document] = grammar;
    } else {
      if (grammar) {
        delete grammar;
        grammar = 0;
      }
      cspeech_log_printf(CSPEECH_LOG_INFO, uuid.c_str(), "Failed to parse grammar\n");
    }
  } else {
    cspeech_log_printf(CSPEECH_LOG_DEBUG, uuid.c_str(), "Using cached grammar\n");
	grammar = i->second;
  }
  //switch_mutex_unlock(parser->mutex);

  return grammar;
}

/* TODO - add MAX_TAGS check back... */
#define MAX_TAGS 30
#define MAX_INPUT_SIZE 128
#define OVECTOR_SIZE MAX_TAGS
#define WORKSPACE_SIZE 1024

/**
 * Check if no more digits can be added to input and match
 * @param compiled_regex the regex used in the initial match
 * @param input the input to check
 * @return true if end of match (no more input can be added)
 */
static int is_match_end(pcre *compiled_regex, const std::string &input)
{
  int ovector[OVECTOR_SIZE];
  int input_size = input.size();
  char search_input[MAX_INPUT_SIZE + 2];
  const char *search_set = "0123456789#*ABCD";
  const char *search = strchr(search_set, input[input_size - 1]); /* start with last digit in input */
  int i = 0;

  /* For each digit in search_set, check if input + search_set digit is a potential match.
     If so, then this is not a match end.
   */
  sprintf(search_input, "%sZ", input.c_str());
  for (i = 0; i < 16; i++) {
    int result;
    if (!*search) {
      search = search_set;
    }
    search_input[input_size] = *search++;
    result = pcre_exec(compiled_regex, NULL, search_input, input_size + 1, 0, 0,
      ovector, sizeof(ovector) / sizeof(ovector[0]));
    if (result > 0) {
      cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "not match end\n");
      return 0;
    }
  }
  cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "is match end\n");
  return 1;
}

/**
 * Find a match
 * @param grammar the grammar to match
 * @param input the input to compare
 * @param interpretation the (optional) interpretation of the input result
 * @return the match result
 */
cspeech_srgs_match_type srgs_grammar::match(const std::string &input, std::string &interpretation)
{
  int result = 0;
  int ovector[OVECTOR_SIZE];
  pcre *compiled_regex;

  interpretation = "";

  if (input == "") {
    return CSMT_NO_MATCH;
  }
  if (input.length() > MAX_INPUT_SIZE) {
    cspeech_log_printf(CSPEECH_LOG_WARNING, 0, "input too large: %s\n", input.c_str());
    return CSMT_NO_MATCH;
  }

  if (!(compiled_regex = get_compiled_regex())) {
    return CSMT_NO_MATCH;
  }
  result = pcre_exec(compiled_regex, NULL, input.c_str(), input.length(), 0, PCRE_PARTIAL,
    ovector, OVECTOR_SIZE);

  cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "match = %i\n", result);
  if (result > 0) {
    int i;
    char buffer[MAX_INPUT_SIZE + 1];
    buffer[MAX_INPUT_SIZE] = '\0';

    /* find matching instance... */
    for (i = 1; i <= tags.size(); i++) {
      char substring_name[16] = { 0 };
      buffer[0] = '\0';
      snprintf(substring_name, 16, "%d", i);
      if (pcre_copy_named_substring(compiled_regex, input.c_str(), ovector, result, substring_name, buffer, MAX_INPUT_SIZE) != PCRE_ERROR_NOSUBSTRING && buffer[0]) {
        interpretation = tags[i - 1];
        break;
      }
    }

    if (is_match_end(compiled_regex, input)) {
      return CSMT_MATCH_END;
    }
    return CSMT_MATCH;
  }
  if (result == PCRE_ERROR_PARTIAL) {
    return CSMT_MATCH_PARTIAL;
  }

  return CSMT_NO_MATCH;
}

/**
 * Generate regex from SRGS document.  Call this after parsing SRGS document.
 * @param parser the parser
 * @return the regex
 */
const std::string &srgs_grammar::to_regex(void)
{
  static std::string nil_regex = "";
  //switch_mutex_lock(grammar->mutex);
  std::stringstream new_stream;
  if (regex == "" && !create_regexes(this, root, new_stream)) {
    //switch_mutex_unlock(grammar->mutex);
    return nil_regex;
  }
  //switch_mutex_unlock(grammar->mutex);
  return regex;
}

/**
 * Create JSGF grammar
 * @param parser the parser
 * @param node root node
 * @param stream set to NULL
 * @return 1 if successful
 */
static int create_jsgf(srgs_grammar *grammar, srgs_node *node, std::stringstream &stream)
{
  node->log_node_open();
  switch (node->type) {
    case SNT_GRAMMAR:
      if (node->child) {
        srgs_node *child;
        std::stringstream new_stream;

        new_stream << "#JSGF V1.0";
        if (grammar->encoding != "") {
          new_stream << " " << grammar->encoding;
          if (grammar->language != "") {
            new_stream << " " << grammar->language;
          }
        }

        new_stream << ";\ngrammar org.freeswitch.srgs_to_jsgf;\n"
                   << "public ";

        /* output root rule */
        if (grammar->root_rule) {
          if (!create_jsgf(grammar, grammar->root_rule, new_stream)) {
            return 0;
          }
        } else {
          int num_rules = 0;
          int first = 1;

          for (child = node->child; child; child = child->next) {
            if (child->type == SNT_RULE && child->value.rule.is_public) {
              num_rules++;
            }
          }

          if (num_rules > 1) {
            new_stream << "<root> =";
            for (child = node->child; child; child = child->next) {
              if (child->type == SNT_RULE && child->value.rule.is_public) {
                if (!first) {
                  new_stream << " |";
                }
                first = 0;
                new_stream << " <" << child->value.rule.id << ">";
              }
            }
            new_stream << ";\n";
          } else {
            for (child = node->child; child; child = child->next) {
              if (child->type == SNT_RULE && child->value.rule.is_public) {
                grammar->root_rule = child;
                if (!create_jsgf(grammar, child, new_stream)) {
                  return 0;
                } else {
                  break;
                }
              }
            }
          }
        }

        /* output all rule definitions */
        for (child = node->child; child; child = child->next) {
          if (child->type == SNT_RULE && child != grammar->root_rule) {
            if (!create_jsgf(grammar, child, new_stream)) {
              return 0;
            }
          }
        }
        grammar->jsgf = new_stream.str();
        cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "document jsgf = %s\n", grammar->jsgf.c_str());
      }
      break;
    case SNT_RULE:
      if (node->child) {
        srgs_node *item = node->child;
        stream << "<" << node->value.rule.id << "> =";
        for (; item; item = item->next) {
          if (!create_jsgf(grammar, item, stream)) {
            cspeech_log_printf(CSPEECH_LOG_DEBUG, 0, "%s jsgf rule failed\n", node->value.rule.id.c_str());
            return 0;
          }
        }
        stream << ";\n";
      }
      break;
    case SNT_STRING: {
      int len = node->value.str.length();
      int i;
      stream << " ";
      for (i = 0; i < len; i++) {
        switch (node->value.str[i]) {
          case '\\':
          case '*':
          case '+':
          case '/':
          case '(':
          case ')':
          case '[':
          case ']':
          case '{':
          case '}':
          case '=':
          case '<':
          case '>':
          case ';':
          case '|':
            stream << "\\";
            break;
          default:
            break;
        }
        stream.put(node->value.str[i]);
      }
      if (node->child) {
        if (!create_jsgf(grammar, node->child, stream)) {
          return 0;
        }
      }
      break;
    }
    case SNT_ITEM:
      if (node->child) {
        srgs_node *item;
        if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == 1) {
          /* optional item */
          stream << " [";
          for(item = node->child; item; item = item->next) {
            if (!create_jsgf(grammar, item, stream)) {
              return 0;
            }
          }
          stream << " ]";
        } else {
          /* minimum repeats */
          int i;
          for (i = 0; i < node->value.item.repeat_min; i++) {
            if (node->value.item.repeat_min != 1 && node->value.item.repeat_max != 1) {
              stream << " (";
            }
            for(item = node->child; item; item = item->next) {
              if (!create_jsgf(grammar, item, stream)) {
                return 0;
              }
            }
            if (node->value.item.repeat_min != 1 && node->value.item.repeat_max != 1) {
              stream << " )";
            }
          }
          if (node->value.item.repeat_max == INT_MAX) {
            stream << "*";
          } else {
            for (;i < node->value.item.repeat_max; i++) {
              stream << " [";
              for(item = node->child; item; item = item->next) {
                if (!create_jsgf(grammar, item, stream)) {
                  return 0;
                }
              }
              stream << " ]";
            }
          }
        }
      }
      break;
    case SNT_ONE_OF:
      if (node->child) {
        srgs_node *item = node->child;
        if (node->num_children > 1) {
          stream << " (";
        }
        for (; item; item = item->next) {
          if (item != node->child) {
            stream << " |";
          }
          stream << " (";
          if (!create_jsgf(grammar, item, stream)) {
            return 0;
          }
          stream << " )";
        }
        if (node->num_children > 1) {
          stream << " )";
        }
      }
      break;
    case SNT_REF: {
      srgs_node *rule = node->value.ref.node;
      stream << " <" << rule->value.rule.id << ">";
      break;
    }
    case SNT_ANY:
    default:
      /* ignore */
      return 1;
  }
  node->log_node_close();
  return 1;
}

/**
 * Generate JSGF from SRGS document.  Call this after parsing SRGS document.
 * @return the JSGF document or NULL
 */
const std::string &srgs_grammar::to_jsgf(void)
{
  static std::string nil_jsgf = "";
  //switch_mutex_lock(grammar->mutex);
  std::stringstream stream;
  if (jsgf == "" && !create_jsgf(this, root, stream)) {
    //switch_mutex_unlock(grammar->mutex);
    return nil_jsgf;
  }
  //switch_mutex_unlock(grammar->mutex);
  return jsgf;
}

/**
 * Generate JSGF file from SRGS document.  Call this after parsing SRGS document.
 * @param basedir the base path to use if file does not already exist
 * @param ext the extension to use
 * @return the path
 */
const std::string &srgs_grammar::to_jsgf_file(const std::string &basedir, const std::string &ext)
{
  static std::string nil_jsgf_file_name = "";
  //switch_mutex_lock(grammar->mutex);
  if (jsgf_file_name == "") {
    /* TODO generate UUID instead of "foo */
    FILE *file;
    std::string jsgf = to_jsgf();
    if (jsgf == "") {
      return nil_jsgf_file_name;
    }

    /* write grammar to file */
    jsgf_file_name = basedir + "/foo." + ext;
    if (!(file = fopen(jsgf_file_name.c_str(), "w"))) {
      cspeech_log_printf(CSPEECH_LOG_WARNING, 0, "Failed to create jsgf file: %s!\n", jsgf_file_name.c_str());
      jsgf_file_name = "";
      //switch_mutex_unlock(grammar->mutex);
      return nil_jsgf_file_name;
    }
    fwrite(jsgf.c_str(), sizeof(char), jsgf.length(), file);
    fclose(file);
  }
  //switch_mutex_unlock(grammar->mutex);
  return jsgf_file_name;
}

/**
 * Initialize SRGS parser.  This function is not thread safe.
 */
int srgs_init(void)
{
  if (globals.init) {
    return 1;
  }

  globals.init = true;

  add_root_tag_def("grammar", process_grammar, process_cdata_bad, "meta,metadata,lexicon,tag,rule");
  add_tag_def("ruleref", process_ruleref, process_cdata_bad, "");
  add_tag_def("token", process_attribs_ignore, process_cdata_ignore, "");
  add_tag_def("tag", process_attribs_ignore, process_cdata_tag, "");
  add_tag_def("one-of", process_attribs_ignore, process_cdata_tokens, "item");
  add_tag_def("item", process_item, process_cdata_tokens, "token,ruleref,item,one-of,tag");
  add_tag_def("rule", process_rule, process_cdata_tokens, "token,ruleref,item,one-of,tag,example");
  add_tag_def("example", process_attribs_ignore, process_cdata_ignore, "");
  add_tag_def("lexicon", process_attribs_ignore, process_cdata_bad, "");
  add_tag_def("meta", process_attribs_ignore, process_cdata_bad, "");
  add_tag_def("metadata", process_attribs_ignore, process_cdata_ignore, "ANY");
  add_tag_def("ANY", process_attribs_ignore, process_cdata_ignore, "ANY");

  return 1;
}
