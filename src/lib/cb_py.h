#ifndef CB_PY_H
#define CB_PY_H


#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline bool starts_with(const char *s, const char *prefix) {
  size_t a = strlen(prefix);
  return strncmp(s, prefix, a) == 0;
}
static inline bool ends_with(const char *s, const char *suffix) {
  size_t ls = strlen(s), lt = strlen(suffix);
  if (lt > ls)
    return false;
  return strcmp(s + (ls - lt), suffix) == 0;
}
static int cb_count_indent(const char *s) {
  int n = 0;
  for (; *s; s++) {
    if (*s == ' ')
      n++;
    else if (*s == '\t')
      n += 4;
    else
      break;
  }
  return n;
}
static char *cb_strdup_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int n = vsnprintf(NULL, 0, fmt, ap2);
  va_end(ap2);
  char *buf = (char *)malloc((size_t)n + 1);
  vsnprintf(buf, (size_t)n + 1, fmt, ap);
  va_end(ap);
  return buf;
}
static void cb_push_line(char ***out, int *count, const char *line) {
  *out = (char **)realloc(*out, (size_t)(*count + 1) * sizeof(char *));
  (*out)[(*count)++] = strdup(line);
}
static void cb_push_line_indent(char ***out, int *count, int depth,
                                const char *content) {
  int pad = depth * 2;
  size_t L = strlen(content);
  char *buf = (char *)malloc((size_t)pad + L + 1);
  memset(buf, ' ', (size_t)pad);
  memcpy(buf + pad, content, L + 1);
  cb_push_line(out, count, buf);
  free(buf);
}
static inline char *str_dup_trim(const char *s, int len) {
  while (len > 0 && isspace((unsigned char)s[0])) {
    s++;
    len--;
  }
  while (len > 0 && isspace((unsigned char)s[len - 1]))
    len--;
  char *out = (char *)malloc((size_t)len + 1);
  memcpy(out, s, (size_t)len);
  out[len] = '\0';
  return out;
}
static inline char *cb_str_append(char *dst, const char *add) {
  size_t a = dst ? strlen(dst) : 0;
  size_t b = add ? strlen(add) : 0;
  char *res = (char *)realloc(dst, a + b + 1);
  memcpy(res + a, add, b);
  res[a + b] = '\0';
  return res;
}
static char *cb_str_appendf(char *dst, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int need = vsnprintf(NULL, 0, fmt, ap2);
  va_end(ap2);
  char *buf = (char *)malloc((size_t)need + 1);
  vsnprintf(buf, (size_t)need + 1, fmt, ap);
  va_end(ap);
  char *res = cb_str_append(dst, buf);
  free(buf);
  return res;
}
static inline bool is_ident_char(char c) {
  return isalnum((unsigned char)c) || c == '_' || c == '$';
}
static inline bool is_string_literal(const char *s) {
  if (!s || !*s)
    return false;
  char c = *s;
  if (c != '"' && c != '\'')
    return false;
  size_t L = strlen(s);
  if (L < 2)
    return false;
  return s[L - 1] == c;
}
static inline bool is_numeric_literal(const char *s) {
  if (!s)
    return false;
  const char *p = s;
  if (*p == '+' || *p == '-')
    p++;
  bool has_digit = false, dot = false;
  while (*p) {
    if (isdigit((unsigned char)*p))
      has_digit = true;
    else if (*p == '.' && !dot)
      dot = true;
    else
      return false;
    p++;
  }
  return has_digit;
}

static char *normalize_condition_expr(const char *expr) {
  const char *p = expr;
  char *out = strdup("");
  while (*p) {
    if ((p == expr || !is_ident_char(p[-1])) && starts_with(p, "and") &&
        !is_ident_char(p[3])) {
      out = cb_str_append(out, "&&");
      p += 3;
    } else if ((p == expr || !is_ident_char(p[-1])) && starts_with(p, "or") &&
               !is_ident_char(p[2])) {
      out = cb_str_append(out, "||");
      p += 2;
    } else if ((p == expr || !is_ident_char(p[-1])) && starts_with(p, "not") &&
               !is_ident_char(p[3])) {
      out = cb_str_append(out, "!");
      p += 3;
    } else if ((p == expr || !is_ident_char(p[-1])) && starts_with(p, "True") &&
               !is_ident_char(p[4])) {
      out = cb_str_append(out, "1");
      p += 4;
    } else if ((p == expr || !is_ident_char(p[-1])) &&
               starts_with(p, "False") && !is_ident_char(p[5])) {
      out = cb_str_append(out, "0");
      p += 5;
    } else {
      char buf[2] = {*p, 0};
      out = cb_str_append(out, buf);
      p++;
    }
  }
  return out;
}

typedef struct {
  char *name;
  const char *ctype; // "int", "double", "char *", "T[]"
} Symbol;

static int sym_find(Symbol *symbols, int n, const char *name) {
  for (int i = 0; i < n; i++)
    if (strcmp(symbols[i].name, name) == 0)
      return i;
  return -1;
}

static int expr_mentions_symbol_of_type(const char *expr, Symbol *symbols,
                                        int n, const char *ctype) {
  for (int i = 0; i < n; i++) {
    if (!symbols[i].ctype || strcmp(symbols[i].ctype, ctype) != 0)
      continue;
    const char *name = symbols[i].name;
    const char *p = expr;
    size_t len = strlen(name);
    while ((p = strstr(p, name)) != NULL) {
      char b = (p == expr) ? ' ' : p[-1];
      char a = p[len];
      int left_ok = !(isalnum((unsigned char)b) || b == '_');
      int right_ok = !(isalnum((unsigned char)a) || a == '_');
      if (left_ok && right_ok)
        return 1;
      p += len;
    }
  }
  return 0;
}

static const char *infer_c_type_from_expr(const char *value, Symbol *symbols,
                                          int n) {
  if (!value || !*value)
    return "int";
  if (value[0] == '"' || value[0] == '\'')
    return "char *";
  if (expr_mentions_symbol_of_type(value, symbols, n, "char *"))
    return "char *";

  // If using list[index] -> element type
  for (int i = 0; i < n; i++) {
    if (symbols[i].ctype && ends_with(symbols[i].ctype, "[]")) {
      const char *name = symbols[i].name;
      const char *p = strstr(value, name);
      if (p) { // check for name[ ... ]
        const char *after = p + strlen(name);
        while (*after == ' ' || *after == '\t')
          after++;
        if (*after == '[') {
          static char buf[64];
          snprintf(buf, sizeof(buf), "%s", symbols[i].ctype);
          size_t L = strlen(buf);
          if (L >= 2)
            buf[L - 2] = '\0';
          return buf;
        }
      }
    }
  }

  // If contains '.', or refers to a known double, call double
  for (const char *p = value; *p; ++p)
    if (*p == '.')
      return "double";
  if (expr_mentions_symbol_of_type(value, symbols, n, "double"))
    return "double";
  if (is_numeric_literal(value))
    return (strchr(value, '.') ? "double" : "int");

  // Unknown identifiers present? default to int (don't block on raw C
  // variables).
  return "int";
}

static char **split_args(const char *s, int *out_count) {
  char **out = NULL;
  int n = 0, cap = 0;
  int dpar = 0, dbr = 0;
  int in_s = 0, in_d = 0;
  const char *start = s;
  for (const char *p = s;; p++) {
    char c = *p;
    bool end = (c == '\0');
    bool at_comma =
        (!end && c == ',' && dpar == 0 && dbr == 0 && !in_s && !in_d);
    if (at_comma || end) {
      int len = (int)(p - start);
      char *piece = str_dup_trim(start, len);
      if (n == cap) {
        cap = cap ? cap * 2 : 4;
        out = (char **)realloc(out, (size_t)cap * sizeof(char *));
      }
      out[n++] = piece;
      if (end)
        break;
      start = p + 1;
      continue;
    }
    if (!in_s && !in_d) {
      if (c == '(')
        dpar++;
      else if (c == ')') {
        if (dpar > 0)
          dpar--;
      } else if (c == '[')
        dbr++;
      else if (c == ']') {
        if (dbr > 0)
          dbr--;
      } else if (c == '\'')
        in_s = 1;
      else if (c == '"')
        in_d = 1;
    } else {
      if (in_s && c == '\'')
        in_s = 0;
      if (in_d && c == '"')
        in_d = 0;
    }
  }
  *out_count = n;
  return out;
}
static void free_split(char **arr, int n) {
  for (int i = 0; i < n; i++)
    free(arr[i]);
  free(arr);
}

static const char *ctype_to_fmt(const char *ctype) {
  if (!ctype)
    return NULL;
  if (strcmp(ctype, "int") == 0)
    return "%d";
  if (strcmp(ctype, "long") == 0 || strcmp(ctype, "long long") == 0)
    return "%lld";
  if (strcmp(ctype, "unsigned") == 0 || strcmp(ctype, "unsigned int") == 0)
    return "%u";
  if (strcmp(ctype, "float") == 0 || strcmp(ctype, "double") == 0)
    return "%f";
  if (strcmp(ctype, "char *") == 0)
    return "%s";
  if (strcmp(ctype, "bool") == 0)
    return "%d";
  if (ends_with(ctype, "[]"))
    return NULL;
  return NULL;
}

static char *extract_rhs_operand(const char *expr, const char **cursor_out) {
  const char *p = *cursor_out;
  p++;
  while (*p == ' ' || *p == '\t')
    p++;
  const char *start = p;
  int dpar = 0, dbr = 0;
  int in_s = 0, in_d = 0;
  if (*p == '+' || *p == '-')
    p++;
  while (*p) {
    char c = *p;
    if (!in_s && !in_d) {
      if (c == '(') {
        dpar++;
        p++;
        continue;
      }
      if (c == ')') {
        if (dpar == 0 && dbr == 0)
          break;
        dpar--;
        p++;
        continue;
      }
      if (c == '[') {
        dbr++;
        p++;
        continue;
      }
      if (c == ']') {
        dbr--;
        p++;
        continue;
      }
      if (c == '\'') {
        in_s = 1;
        p++;
        continue;
      }
      if (c == '"') {
        in_d = 1;
        p++;
        continue;
      }
      if ((c == '+' || c == '-' || c == '*' || c == '/' || c == '%' ||
           c == '&' || c == '|' || c == '^' || c == ',' || c == ';' ||
           c == '?' || c == ':' || c == '>' || c == '<' || c == '=') &&
          dpar == 0 && dbr == 0)
        break;
      p++;
    } else {
      if (in_s && c == '\'')
        in_s = 0;
      if (in_d && c == '"')
        in_d = 0;
      p++;
    }
  }
  char *rhs = str_dup_trim(start, (int)(p - start));
  *cursor_out = p;
  return rhs;
}
static void emit_division_asserts(char ***out, int *out_size, int depth,
                                  const char *expr) {
  const char *p = expr;
  int dpar = 0, dbr = 0;
  int in_s = 0, in_d = 0;
  while (*p) {
    char c = *p;
    if (!in_s && !in_d) {
      if (c == '(') {
        dpar++;
        p++;
        continue;
      }
      if (c == ')') {
        if (dpar > 0)
          dpar--;
        p++;
        continue;
      }
      if (c == '[') {
        dbr++;
        p++;
        continue;
      }
      if (c == ']') {
        if (dbr > 0)
          dbr--;
        p++;
        continue;
      }
      if (c == '\'') {
        in_s = 1;
        p++;
        continue;
      }
      if (c == '"') {
        in_d = 1;
        p++;
        continue;
      }
      if ((c == '/' || c == '%') && dpar == 0 && dbr == 0) {
        const char *cur = p;
        char *den = extract_rhs_operand(expr, &cur);
        if (den && den[0]) {
          char *line = cb_strdup_printf("assert((%s) != 0);", den);
          cb_push_line_indent(out, out_size, depth, line);
          free(line);
        }
        free(den);
        p = cur;
        continue;
      }
      p++;
    } else {
      if (in_s && c == '\'')
        in_s = 0;
      if (in_d && c == '"')
        in_d = 0;
      p++;
    }
  }
}
static void emit_index_bounds_asserts(char ***out, int *out_size, int depth,
                                      const char *expr, Symbol *symbols,
                                      int sym_n) {
  const char *p = expr;
  int in_s = 0, in_d = 0, dpar = 0;
  while (*p) {
    char c = *p;
    if (!in_s && !in_d) {
      if (c == '(') {
        dpar++;
        p++;
        continue;
      }
      if (c == ')') {
        if (dpar > 0)
          dpar--;
        p++;
        continue;
      }
      if (c == '\'') {
        in_s = 1;
        p++;
        continue;
      }
      if (c == '"') {
        in_d = 1;
        p++;
        continue;
      }
      if (c == '[') {
        const char *q = p - 1;
        while (q > expr && isspace((unsigned char)*q))
          q--;
        const char *end = q + 1;
        while (q >= expr && is_ident_char(*q))
          q--;
        const char *begin = q + 1;
        if (begin < end) {
          char *name = str_dup_trim(begin, (int)(end - begin));
          int si = sym_find(symbols, sym_n, name);
          bool is_list = (si >= 0 && symbols[si].ctype &&
                          ends_with(symbols[si].ctype, "[]"));

          int depth_br = 1;
          const char *idx_start = p + 1;
          const char *r = idx_start;
          int in_s2 = 0, in_d2 = 0, dpar2 = 0;
          while (*r) {
            char ch = *r;
            if (!in_s2 && !in_d2) {
              if (ch == '(')
                dpar2++;
              else if (ch == ')') {
                if (dpar2 > 0)
                  dpar2--;
              } else if (ch == '[')
                depth_br++;
              else if (ch == ']') {
                depth_br--;
                if (depth_br == 0)
                  break;
              } else if (ch == '\'')
                in_s2 = 1;
              else if (ch == '"')
                in_d2 = 1;
            } else {
              if (in_s2 && ch == '\'')
                in_s2 = 0;
              if (in_d2 && ch == '"')
                in_d2 = 0;
            }
            r++;
          }
          char *idx = str_dup_trim(idx_start, (int)(r - idx_start));
          if (is_list) {
            char *line = cb_strdup_printf("assert((%s) >= 0);", idx);
            cb_push_line_indent(out, out_size, depth, line);
            free(line);
            line = cb_strdup_printf("assert((%s) < %s_len);", idx, name);
            cb_push_line_indent(out, out_size, depth, line);
            free(line);
          }
          free(idx);
          free(name);
          if (*r == ']') {
            p = r + 1;
            continue;
          }
        }
      }
    } else {
      if (in_s && c == '\'')
        in_s = 0;
      if (in_d && c == '"')
        in_d = 0;
    }
    p++;
  }
}

static bool is_list_literal(const char *s) {
  if (!s)
    return false;
  size_t L = strlen(s);
  if (L < 2)
    return false;
  while (*s && isspace((unsigned char)*s))
    s++;
  if (*s != '[')
    return false;
  const char *e = s + strlen(s) - 1;
  while (e > s && isspace((unsigned char)*e))
    e--;
  return *e == ']';
}
static char *strip_brackets(const char *s) {
  const char *p = s;
  while (*p && isspace((unsigned char)*p))
    p++;
  if (*p == '[')
    p++;
  const char *q = s + strlen(s) - 1;
  while (q > p && isspace((unsigned char)*q))
    q--;
  if (*q == ']')
    q--;
  int len = (int)(q - p + 1);
  return str_dup_trim(p, len);
}
static const char *deduce_list_base_ctype(char **elems, int n, Symbol *symbols,
                                          int sym_n) {
  if (n == 0)
    return "int"; // default empty list base
  const char *first = NULL;
  for (int i = 0; i < n; i++) {
    const char *e = elems[i];
    const char *t = NULL;
    if (is_string_literal(e))
      t = "char *";
    else if (is_numeric_literal(e))
      t = (strchr(e, '.') ? "double" : "int");
    else {
      bool bare_ident = true;
      for (const char *k = e; *k; k++) {
        if (!is_ident_char(*k)) {
          bare_ident = false;
          break;
        }
      }
      if (bare_ident) {
        int si = sym_find(symbols, sym_n, e);
        if (si >= 0)
          t = symbols[si].ctype;
      }
      if (!t)
        t = infer_c_type_from_expr(e, symbols, sym_n);
    }
    if (!first)
      first = t;
    else if (strcmp(first, t) != 0)
      return NULL; // heterogeneous not supported
  }
  return first ? first : "int";
}

static void emit_list_set_from_literal(char ***out, int *out_size, int depth,
                                       const char *lhs, char **elems, int n,
                                       const char *base, bool existed_before) {
  if (!existed_before) {
    char *decl0 = cb_strdup_printf("%s *%s = NULL;", base, lhs);
    cb_push_line_indent(out, out_size, depth, decl0);
    free(decl0);
    char *declL = cb_strdup_printf("int %s_len = 0;", lhs);
    cb_push_line_indent(out, out_size, depth, declL);
    free(declL);
    char *declC = cb_strdup_printf("int %s_cap = 0;", lhs);
    cb_push_line_indent(out, out_size, depth, declC);
    free(declC);
  } else {
    // if reassigning, clear previous contents
    char *clr = cb_strdup_printf(
        "if (%s) { free(%s); %s = NULL; } %s_len = 0; %s_cap = 0;", lhs, lhs,
        lhs, lhs, lhs);
    cb_push_line_indent(out, out_size, depth, clr);
    free(clr);
  }

  // Ensure capacity and copy elements
  char *need = cb_strdup_printf("int __need_%s = %d;", lhs, n);
  cb_push_line_indent(out, out_size, depth, need);
  free(need);
  char *grow1 =
      cb_strdup_printf("int __cap_%s = %s_cap ? %s_cap : 4;", lhs, lhs, lhs);
  cb_push_line_indent(out, out_size, depth, grow1);
  free(grow1);
  char *grow2 = cb_strdup_printf("while (__cap_%s < __need_%s) __cap_%s *= 2;",
                                 lhs, lhs, lhs);
  cb_push_line_indent(out, out_size, depth, grow2);
  free(grow2);
  char *alloc = cb_strdup_printf(
      "%s = (%s*)realloc(%s, (size_t)__cap_%s * sizeof(*%s)); assert(%s);", lhs,
      base, lhs, lhs, lhs, lhs);
  cb_push_line_indent(out, out_size, depth, alloc);
  free(alloc);
  char *setcap = cb_strdup_printf("%s_cap = __cap_%s;", lhs, lhs);
  cb_push_line_indent(out, out_size, depth, setcap);
  free(setcap);

  for (int i = 0; i < n; i++) {
    char *seti = cb_strdup_printf("%s[%s_len++] = %s;", lhs, lhs, elems[i]);
    cb_push_line_indent(out, out_size, depth, seti);
    free(seti);
  }
}

// Emit ensure-capacity for a list for additional "add" count
static void emit_list_ensure_capacity(char ***out, int *out_size, int depth,
                                      const char *name,
                                      const char *extra_expr) {
  char *need = cb_strdup_printf("int __need_%s = %s_len + (%s);", name, name,
                                extra_expr);
  cb_push_line_indent(out, out_size, depth, need);
  free(need);
  char *grow1 =
      cb_strdup_printf("int __cap_%s = %s_cap ? %s_cap : 4;", name, name, name);
  cb_push_line_indent(out, out_size, depth, grow1);
  free(grow1);
  char *grow2 = cb_strdup_printf("while (__cap_%s < __need_%s) __cap_%s *= 2;",
                                 name, name, name);
  cb_push_line_indent(out, out_size, depth, grow2);
  free(grow2);
  char *alloc = cb_strdup_printf(
      "%s = realloc(%s, (size_t)__cap_%s * sizeof(*%s)); assert(%s);", name,
      name, name, name, name);
  cb_push_line_indent(out, out_size, depth, alloc);
  free(alloc);
  char *setcap = cb_strdup_printf("%s_cap = __cap_%s;", name, name);
  cb_push_line_indent(out, out_size, depth, setcap);
  free(setcap);
}

static int __print_counter = 0;

static void emit_print_arg_scalar(char ***out, int *out_size, int depth,
                                  const char *a, const char *ctype,
                                  const char *space_guard_name) {
  const char *ph = ctype_to_fmt(ctype);
  if (!ph)
    ph = "%d"; // default, don't fail for unknowns
  char *pre = cb_strdup_printf("if (%s) printf(\" \");", space_guard_name);
  cb_push_line_indent(out, out_size, depth, pre);
  free(pre);
  if (is_string_literal(a)) {
    char *ln = cb_strdup_printf("printf(\"%%s\", %s);", a);
    cb_push_line_indent(out, out_size, depth, ln);
    free(ln);
  } else {
    char *ln = cb_strdup_printf("printf(\"%s\", %s);", ph, a);
    cb_push_line_indent(out, out_size, depth, ln);
    free(ln);
  }
  char *setp = cb_strdup_printf("%s = 1;", space_guard_name);
  cb_push_line_indent(out, out_size, depth, setp);
  free(setp);
}
static void emit_print_arg_list(char ***out, int *out_size, int depth,
                                const char *name, const char *elem_ctype,
                                const char *space_guard_name) {
  const char *ph = ctype_to_fmt(elem_ctype);
  if (!ph)
    ph = "%d";
  char *pre = cb_strdup_printf("if (%s) printf(\" \");", space_guard_name);
  cb_push_line_indent(out, out_size, depth, pre);
  free(pre);
  cb_push_line_indent(out, out_size, depth, "printf(\"[\");");
  int kid = __print_counter++;
  char idx[32];
  snprintf(idx, sizeof(idx), "__pj%d", kid);
  char *loop = cb_strdup_printf("for (int %s = 0; %s < %s_len; %s++) {", idx,
                                idx, name, idx);
  cb_push_line_indent(out, out_size, depth, loop);
  free(loop);
  cb_push_line_indent(out, out_size, depth + 1,
                      cb_strdup_printf("if (%s) printf(\", \");", idx));
  if (strcmp(elem_ctype, "char *") == 0) {
    char *ln = cb_strdup_printf("printf(\"'%%s'\", %s[%s]);", name, idx);
    cb_push_line_indent(out, out_size, depth + 1, ln);
    free(ln);
  } else {
    char *ln = cb_strdup_printf("printf(\"%s\", %s[%s]);", ph, name, idx);
    cb_push_line_indent(out, out_size, depth + 1, ln);
    free(ln);
  }
  cb_push_line_indent(out, out_size, depth, "}");
  cb_push_line_indent(out, out_size, depth, "printf(\"]\");");
  char *setp = cb_strdup_printf("%s = 1;", space_guard_name);
  cb_push_line_indent(out, out_size, depth, setp);
  free(setp);
}
static void emit_printf_from_print(char ***out, int *out_size, int depth,
                                   const char *arglist, Symbol *symbols,
                                   int sym_n) {
  int argc = 0;
  char **args = split_args(arglist, &argc);
  bool has_list = false;
  int *is_list = (int *)calloc((size_t)argc, sizeof(int));
  const char **elem_types = (const char **)calloc((size_t)argc, sizeof(char *));
  const char **scalar_types =
      (const char **)calloc((size_t)argc, sizeof(char *));
  for (int i = 0; i < argc; i++) {
    const char *a = args[i];
    bool bare_ident = true;
    for (const char *t = a; *t; t++)
      if (!is_ident_char(*t)) {
        bare_ident = false;
        break;
      }
    if (bare_ident) {
      int si = sym_find(symbols, sym_n, a);
      if (si >= 0 && symbols[si].ctype && ends_with(symbols[si].ctype, "[]")) {
        has_list = true;
        is_list[i] = 1;
        static char buf[64];
        snprintf(buf, sizeof(buf), "%s", symbols[si].ctype);
        size_t L = strlen(buf);
        if (L >= 2)
          buf[L - 2] = '\0';
        elem_types[i] = strdup(buf);
        continue;
      }
    }
    const char *ctype = NULL;
    if (is_string_literal(a))
      ctype = "char *";
    else {
      if (bare_ident) {
        int si = sym_find(symbols, sym_n, a);
        if (si >= 0)
          ctype = symbols[si].ctype;
      }
      if (!ctype)
        ctype = infer_c_type_from_expr(a, symbols, sym_n);
    }
    scalar_types[i] = ctype;
  }

  if (!has_list) {
    char *fmt = strdup("");
    char *params = strdup("");
    for (int i = 0; i < argc; i++) {
      const char *a = args[i];
      if (i > 0)
        fmt = cb_str_append(fmt, " ");
      if (is_string_literal(a)) {
        fmt = cb_str_append(fmt, "%s");
        params = cb_str_appendf(params, "%s%s", (params[0] ? ", " : ""), a);
      } else {
        const char *ph = ctype_to_fmt(scalar_types[i]);
        if (!ph)
          ph = "%d";
        fmt = cb_str_append(fmt, ph);
        params = cb_str_appendf(params, "%s%s", (params[0] ? ", " : ""), a);
      }
    }
    fmt = cb_str_append(fmt, "\\n");
    char *line = NULL;
    if (params[0])
      line = cb_strdup_printf("printf(\"%s\", %s);", fmt, params);
    else
      line = cb_strdup_printf("printf(\"%s\");", fmt);
    cb_push_line_indent(out, out_size, depth, line);
    free(line);
    free(fmt);
    free(params);
  } else {
    int kid = __print_counter++;
    char guard[32];
    snprintf(guard, sizeof(guard), "__p%d", kid);
    char *decl = cb_strdup_printf("int %s = 0;", guard);
    cb_push_line_indent(out, out_size, depth, decl);
    free(decl);
    for (int i = 0; i < argc; i++) {
      if (is_list[i]) {
        if (!args[i][0])
          continue;
        emit_print_arg_list(out, out_size, depth, args[i], elem_types[i],
                            guard);
      } else {
        const char *a = args[i];
        const char *ctype = scalar_types[i];
        if (is_string_literal(a))
          ctype = "char *";
        emit_print_arg_scalar(out, out_size, depth, a, ctype, guard);
      }
    }
    cb_push_line_indent(out, out_size, depth, "printf(\"\\n\");");
  }

  for (int i = 0; i < argc; i++)
    if (elem_types[i])
      free((void *)elem_types[i]);
  free(elem_types);
  free(scalar_types);
  free(is_list);
  free_split(args, argc);
}

static int __loop_counter = 0;
char *__pending_for_bind_line = NULL;

static void handle_for_header(char ***out, int *out_size, int *depth,
                              int indent, const char *head, Symbol **symbols,
                              int *sym_n) {
  const char *var = head + 4; // after "for "
  const char *in = strstr(var, " in ");
  if (!in) {
    char *err =
        cb_strdup_printf("assert(0 && \"Malformed for header: %s\");", head);
    cb_push_line_indent(out, out_size, *depth, err);
    free(err);
    return;
  }
  char *lhs = str_dup_trim(var, (int)(in - var));
  const char *iter = in + 4;

  if (starts_with(iter, "range(")) {
    const char *rp = strrchr(iter, ')');
    if (!rp) {
      char *err =
          cb_strdup_printf("assert(0 && \"Malformed range() in: %s\");", head);
      cb_push_line_indent(out, out_size, *depth, err);
      free(err);
      free(lhs);
      return;
    }
    char *inside = str_dup_trim(iter + 6, (int)(rp - (iter + 6)));
    int argc = 0;
    char **argv = split_args(inside, &argc);

    const char *c_start = "0", *c_stop = NULL, *c_step = "1";
    if (argc == 1)
      c_stop = argv[0];
    else if (argc == 2) {
      c_start = argv[0];
      c_stop = argv[1];
    } else if (argc >= 3) {
      c_start = argv[0];
      c_stop = argv[1];
      c_step = argv[2];
    }

    char *a1 = cb_strdup_printf("assert(%s != 0);", c_step);
    cb_push_line_indent(out, out_size, *depth, a1);
    free(a1);

    char *cond = cb_strdup_printf("(%s) > 0 ? (%s) < (%s) : (%s) > (%s)",
                                  c_step, lhs, c_stop, lhs, c_stop);
    char *line = cb_strdup_printf("for (int %s = (%s); %s; %s += (%s)) {", lhs,
                                  c_start, cond, lhs, c_step);
    cb_push_line_indent(out, out_size, *depth, line);
    free(cond);
    free(line);
    free_split(argv, argc);
    free(inside);
    free(lhs);
    return;
  }

  // for x in list_name:
  int si = sym_find(*symbols, *sym_n, iter);
  const char *arr_t = (si >= 0 ? (*symbols)[si].ctype : NULL);
  if (!arr_t || !ends_with(arr_t, "[]")) {
    char *err = cb_strdup_printf(
        "assert(0 && \"for-in expects list variable: %s\");", head);
    cb_push_line_indent(out, out_size, *depth, err);
    free(err);
    free(lhs);
    return;
  }

  char *elem_t = str_dup_trim(arr_t, (int)strlen(arr_t) - 2);
  int k = __loop_counter++;
  char idx_name[32];
  snprintf(idx_name, sizeof(idx_name), "__idx%d", k);

  char *line = cb_strdup_printf("for (int %s = 0; %s < %s_len; %s++) {",
                                idx_name, idx_name, iter, idx_name);
  cb_push_line_indent(out, out_size, *depth, line);
  free(line);

  char *bind = cb_strdup_printf("%s %s = %s[%s];", elem_t, lhs, iter, idx_name);
  __pending_for_bind_line = bind;

  free(elem_t);
  free(lhs);
}

static bool parse_list_method_call(const char *stmt, char *list_out,
                                   size_t list_sz, char *method_out,
                                   size_t meth_sz, char **inside_out) {
  const char *dot = strchr(stmt, '.');
  if (!dot)
    return false;
  const char *lp = strchr(stmt, '(');
  if (!lp)
    return false;
  const char *rp = strrchr(stmt, ')');
  if (!rp || rp < lp)
    return false;
  // Extract list name
  int L = (int)(dot - stmt);
  if (L <= 0 || (size_t)L >= list_sz)
    return false;
  memcpy(list_out, stmt, (size_t)L);
  list_out[L] = 0;
  // Extract method
  int M = (int)(lp - (dot + 1));
  if (M <= 0 || (size_t)M >= meth_sz)
    return false;
  memcpy(method_out, dot + 1, (size_t)M);
  method_out[M] = 0;
  // Extract inside
  *inside_out = str_dup_trim(lp + 1, (int)(rp - (lp + 1)));
  return true;
}

static bool stmt_is_bare_list_call(const char *stmt) {
  // Rough check: "<ident>.<method>(...)" and no trailing stuff
  const char *rp = strrchr(stmt, ')');
  if (!rp)
    return false;
  const char *after = rp + 1;
  while (*after && isspace((unsigned char)*after))
    after++;
  return *after == '\0';
}

static void emit_list_method_stmt(char ***out, int *out_size, int depth,
                                  const char *stmt, Symbol *symbols,
                                  int sym_n) {
  char list[128], method[64];
  char *inside = NULL;
  if (!parse_list_method_call(stmt, list, sizeof(list), method, sizeof(method),
                              &inside))
    return;

  if (strcmp(method, "append") == 0) {
    emit_list_ensure_capacity(out, out_size, depth, list, "1");
    char *ln = cb_strdup_printf("%s[%s_len++] = %s;", list, list,
                                inside[0] ? inside : "0");
    cb_push_line_indent(out, out_size, depth, ln);
    free(ln);
    goto done;
  }
  // pop([i])
  if (strcmp(method, "pop") == 0) {
    if (inside[0] == '\0') {
      cb_push_line_indent(out, out_size, depth,
                          cb_strdup_printf("assert(%s_len>0);", list));
      char *ln = cb_strdup_printf("%s_len--;", list);
      cb_push_line_indent(out, out_size, depth, ln);
      free(ln);
    } else {
      cb_push_line_indent(out, out_size, depth,
                          cb_strdup_printf("assert(%s_len>0);", list));
      char *ai = cb_strdup_printf(
          "int __i_%s = (%s); assert(__i_%s>=0 && __i_%s<%s_len);", list,
          inside, list, list, list);
      cb_push_line_indent(out, out_size, depth, ai);
      free(ai);
      char *mv = cb_strdup_printf("memmove(%s+__i_%s, %s+__i_%s+1, "
                                  "(size_t)(%s_len-__i_%s-1)*sizeof(*%s));",
                                  list, list, list, list, list, list, list);
      cb_push_line_indent(out, out_size, depth, mv);
      free(mv);
      char *dec = cb_strdup_printf("%s_len--;", list);
      cb_push_line_indent(out, out_size, depth, dec);
      free(dec);
    }
    goto done;
  }
  // insert(i, x)
  if (strcmp(method, "insert") == 0) {
    int ac = 0;
    char **av = split_args(inside, &ac);
    const char *idx = (ac >= 1 ? av[0] : "0");
    const char *val = (ac >= 2 ? av[1] : "0");
    emit_list_ensure_capacity(out, out_size, depth, list, "1");
    char *chk = cb_strdup_printf(
        "int __i_%s = (%s); assert(__i_%s>=0 && __i_%s<=%s_len);", list, idx,
        list, list, list);
    cb_push_line_indent(out, out_size, depth, chk);
    free(chk);
    char *mv = cb_strdup_printf(
        "memmove(%s+__i_%s+1, %s+__i_%s, (size_t)(%s_len-__i_%s)*sizeof(*%s));",
        list, list, list, list, list, list, list);
    cb_push_line_indent(out, out_size, depth, mv);
    free(mv);
    char *seti = cb_strdup_printf("%s[__i_%s] = %s;", list, list, val);
    cb_push_line_indent(out, out_size, depth, seti);
    free(seti);
    char *inc = cb_strdup_printf("%s_len++;", list);
    cb_push_line_indent(out, out_size, depth, inc);
    free(inc);
    free_split(av, ac);
    goto done;
  }
  // remove(x)
  if (strcmp(method, "remove") == 0) {
    const char *val = inside[0] ? inside : "0";
    char *find = cb_strdup_printf(
        "int __j_%s=-1; for (int __k_%s=0; __k_%s<%s_len; __k_%s++){ if "
        "(%s[__k_%s]==(%s)) { __j_%s=__k_%s; break; } }",
        list, list, list, list, list, list, list, val, list, list);
    cb_push_line_indent(out, out_size, depth, find);
    free(find);
    char *chk = cb_strdup_printf("assert(__j_%s>=0);", list);
    cb_push_line_indent(out, out_size, depth, chk);
    free(chk);
    char *mv = cb_strdup_printf("memmove(%s+__j_%s, %s+__j_%s+1, "
                                "(size_t)(%s_len-__j_%s-1)*sizeof(*%s));",
                                list, list, list, list, list, list, list);
    cb_push_line_indent(out, out_size, depth, mv);
    free(mv);
    char *dec = cb_strdup_printf("%s_len--;", list);
    cb_push_line_indent(out, out_size, depth, dec);
    free(dec);
    goto done;
  }
  // extend(other)
  if (strcmp(method, "extend") == 0) {
    const char *other = inside[0] ? inside : "NULL";
    emit_list_ensure_capacity(out, out_size, depth, list,
                              cb_strdup_printf("%s_len", other));
    char *cpy =
        cb_strdup_printf("memcpy(%s+%s_len, %s, (size_t)%s_len*sizeof(*%s));",
                         list, list, other, other, list);
    cb_push_line_indent(out, out_size, depth, cpy);
    free(cpy);
    char *inc = cb_strdup_printf("%s_len += %s_len;", list, other);
    cb_push_line_indent(out, out_size, depth, inc);
    free(inc);
    goto done;
  }

done:
  free(inside);
}

// If RHS is exactly "<list>.pop(...)" and LHS is scalar, expand and set LHS.
static bool emit_assignment_pop_expr(char ***out, int *out_size, int depth,
                                     const char *lhs, const char *rhs) {
  char list[128], method[64];
  char *inside = NULL;
  if (!parse_list_method_call(rhs, list, sizeof(list), method, sizeof(method),
                              &inside))
    return false;
  if (strcmp(method, "pop") != 0) {
    free(inside);
    return false;
  }

  if (inside[0] == '\0') {
    char *pre = cb_strdup_printf("assert(%s_len>0);", list);
    cb_push_line_indent(out, out_size, depth, pre);
    free(pre);
    char *as = cb_strdup_printf("%s = %s[%s_len-1];", lhs, list, list);
    cb_push_line_indent(out, out_size, depth, as);
    free(as);
    char *dec = cb_strdup_printf("%s_len--;", list);
    cb_push_line_indent(out, out_size, depth, dec);
    free(dec);
  } else {
    char *idx = cb_strdup_printf(
        "int __i_%s = (%s); assert(__i_%s>=0 && __i_%s<%s_len);", list, inside,
        list, list, list);
    cb_push_line_indent(out, out_size, depth, idx);
    free(idx);
    char *as = cb_strdup_printf("%s = %s[__i_%s];", lhs, list, list);
    cb_push_line_indent(out, out_size, depth, as);
    free(as);
    char *mv = cb_strdup_printf("memmove(%s+__i_%s, %s+__i_%s+1, "
                                "(size_t)(%s_len-__i_%s-1)*sizeof(*%s));",
                                list, list, list, list, list, list, list);
    cb_push_line_indent(out, out_size, depth, mv);
    free(mv);
    char *dec = cb_strdup_printf("%s_len--;", list);
    cb_push_line_indent(out, out_size, depth, dec);
    free(dec);
  }
  free(inside);
  return true;
}

static char **transpile_py_block(char **lines, int line_count, int *out_size) {
  char **out = NULL;
  *out_size = 0;
  Symbol *symbols = NULL;
  int sym_n = 0;

  int indent_stack[256];
  int depth = 0;

  for (int i = 0; i < line_count; i++) {
    const char *raw = lines[i];

    int k = 0;
    while (raw[k] == ' ' || raw[k] == '\t')
      k++;
    if (raw[k] == '\0') {
      cb_push_line(&out, out_size, "");
      continue;
    }

    int indent = cb_count_indent(raw);
    const char *stmt = raw + indent;

    while (depth > 0 && indent <= indent_stack[depth - 1]) {
      depth--;
      cb_push_line_indent(&out, out_size, depth, "}");
    }

    size_t L = strlen(stmt);
    while (L > 0 && isspace((unsigned char)stmt[L - 1]))
      L--;
    int ends_colon = (L > 0 && stmt[L - 1] == ':');

    if (ends_colon) {
      char *head = str_dup_trim(stmt, (int)L - 1);

      if (starts_with(head, "if ")) {
        char *cond_py = strdup(head + 3);
        char *cond = normalize_condition_expr(cond_py);
        emit_division_asserts(&out, out_size, depth, cond);
        emit_index_bounds_asserts(&out, out_size, depth, cond, symbols, sym_n);
        char *line = cb_strdup_printf("if (%s) {", cond);
        cb_push_line_indent(&out, out_size, depth, line);
        free(line);
        indent_stack[depth++] = indent;
        free(cond_py);
        free(cond);
        free(head);
        continue;
      }

      if (starts_with(head, "elif ")) {
        char *cond_py = strdup(head + 5);
        char *cond = normalize_condition_expr(cond_py);
        emit_division_asserts(&out, out_size, depth, cond);
        emit_index_bounds_asserts(&out, out_size, depth, cond, symbols, sym_n);
        char *line = cb_strdup_printf("else if (%s) {", cond);
        cb_push_line_indent(&out, out_size, depth, line);
        free(line);
        indent_stack[depth++] = indent;
        free(cond_py);
        free(cond);
        free(head);
        continue;
      }

      if (strcmp(head, "else") == 0) {
        cb_push_line_indent(&out, out_size, depth, "else {");
        indent_stack[depth++] = indent;
        free(head);
        continue;
      }

      if (starts_with(head, "while ")) {
        char *cond_py = strdup(head + 6);
        char *cond = normalize_condition_expr(cond_py);
        emit_division_asserts(&out, out_size, depth, cond);
        emit_index_bounds_asserts(&out, out_size, depth, cond, symbols, sym_n);
        char *line = cb_strdup_printf("while (%s) {", cond);
        cb_push_line_indent(&out, out_size, depth, line);
        free(line);
        indent_stack[depth++] = indent;
        free(cond_py);
        free(cond);
        free(head);
        continue;
      }

      if (starts_with(head, "for ")) {
        handle_for_header(&out, out_size, &depth, indent, head, &symbols,
                          &sym_n);
        indent_stack[depth++] = indent;
        if (__pending_for_bind_line) {
          cb_push_line_indent(&out, out_size, depth, __pending_for_bind_line);
          free(__pending_for_bind_line);
          __pending_for_bind_line = NULL;
        }
        free(head);
        continue;
      }

      if (strcmp(head, "pass") == 0) {
        cb_push_line_indent(&out, out_size, depth, "{ /* pass */");
        indent_stack[depth++] = indent;
        free(head);
        continue;
      }

      char *err =
          cb_strdup_printf("assert(0 && \"Unhandled header: %s\");", head);
      cb_push_line_indent(&out, out_size, depth, err);
      free(err);
      free(head);
      continue;
    }

    // simple statements
    if (strcmp(stmt, "pass") == 0) {
      cb_push_line_indent(&out, out_size, depth, ";");
      continue;
    }
    if (strcmp(stmt, "break") == 0) {
      cb_push_line_indent(&out, out_size, depth, "break;");
      continue;
    }
    if (strcmp(stmt, "continue") == 0) {
      cb_push_line_indent(&out, out_size, depth, "continue;");
      continue;
    }

    if (starts_with(stmt, "print(")) {
      const char *rp = strrchr(stmt, ')');
      if (!rp) {
        char *err =
            cb_strdup_printf("assert(0 && \"Malformed print(): %s\");", stmt);
        cb_push_line_indent(&out, out_size, depth, err);
        free(err);
        continue;
      }
      char *inside = str_dup_trim(stmt + 6, (int)(rp - (stmt + 6)));
      emit_division_asserts(&out, out_size, depth, inside);
      emit_index_bounds_asserts(&out, out_size, depth, inside, symbols, sym_n);
      emit_printf_from_print(&out, out_size, depth, inside, symbols, sym_n);
      free(inside);
      continue;
    }

    // bare list method statements (append/insert/remove/extend/pop)
    if (stmt_is_bare_list_call(stmt)) {
      emit_list_method_stmt(&out, out_size, depth, stmt, symbols, sym_n);
      continue;
    }

    // assignment
    const char *eq = strchr(stmt, '=');
    if (eq) {
      int lhs_len = (int)(eq - stmt);
      char *lhs = str_dup_trim(stmt, lhs_len);
      const char *rhs = eq + 1;
      while (*rhs == ' ' || *rhs == '\t')
        rhs++;

      emit_division_asserts(&out, out_size, depth, rhs);
      emit_index_bounds_asserts(&out, out_size, depth, rhs, symbols, sym_n);

      // Special: x = lst.pop(...)
      if (emit_assignment_pop_expr(&out, out_size, depth, lhs, rhs)) {
        // infer type for lhs from list element if we know it; else int
        int siL = sym_find(symbols, sym_n, lhs);
        if (siL < 0) {
          // try to find list element type from rhs
          const char *elem_t = "int";
          char list[128], method[64];
          char *inside2 = NULL;
          if (parse_list_method_call(rhs, list, sizeof(list), method,
                                     sizeof(method), &inside2)) {
            int siX = sym_find(symbols, sym_n, list);
            if (siX >= 0 && symbols[siX].ctype &&
                ends_with(symbols[siX].ctype, "[]")) {
              static char buf[64];
              snprintf(buf, sizeof(buf), "%s", symbols[siX].ctype);
              size_t Lb = strlen(buf);
              if (Lb >= 2)
                buf[Lb - 2] = '\0';
              elem_t = buf;
            }
            free(inside2);
          }
          symbols =
              (Symbol *)realloc(symbols, (size_t)(sym_n + 1) * sizeof(Symbol));
          symbols[sym_n].name = strdup(lhs);
          symbols[sym_n].ctype = strdup(elem_t);
          char *decl = cb_strdup_printf("%s %s; /* from pop */", elem_t, lhs);
          cb_push_line_indent(&out, out_size, depth, decl);
          free(decl);
          sym_n++;
        }
        free(lhs);
        continue;
      }

      if (is_list_literal(rhs)) {
        char *inside = strip_brackets(rhs);
        int n = 0;
        char **elems = split_args(inside, &n);
        const char *base = deduce_list_base_ctype(elems, n, symbols, sym_n);
        if (!base) {
          char *err = cb_strdup_printf(
              "assert(0 && \"Heterogeneous list literal for %s\");", lhs);
          cb_push_line_indent(&out, out_size, depth, err);
          free(err);
          base = "int";
        }
        int si = sym_find(symbols, sym_n, lhs);
        bool existed = (si >= 0);
        if (!existed) {
          symbols =
              (Symbol *)realloc(symbols, (size_t)(sym_n + 1) * sizeof(Symbol));
          symbols[sym_n].name = strdup(lhs);
          char *ctype = cb_strdup_printf("%s[]", base);
          symbols[sym_n].ctype = strdup(ctype);
          free(ctype);
          sym_n++;
        }
        emit_list_set_from_literal(&out, out_size, depth, lhs, elems, n, base,
                                   existed);
        free_split(elems, n);
        free(inside);
        free(lhs);
        continue;
      }

      const char *new_t = infer_c_type_from_expr(rhs, symbols, sym_n);
      int si = sym_find(symbols, sym_n, lhs);
      if (si < 0) {
        symbols =
            (Symbol *)realloc(symbols, (size_t)(sym_n + 1) * sizeof(Symbol));
        symbols[sym_n].name = strdup(lhs);
        symbols[sym_n].ctype = strdup(new_t);
        char *cl = cb_strdup_printf("%s %s = %s;", new_t, lhs, rhs);
        cb_push_line_indent(&out, out_size, depth, cl);
        free(cl);
        sym_n++;
      } else {
        char *cl = cb_strdup_printf("%s = %s;", lhs, rhs);
        cb_push_line_indent(&out, out_size, depth, cl);
        free(cl);
      }
      free(lhs);
      continue;
    }

    // fallback
    {
      char *cl = cb_strdup_printf("assert(0 && \"Unhandled stmt: %s\");", stmt);
      cb_push_line_indent(&out, out_size, depth, cl);
      free(cl);
    }
  }

  while (depth > 0) {
    depth--;
    cb_push_line_indent(&out, out_size, depth, "}");
  }

  for (int i = 0; i < sym_n; i++)
    free(symbols[i].name);
  free(symbols);

  return out;
}

#endif // CB_PY_H
