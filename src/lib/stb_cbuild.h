#ifndef _STB_CB_H
#define _STB_CB_H
#include <openssl/md5.h> // Requires OpenSSL
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//============================= arglist.h
//=======================================
typedef struct {
  char **list;
  int count;
  int capacity;
} CB_ARGLIST;

static inline CB_ARGLIST *arglist_new();
static inline void arglist_append(CB_ARGLIST *arglist, ...); // sentinel: NULL
static inline void arglist_append_array(CB_ARGLIST *arglist, const char **arr);
static inline void arglist_free(CB_ARGLIST *arglist);

//============================= platform & macros
//===============================
#if defined(_WIN32)
#define OS_WIN 1
#include <process.h>
#include <windows.h>
#else
#define OS_UNIX 1
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#define OS_MACOS 1
#endif

#ifdef CB_DEBUG
#define CB_DEBUG_LOG(fmt, ...)                                                 \
  fprintf(stderr, "\x1b[36m[DEBUG] %s:%d: " fmt "\x1b[0m\n", __FILE__,         \
          __LINE__, ##__VA_ARGS__)
#else
#define CB_DEBUG_LOG(fmt, ...)
#endif

#if OS_UNIX
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <sys/types.h>
#endif

// Allow override by macro or environment
#ifndef CB_COMPILER
#if OS_WIN
#define COMPILER_NAME_DEFAULT "cl"
#elif defined(OS_MACOS)
#define COMPILER_NAME_DEFAULT "clang"
#else
#define COMPILER_NAME_DEFAULT "cc"
#endif
#else
#define COMPILER_NAME_DEFAULT CB_COMPILER
#endif

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_CYAN "\x1b[36m"

typedef enum { BUILD_EXEC, BUILD_STATIC, BUILD_SHARED } _CB_BUILD_TYPE;

typedef struct _CB_PROJECT {
  char *name;
  char *output;
  CB_ARGLIST *files; // may contain wildcard patterns; expanded before build
  CB_ARGLIST *buildflags;
  CB_ARGLIST *flags;
  char *compile_command;
  int is_rebuild;
  _CB_BUILD_TYPE build_type;
  int CB_PYTHON;
} _CB_PROJECT;

typedef struct {
  _CB_PROJECT **projects;
  int run;            // run produced outputs?
  int run_if_skipped; // run even if build skipped (cache hit)
  int parallel_build; // NEW: number of parallel build jobs
  int parallel_run;   // NEW: number of parallel run jobs
  int parallel; // DEPRECATED: kept for back-compat; treated as parallel_run if
                // >0
} CB_PROJECT_BUILD_CONFIG;

#define CB_STRLIST(...) ((const char *[]){__VA_ARGS__, NULL})
#define CB_PROJECT_LIST(...) ((_CB_PROJECT *[]){__VA_ARGS__, NULL})

#define _CB_CREATE_PROJECT(var, ...)                                           \
  _CB_PROJECT *var = (_CB_PROJECT *)malloc(sizeof(_CB_PROJECT));               \
  if (!(var)) {                                                                \
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);                    \
    exit(1);                                                                   \
  }                                                                            \
  memset(var, 0, sizeof(_CB_PROJECT));                                         \
  struct {                                                                     \
    char *name;                                                                \
    char *output;                                                              \
    const char **files;                                                        \
    const char **buildflags;                                                   \
    const char **flags;                                                        \
    int is_rebuild;                                                            \
    _CB_BUILD_TYPE build_type;                                                 \
    int CB_PYTHON;                                                             \
  } var##_init = {__VA_ARGS__};                                                \
  var->name = var##_init.name;                                                 \
  var->output = var##_init.output;                                             \
  var->files = arglist_new();                                                  \
  var->buildflags = arglist_new();                                             \
  var->flags = arglist_new();                                                  \
  var->is_rebuild = var##_init.is_rebuild;                                     \
  var->build_type = var##_init.build_type;                                     \
  var->CB_PYTHON = var##_init.CB_PYTHON;                                       \
  if (var##_init.files)                                                        \
    arglist_append_array(var->files, var##_init.files);                        \
  if (var##_init.buildflags)                                                   \
    arglist_append_array(var->buildflags, var##_init.buildflags);              \
  if (var##_init.flags)                                                        \
  arglist_append_array(var->flags, var##_init.flags)

#define CB_NEEDED_LIBS "-lssl -lcrypto"

// — forward decls —
static char *cb_concat_compile_command(_CB_PROJECT *proj);
#define _CB_BUILD_COMPILE_COMMAND(proj)                                        \
  do {                                                                         \
    if ((proj)->compile_command) {                                             \
      free((proj)->compile_command);                                           \
    }                                                                          \
    (proj)->compile_command = cb_concat_compile_command(proj);                 \
  } while (0)

static void cb_dump_to_console(const _CB_PROJECT *project);
static void cb_free_project(_CB_PROJECT *project);
static char *cb_compute_md5(const char *data, size_t len);
static char *cb_read_file_content(const char *filepath, size_t *out_len);
static char *cb_compute_project_checksum(_CB_PROJECT *proj);
static char *cb_read_checksum(const char *filename);
static int cb_write_checksum(const char *filename, const char *checksum);
static void cb_expand_project_wildcards(_CB_PROJECT *proj); // NEW

typedef struct {
#if OS_WIN
  PROCESS_INFORMATION pi;
#else
  pid_t pid;
#endif
  int running;
  _CB_PROJECT *project;
  int is_build;
} proc_t;

static int proc_start_run(proc_t *proc, _CB_PROJECT *proj, char **argv);
static int proc_start_build_cmd(proc_t *proc, _CB_PROJECT *proj,
                                const char *cmdline);
static int proc_poll(proc_t *proc);
static void proc_wait_all(proc_t *procs, int count);

#define _CB_PROJECT_BUILD(...)                                                 \
  _cb_project_build_internal((CB_PROJECT_BUILD_CONFIG){__VA_ARGS__})
static void _cb_project_build_internal(CB_PROJECT_BUILD_CONFIG config);

#define _CB_IMPLEMENTATION
//============================= implementation
//==================================
#ifdef _CB_IMPLEMENTATION

//---------- small utils ----------
static char *cb_strdup(const char *s) {
  if (!s)
    return NULL;
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (!p) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  memcpy(p, s, n);
  return p;
}
static void *cb_realloc(void *p, size_t sz) {
  void *q = realloc(p, sz);
  if (!q) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  return q;
}
static int cb_str_has_wildcards(const char *s) {
  if (!s)
    return 0;
  for (; *s; ++s) {
    if (*s == '*' || *s == '?' || *s == '[')
      return 1;
#if OS_WIN
      // Windows doesn't support [...] in FindFirstFile, but treat it as pattern
      // anyway
#endif
  }
  return 0;
}

// Growable string builder append
static void cb_strcatf(char **dst, size_t *cap, size_t *len, const char *fmt,
                       ...) {
  va_list ap;
  for (;;) {
    va_start(ap, fmt);
    int need = vsnprintf((*dst) ? *dst + *len : NULL, (*dst) ? *cap - *len : 0,
                         fmt, ap);
    va_end(ap);
    if (need < 0) { // encoding error
      return;
    }
    size_t req = (size_t)need;
    if ((*dst) && *len + req < *cap) {
      *len += req;
      return;
    }
    size_t newcap = (*cap ? *cap : 64);
    while (newcap <= *len + req)
      newcap *= 2;
    *dst = (char *)cb_realloc(*dst, newcap);
    if (*cap == 0) {
      (*dst)[0] = '\0';
    }
    *cap = newcap;
  }
}

//---------- arglist ----------
static inline CB_ARGLIST *arglist_new() {
  CB_ARGLIST *a = (CB_ARGLIST *)malloc(sizeof(CB_ARGLIST));
  if (!a) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  a->count = 0;
  a->capacity = 8;
  a->list = (char **)malloc(sizeof(char *) * a->capacity);
  if (!a->list) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  return a;
}
static void arglist__ensure(CB_ARGLIST *a, int need) {
  if (a->count + need <= a->capacity)
    return;
  while (a->count + need > a->capacity)
    a->capacity *= 2;
  a->list = (char **)cb_realloc(a->list, sizeof(char *) * a->capacity);
}
static inline void arglist_append(CB_ARGLIST *arglist, ...) {
  if (!arglist)
    return;
  va_list args;
  va_start(args, arglist);
  for (;;) {
    char *arg = va_arg(args, char *);
    if (!arg)
      break;
    arglist__ensure(arglist, 1);
    arglist->list[arglist->count++] = cb_strdup(arg);
  }
  va_end(args);
}
static inline void arglist_append_array(CB_ARGLIST *arglist, const char **arr) {
  if (!arglist || !arr)
    return;
  for (int i = 0; arr[i] != NULL; i++) {
    arglist_append(arglist, arr[i], NULL);
  }
}
static inline void arglist_free(CB_ARGLIST *arglist) {
  if (!arglist)
    return;
  for (int i = 0; i < arglist->count; i++)
    free(arglist->list[i]);
  free(arglist->list);
  free(arglist);
}

//---------- compiler selection ----------
static const char *cb_pick_compiler_name(void) {
  const char *env = getenv("CB_CC");
  if (env && env[0])
    return env;
  return COMPILER_NAME_DEFAULT;
}

//---------- wildcard expansion ----------
static void cb_files_add(CB_ARGLIST *files, const char *s) {
  arglist_append(files, s, NULL);
}

#if OS_WIN
static void cb_expand_pattern_win(CB_ARGLIST *out, const char *pattern) {
  // Split directory part to preserve prefix
  char dir[MAX_PATH];
  const char *slash = strrchr(pattern, '\\');
  const char *slash2 = strrchr(pattern, '/');
  const char *cut = slash ? slash : slash2;
  size_t dlen = 0;
  if (cut) {
    dlen = (size_t)(cut - pattern + 1);
    if (dlen >= sizeof(dir))
      dlen = sizeof(dir) - 1;
    memcpy(dir, pattern, dlen);
    dir[dlen] = '\0';
  } else {
    dir[0] = '\0';
  }

  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    // no match: keep literal to let compiler report it
    cb_files_add(out, pattern);
    return;
  }
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      char path[MAX_PATH * 2];
      snprintf(path, sizeof(path), "%s%s", dir, fd.cFileName);
      cb_files_add(out, path);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
}
#else
static void cb_expand_pattern_unix(CB_ARGLIST *out, const char *pattern) {
  glob_t gl;
  memset(&gl, 0, sizeof(gl));
  int r = glob(pattern, GLOB_TILDE, NULL, &gl);
  if (r == 0) {
    for (size_t i = 0; i < gl.gl_pathc; i++) {
      cb_files_add(out, gl.gl_pathv[i]);
    }
    globfree(&gl);
    return;
  }
  // No matches or error — keep as literal so the compiler can error out if
  // needed.
  cb_files_add(out, pattern);
}
#endif

static void cb_expand_project_wildcards(_CB_PROJECT *proj) {
  if (!proj || !proj->files)
    return;
  CB_ARGLIST *expanded = arglist_new();
  for (int i = 0; i < proj->files->count; i++) {
    const char *f = proj->files->list[i];
    if (cb_str_has_wildcards(f)) {
#if OS_WIN
      cb_expand_pattern_win(expanded, f);
#else
      cb_expand_pattern_unix(expanded, f);
#endif
    } else {
      cb_files_add(expanded, f);
    }
  }
  // swap lists
  arglist_free(proj->files);
  proj->files = expanded;
  CB_DEBUG_LOG("Wildcard expansion for %s produced %d file(s)", proj->name,
               proj->files->count);
}

#ifdef _CB_PY

#include "cb_py.h"



typedef struct {
  const char *name;

  char *file_data;
  int file_size;

  char ***code_blocks;
  int code_block_count;
  int *code_block_sizes;
  int *code_block_starts;

} _CB_PROJECT_TRANSPILE;

static void _cb_project_transpile_free(_CB_PROJECT_TRANSPILE *transpile) {
  for (int i = 0; i < transpile->code_block_count; i++) {
    for (int j = 0; j < transpile->code_block_sizes[i]; j++) {
      free(transpile->code_blocks[i][j]); // free each line
    }
    free(transpile->code_blocks[i]); // free line array
  }
  free(transpile->code_blocks);
  free(transpile->code_block_sizes);
  free(transpile->code_block_starts);
  free(transpile->file_data);
  free(transpile);
}

static void _cb_project_transpile_append(_CB_PROJECT_TRANSPILE *transpile,
                                         char **code_block, int code_block_size,
                                         int start_line) {
  transpile->code_blocks =
      (char ***)realloc(transpile->code_blocks,
                        (transpile->code_block_count + 1) * sizeof(char **));
  transpile->code_block_sizes =
      (int *)realloc(transpile->code_block_sizes,
                     (transpile->code_block_count + 1) * sizeof(int));
  transpile->code_block_starts =
      (int *)realloc(transpile->code_block_starts,
                     (transpile->code_block_count + 1) * sizeof(int));

  transpile->code_blocks[transpile->code_block_count] = code_block;
  transpile->code_block_sizes[transpile->code_block_count] = code_block_size;
  transpile->code_block_starts[transpile->code_block_count] = start_line;
  transpile->code_block_count++;

  // Debug print
  CB_DEBUG_LOG("Captured code block #%d starting at line %d (%d lines):",
               transpile->code_block_count, start_line, code_block_size);
}

static char *cb_strip_comment_prefix(const char *line) {
  const char *p = line;
  while (*p == ' ' || *p == '\t')
    p++;

  if (p[0] == '/' && p[1] == '/') {
    p += 2;
    if (*p == ' ')
      p++;
  }

  return strdup(p); // return cleaned line
}
static int _py_to_c99(_CB_PROJECT *proj) {
  for (int i = 0; i < proj->files->count; i++) {
    const char *f = proj->files->list[i];
    FILE *fp = fopen(f, "r");
    if (!fp) {
      CB_DEBUG_LOG("Failed to open file %s", f);
      return -1;
    }

    // read file into memory
    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *file_data = (char *)malloc(file_size + 1);
    if (!file_data) {
      CB_DEBUG_LOG("Failed to allocate memory for file %s", f);
      fclose(fp);
      return -1;
    }
    fread(file_data, 1, file_size, fp);
    file_data[file_size] = '\0';
    fclose(fp);

    // split into lines
    int line_count = 0;
    char **lines = NULL;
    char *saveptr;
    char *tok = strtok_r(file_data, "\n", &saveptr);
    while (tok) {
      lines = (char **)realloc(lines, (line_count + 1) * sizeof(char *));
      lines[line_count++] = strdup(tok);
      tok = strtok_r(NULL, "\n", &saveptr);
    }

    // process file: detect blocks
    int in_block = 0;
    char **current_block = NULL;
    int current_size = 0;
    int start_line = 0;

    // new file buffer (lines replaced)
    char **new_lines = NULL;
    int new_count = 0;

    for (int j = 0; j < line_count; j++) {
      const char *line = lines[j];
      if (!in_block && strstr(line, "__CB_PY_BEGIN")) {
        in_block = 1;
        start_line = j;
        // keep a marker comment in output
        new_lines =
            (char **)realloc(new_lines, (new_count + 1) * sizeof(char *));
        new_lines[new_count++] = strdup("// transpiled block begin");
        continue;
      }

      if (in_block && strstr(line, "__CB_PY_END")) {
        in_block = 0;

        CB_DEBUG_LOG("Captured code block #%d starting at line %d (%d lines):",
                     new_count, start_line, current_size);
        for (int k = 0; k < current_size; k++) {
          CB_DEBUG_LOG("  %s", current_block[k]);
        }
        // transpile captured block
        int out_size = 0;
        char **c_lines =
            transpile_py_block(current_block, current_size, &out_size);

        for (int k = 0; k < out_size; k++) {
          new_lines =
              (char **)realloc(new_lines, (new_count + 1) * sizeof(char *));
          new_lines[new_count++] = c_lines[k]; // already malloc’d
        }

        // cleanup block
        for (int k = 0; k < current_size; k++)
          free(current_block[k]);
        free(current_block);
        current_block = NULL;
        current_size = 0;

        new_lines =
            (char **)realloc(new_lines, (new_count + 1) * sizeof(char *));
        new_lines[new_count++] = strdup("// transpiled block end");
        continue;
      }

      if (in_block) {
        // capture block lines (strip // prefix)
        current_block = (char **)realloc(current_block,
                                         (current_size + 1) * sizeof(char *));
        current_block[current_size++] = cb_strip_comment_prefix(line);
      } else {
        // just copy normal line
        new_lines =
            (char **)realloc(new_lines, (new_count + 1) * sizeof(char *));
        new_lines[new_count++] = strdup(line);
      }
    }

    // write file back
    fp = fopen(f, "w");
    if (!fp) {
      CB_DEBUG_LOG("Failed to write file %s", f);
      return -1;
    }
    for (int j = 0; j < new_count; j++) {
      fprintf(fp, "%s\n", new_lines[j]);
      free(new_lines[j]);
    }
    fclose(fp);

    // cleanup
    for (int j = 0; j < line_count; j++)
      free(lines[j]);
    free(lines);
    free(new_lines);
    free(file_data);

    CB_DEBUG_LOG("Transpiled %s", f);
  }
  return 0;
}

#define _CB_PYTHON_TRANSPILE(proj) int ret = _py_to_c99(proj)

#endif // _CB_PY
//---------- compile command ----------
static char *cb_concat_compile_command(_CB_PROJECT *proj) {
  if (!proj || !proj->files || proj->files->count == 0)
    return cb_strdup("[error] No source files");

#ifdef  _CB_PY
  if (proj->CB_PYTHON) {
    CB_DEBUG_LOG("Project is set to have _PY() blocks: %s", proj->output);
    CB_DEBUG_LOG("Will try to transpile into c99.");
    _CB_PYTHON_TRANSPILE(proj);
    if (ret != 0) {
      return cb_strdup("[error] Failed to transpile project");
    }
    CB_DEBUG_LOG("Transpilation successful for %s.", proj->output);
  }
#endif //    _CB_PY
  const char *cc = cb_pick_compiler_name();
  char *cmd = NULL;
  size_t cap = 0, len = 0;

#if OS_WIN
  switch (proj->build_type) {
  case BUILD_EXEC:
    cb_strcatf(&cmd, &cap, &len, "%s", cc);
    break;
  case BUILD_STATIC:
    // compile to .obj files
    for (int i = 0; i < proj->files->count; i++)
      cb_strcatf(&cmd, &cap, &len, "%s /c %s && ", cc, proj->files->list[i]);
    cb_strcatf(&cmd, &cap, &len, "lib /OUT:%s", proj->output);
    return cmd;
  case BUILD_SHARED:
    cb_strcatf(&cmd, &cap, &len, "%s /LD", cc);
    break;
  }
#else // Unix
  switch (proj->build_type) {
  case BUILD_EXEC:
    cb_strcatf(&cmd, &cap, &len, "%s", cc);
    break;
  case BUILD_STATIC:
    // compile all to .o then archive
    for (int i = 0; i < proj->files->count; i++)
      cb_strcatf(&cmd, &cap, &len, "%s -c %s && ", cc, proj->files->list[i]);
    cb_strcatf(&cmd, &cap, &len, "ar rcs %s *.o", proj->output);
    return cmd;
  case BUILD_SHARED:
    cb_strcatf(&cmd, &cap, &len, "%s -fPIC -shared", cc);
    break;
  }
#endif

  // Common flags
  for (int i = 0; i < proj->buildflags->count; i++)
    cb_strcatf(&cmd, &cap, &len, " %s", proj->buildflags->list[i]);

  if (proj->is_rebuild)
    cb_strcatf(&cmd, &cap, &len, " %s", CB_NEEDED_LIBS);

  // Add sources
  for (int i = 0; i < proj->files->count; i++)
    cb_strcatf(&cmd, &cap, &len, " %s", proj->files->list[i]);

  // Output handling
  if (proj->output) {
#if OS_WIN
    if (proj->build_type == BUILD_EXEC)
      cb_strcatf(&cmd, &cap, &len, " /Fe%s", proj->output);
    else if (proj->build_type == BUILD_SHARED)
      cb_strcatf(&cmd, &cap, &len, " /Fe%s", proj->output);
#else
    if (proj->build_type == BUILD_EXEC)
      cb_strcatf(&cmd, &cap, &len, " -o %s", proj->output);
    else if (proj->build_type == BUILD_SHARED)
      cb_strcatf(&cmd, &cap, &len, " -o %s", proj->output);
#endif
  }

  CB_DEBUG_LOG("Generated compile command: %s", cmd);
  return cmd;
}

//---------- info & free ----------
static void _cb_project_dump(_CB_PROJECT *proj) {
  if (!proj)
    return;

  printf("== Project Dump ==\n");
  printf("Name: %s\n", proj->name ? proj->name : "(unnamed)");
  printf("Output: %s\n", proj->output ? proj->output : "(none)");

  // Build type
  const char *type_str = "EXEC";
  if (proj->build_type == BUILD_STATIC)
    type_str = "STATIC";
  else if (proj->build_type == BUILD_SHARED)
    type_str = "SHARED";
  printf("Build type: %s\n", type_str);

  // Files
  printf("Files (%d):\n", proj->files ? proj->files->count : 0);
  if (proj->files)
    for (int i = 0; i < proj->files->count; i++)
      printf("  %s\n", proj->files->list[i]);

  // Build Flags
  printf("Build flags (%d):\n", proj->buildflags ? proj->buildflags->count : 0);
  if (proj->buildflags)
    for (int i = 0; i < proj->buildflags->count; i++)
      printf("  %s\n", proj->buildflags->list[i]);

  // Flags
  printf("Flags (%d):\n", proj->flags ? proj->flags->count : 0);
  if (proj->flags)
    for (int i = 0; i < proj->flags->count; i++)
      printf("  %s\n", proj->flags->list[i]);

  // Command
  printf("Compile command: %s\n",
         proj->compile_command ? proj->compile_command : "(none)");
}

static void cb_free_project(_CB_PROJECT *project) {
  if (!project)
    return;
  if (project->files)
    arglist_free(project->files);
  if (project->buildflags)
    arglist_free(project->buildflags);
  if (project->flags)
    arglist_free(project->flags);
  if (project->compile_command)
    free(project->compile_command);
  free(project);
}

//---------- checksum ----------
static char *cb_compute_md5(const char *data, size_t len) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5((const unsigned char *)data, len, digest);
  char *out = (char *)malloc(MD5_DIGEST_LENGTH * 2 + 1);
  if (!out) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    sprintf(out + i * 2, "%02x", digest[i]);
  out[MD5_DIGEST_LENGTH * 2] = 0;
  return out;
}

static char *cb_read_file_content(const char *filepath, size_t *out_len) {
  FILE *f = fopen(filepath, "rb");
  if (!f)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return NULL;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  char *buffer = (char *)malloc((size_t)size);
  if (!buffer) {
    fclose(f);
    return NULL;
  }
  size_t read_len = fread(buffer, 1, (size_t)size, f);
  fclose(f);
  if (out_len)
    *out_len = read_len;
  return buffer;
}

static char *cb_compute_project_checksum(_CB_PROJECT *proj) {
  if (!proj)
    return NULL;
  MD5_CTX ctx;
  MD5_Init(&ctx);

  // include compile command, which includes flags & file list
  if (proj->compile_command)
    MD5_Update(&ctx, proj->compile_command, strlen(proj->compile_command));

  // include file contents
  for (int i = 0; i < proj->files->count; i++) {
    size_t flen = 0;
    char *fcontent = cb_read_file_content(proj->files->list[i], &flen);
    if (fcontent) {
      MD5_Update(&ctx, fcontent, flen);
      free(fcontent);
    }
  }

  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5_Final(digest, &ctx);

  char *checksum = (char *)malloc(MD5_DIGEST_LENGTH * 2 + 1);
  if (!checksum) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    exit(1);
  }
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    sprintf(checksum + i * 2, "%02x", digest[i]);
  checksum[MD5_DIGEST_LENGTH * 2] = 0;
  return checksum;
}

static char *cb_read_checksum(const char *filename) {
  FILE *f = fopen(filename, "r");
  if (!f)
    return NULL;
  char buf[MD5_DIGEST_LENGTH * 2 + 1];
  size_t r = fread(buf, 1, MD5_DIGEST_LENGTH * 2, f);
  fclose(f);
  if (r != MD5_DIGEST_LENGTH * 2)
    return NULL;
  buf[r] = 0;
  return cb_strdup(buf);
}

static int cb_write_checksum(const char *filename, const char *checksum) {
  FILE *f = fopen(filename, "w");
  if (!f)
    return -1;
  size_t w = fwrite(checksum, 1, strlen(checksum), f);
  fclose(f);
  return (w == strlen(checksum)) ? 0 : -1;
}

//---------- process helpers ----------
static int proc_start_build_cmd(proc_t *proc, _CB_PROJECT *proj,
                                const char *cmdline) {
  if (!cmdline)
    return -1;
#if OS_WIN
  STARTUPINFOA si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&proc->pi, sizeof(proc->pi));

  // run through cmd.exe to avoid manual argument parsing
  char *full = NULL;
  size_t cap = 0, len = 0;
  cb_strcatf(&full, &cap, &len, "cmd.exe /C %s", cmdline);

  BOOL ok = CreateProcessA(NULL, full, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                           &proc->pi);
  free(full);
  if (!ok) {
    fprintf(stderr, COLOR_RED "[error] Failed to start build: %s\n" COLOR_RESET,
            cmdline);
    proc->running = 0;
    return -1;
  }
  proc->running = 1;
  proc->project = proj;
  proc->is_build = 1;
  return 0;
#else
  pid_t pid = fork();
  if (pid == 0) {
    // child: run via /bin/sh -c "cmdline"
    execl("/bin/sh", "sh", "-c", cmdline, (char *)NULL);
    perror("execl");
    _exit(127);
  } else if (pid > 0) {
    proc->pid = pid;
    proc->running = 1;
    proc->project = proj;
    proc->is_build = 1;
    return 0;
  } else {
    perror("fork");
    proc->running = 0;
    return -1;
  }
#endif
}

static int proc_start_run(proc_t *proc, _CB_PROJECT *proj, char **argv) {
#if OS_WIN
  STARTUPINFOA si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&proc->pi, sizeof(proc->pi));

  // Build a quoted commandline
  size_t cmdlen = 0;
  for (int i = 0; argv[i]; i++) {
    size_t arglen = strlen(argv[i]);
    int needs_quotes = strchr(argv[i], ' ') != NULL;
    cmdlen += arglen + (needs_quotes ? 2 : 0) + 1;
  }
  char *cmdline = (char *)malloc(cmdlen + 1);
  if (!cmdline)
    return -1;
  cmdline[0] = 0;
  for (int i = 0; argv[i]; i++) {
    int needs_quotes = strchr(argv[i], ' ') != NULL;
    if (i > 0)
      strcat(cmdline, " ");
    if (needs_quotes)
      strcat(cmdline, "\"");
    strcat(cmdline, argv[i]);
    if (needs_quotes)
      strcat(cmdline, "\"");
  }
  BOOL success = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL,
                                &si, &proc->pi);
  free(cmdline);
  if (!success) {
    fprintf(stderr, COLOR_RED "[error] Failed to run %s\n" COLOR_RESET,
            argv[0]);
    proc->running = 0;
    return -1;
  }
  proc->running = 1;
  proc->project = proj;
  proc->is_build = 0;
  return 0;
#else
  pid_t pid = fork();
  if (pid == 0) {
    execvp(argv[0], argv);
    perror("execvp");
    _exit(127);
  } else if (pid > 0) {
    proc->pid = pid;
    proc->running = 1;
    proc->project = proj;
    proc->is_build = 0;
    return 0;
  } else {
    perror("fork");
    proc->running = 0;
    return -1;
  }
#endif
}

static int proc_poll(proc_t *proc) {
  if (!proc->running)
    return -1;
#if OS_WIN
  DWORD res = WaitForSingleObject(proc->pi.hProcess, 0);
  if (res == WAIT_OBJECT_0) {
    DWORD code;
    GetExitCodeProcess(proc->pi.hProcess, &code);
    CloseHandle(proc->pi.hProcess);
    CloseHandle(proc->pi.hThread);
    proc->running = 0;
    return (int)code;
  }
  return -1;
#else
  int status;
  pid_t ret = waitpid(proc->pid, &status, WNOHANG);
  if (ret == 0)
    return -1; // still running
  else if (ret == proc->pid) {
    proc->running = 0;
    if (WIFEXITED(status))
      return WEXITSTATUS(status);
    else
      return -1;
  }
  return -1;
#endif
}

static void proc_wait_all(proc_t *procs, int count) {
  int running = count;
  while (running > 0) {
    running = 0;
    for (int i = 0; i < count; i++) {
      if (procs[i].running) {
        int ret = proc_poll(&procs[i]);
        if (ret < 0)
          running++;
      }
    }
#if OS_WIN
    Sleep(10);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 10000000;
    nanosleep(&ts, NULL);
#endif
  }
}

//---------- main build driver ----------
static void _cb_project_build_internal(CB_PROJECT_BUILD_CONFIG config) {
  if (!config.projects) {
    fprintf(stderr, COLOR_RED "[error] No projects to build.\n" COLOR_RESET);
    return;
  }

  // Back-compat: old .parallel means parallel_run if caller used it
  if (config.parallel_run <= 0 && config.parallel > 0)
    config.parallel_run = config.parallel;
  if (config.parallel_build <= 0)
    config.parallel_build = 1;
  if (config.parallel_run <= 0)
    config.parallel_run = 1;

#ifdef _CB_LOG_TO_FILE
  FILE *log = fopen(".cb_build.out", "a");
  if (!log) {
    perror("fopen");
    return;
  }
  time_t now = time(NULL);
  fprintf(log, "\n=== Build Started: %s", ctime(&now));
#endif

  // 1) Prepare: expand wildcards, build commands, compute checksums, decide
  // build/no-build
  typedef struct {
    _CB_PROJECT *proj;
    int should_build;
    char checksum_file[512];
    char *new_checksum;
    char *old_checksum;
  } item_t;

  int nproj = 0;
  while (config.projects[nproj])
    nproj++;
  item_t *items = (item_t *)calloc(nproj, sizeof(item_t));
  if (!items) {
    fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
    return;
  }

  for (int i = 0; i < nproj; i++) {
    _CB_PROJECT *proj = config.projects[i];

    // Expand wildcards BEFORE command & checksum
    cb_expand_project_wildcards(proj);
    _CB_BUILD_COMPILE_COMMAND(proj);

    // checksum filename (safe-ish)
    snprintf(items[i].checksum_file, sizeof(items[i].checksum_file),
             ".cb_checksum_%s", proj->name ? proj->name : "noname");
    items[i].proj = proj;

    // compute checksums
    items[i].new_checksum = cb_compute_project_checksum(proj);
    items[i].old_checksum = cb_read_checksum(items[i].checksum_file);
    items[i].should_build = 1;
    if (items[i].new_checksum && items[i].old_checksum &&
        strcmp(items[i].new_checksum, items[i].old_checksum) == 0) {
      items[i].should_build = 0;
    }
  }

  // 2) Build stage (parallel if requested)
  int build_jobs = 0;
  for (int i = 0; i < nproj; i++)
    if (items[i].should_build)
      build_jobs++;

  if (build_jobs == 0) {
    for (int i = 0; i < nproj; i++) {
      printf(COLOR_YELLOW
             "[build] Skipping %s (no changes detected)\n\n" COLOR_RESET,
             items[i].proj->name);
#ifdef _CB_LOG_TO_FILE
      if (log)
        fprintf(log, "[build] Skipped project: %s\n", items[i].proj->name);
#endif
    }
  } else if (config.parallel_build <= 1) {
    for (int i = 0; i < nproj; i++) {
      if (!items[i].should_build) {
        printf(COLOR_YELLOW
               "[build] Skipping %s (no changes detected)\n\n" COLOR_RESET,
               items[i].proj->name);
        continue;
      }
      _CB_PROJECT *proj = items[i].proj;
      printf(COLOR_YELLOW "[build] Building %s\n" COLOR_RESET, proj->name);
      printf("  %s\n", proj->compile_command);
#ifdef _CB_LOG_TO_FILE
      if (log)
        fprintf(log, "[build] Project: %s\nCommand: %s\n", proj->name,
                proj->compile_command);
#endif
      clock_t start = clock();
      // Run synchronously (serial mode)
#if OS_WIN
      // Use system here; it will invoke cmd.exe
      int ret = system(proj->compile_command);
#else
      int ret = system(proj->compile_command);
#endif
      clock_t end = clock();
      if (ret != 0) {
        fprintf(stderr, COLOR_RED "[error] Build failed for %s\n" COLOR_RESET,
                proj->name);
#ifdef _CB_LOG_TO_FILE
        if (log)
          fprintf(log, "[error] Build failed for %s\n", proj->name);
#endif
        continue;
      }
      double duration = (double)(end - start) / CLOCKS_PER_SEC;
      printf(COLOR_GREEN "[success] Built in %.2fs\n" COLOR_RESET, duration);
#ifdef _CB_LOG_TO_FILE
      if (log)
        fprintf(log, "[success] Built in %.2fs\n", duration);
#endif
      cb_write_checksum(items[i].checksum_file, items[i].new_checksum);
    }
  } else {
    // Parallel build pool
    int maxp = config.parallel_build;
    proc_t *pool = (proc_t *)calloc(maxp, sizeof(proc_t));
    if (!pool) {
      fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
      goto after_builds;
    }
    int active = 0, next = 0;

    while (1) {
      // launch while capacity
      while (active < maxp && next < nproj) {
        if (!items[next].should_build) {
          next++;
          continue;
        }
        _CB_PROJECT *proj = items[next].proj;
        printf(COLOR_YELLOW "[build] Building %s (parallel)\n" COLOR_RESET,
               proj->name);
        printf("  %s\n", proj->compile_command);
#ifdef _CB_LOG_TO_FILE
        if (log)
          fprintf(log, "[build] Project: %s\nCommand: %s\n", proj->name,
                  proj->compile_command);
#endif
        // find free slot
        int k = -1;
        for (int t = 0; t < maxp; t++)
          if (!pool[t].running) {
            k = t;
            break;
          }
        if (k == -1)
          break; // shouldn't happen due to active<maxp
        if (proc_start_build_cmd(&pool[k], proj, proj->compile_command) == 0) {
          active++;
        } else {
          fprintf(stderr,
                  COLOR_RED
                  "[error] Failed to start build for %s\n" COLOR_RESET,
                  proj->name);
        }
        next++;
      }

      if (active == 0) {
        // maybe there are only skipped projects left
        int remaining = 0;
        for (int j = next; j < nproj; j++)
          if (items[j].should_build)
            remaining++;
        if (remaining == 0)
          break;
      }

      // poll
      for (int t = 0; t < maxp; t++) {
        if (pool[t].running) {
          int ret = proc_poll(&pool[t]);
          if (ret >= 0) {
            active--;
            if (ret != 0) {
              fprintf(stderr,
                      COLOR_RED
                      "[error] Build failed for %s (exit %d)\n" COLOR_RESET,
                      pool[t].project ? pool[t].project->name : "(unknown)",
                      ret);
#ifdef _CB_LOG_TO_FILE
              if (log)
                fprintf(log, "[error] Build failed for %s\n",
                        pool[t].project ? pool[t].project->name : "(unknown)");
#endif
            } else {
              // success → write checksum
              for (int i = 0; i < nproj; i++)
                if (items[i].proj == pool[t].project)
                  cb_write_checksum(items[i].checksum_file,
                                    items[i].new_checksum);
              printf(COLOR_GREEN "[success] Built %s\n" COLOR_RESET,
                     pool[t].project ? pool[t].project->name : "");
            }
          }
        }
      }
#if OS_WIN
      Sleep(10);
#else
      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = 10000000;
      nanosleep(&ts, NULL);

#endif
      if (next >= nproj && active == 0)
        break;
    }
    free(pool);
  after_builds:;
    // Print skips that never printed
    for (int i = 0; i < nproj; i++)
      if (!items[i].should_build)
        printf(COLOR_YELLOW
               "[build] Skipping %s (no changes detected)\n" COLOR_RESET,
               items[i].proj->name);
  }

  // 3) Optional run stage (may be parallel)
  if (config.run) {
    int maxp = (config.parallel_run > 0 ? config.parallel_run : 1);
    proc_t *pool = (proc_t *)calloc(maxp, sizeof(proc_t));
    if (!pool) {
      fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
      goto cleanup;
    }
    int active = 0;
    for (int i = 0; i < nproj; i++) {
      _CB_PROJECT *proj = items[i].proj;

      int should_run = proj->output != NULL &&
                       (items[i].should_build || config.run_if_skipped);
      if (!should_run)
        continue;

      int argc = proj->flags ? proj->flags->count : 0;
      char **argv = (char **)malloc(sizeof(char *) * (argc + 2));
      if (!argv) {
        fprintf(stderr, COLOR_RED "[error] OOM\n" COLOR_RESET);
        continue;
      }

      char output_path[512];
#if OS_WIN
      snprintf(output_path, sizeof(output_path), "%s", proj->output);
#else
      snprintf(output_path, sizeof(output_path), "./%s", proj->output);
#endif
      argv[0] = cb_strdup(output_path);
      for (int j = 0; j < argc; j++)
        argv[j + 1] = proj->flags->list[j];
      argv[argc + 1] = NULL;

      if (maxp <= 1) {
        // run serially and wait
        printf(COLOR_CYAN "[run] %s\n" COLOR_RESET, argv[0]);
#if OS_WIN
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));
        // Build cmdline
        size_t cmdlen = 0;
        for (int z = 0; argv[z]; z++) {
          size_t L = strlen(argv[z]);
          int q = strchr(argv[z], ' ') != NULL;
          cmdlen += L + (q ? 2 : 0) + 1;
        }
        char *cmdline = (char *)malloc(cmdlen + 1);
        cmdline[0] = 0;
        for (int z = 0; argv[z]; z++) {
          int q = strchr(argv[z], ' ') != NULL;
          if (z > 0)
            strcat(cmdline, " ");
          if (q)
            strcat(cmdline, "\"");
          strcat(cmdline, argv[z]);
          if (q)
            strcat(cmdline, "\"");
        }
        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                           &pi)) {
          WaitForSingleObject(pi.hProcess, INFINITE);
          CloseHandle(pi.hProcess);
          CloseHandle(pi.hThread);
        } else {
          fprintf(stderr, COLOR_RED "[error] Failed to run %s\n" COLOR_RESET,
                  argv[0]);
        }
        free(cmdline);
#else
        pid_t pid = fork();
        if (pid == 0) {
          execvp(argv[0], argv);
          perror("execvp");
          _exit(127);
        } else if (pid > 0) {
          waitpid(pid, NULL, 0);
        } else {
          perror("fork");
        }
#endif
        free(argv[0]);
        free(argv);
        if (proj->is_rebuild) {
          // as per your debug note: stop the program if it's just a rebuild
          exit(1);
        }
      } else {
        // run in parallel pool
        // ensure slot
        for (;;) {
          int used = 0;
          for (int k = 0; k < maxp; k++)
            if (pool[k].running)
              used++;
          if (used < maxp)
            break;
          for (int k = 0; k < maxp; k++) {
            if (pool[k].running) {
              int ret = proc_poll(&pool[k]);
              (void)ret;
            }
          }
#if OS_WIN
          Sleep(10);
#else
          struct timespec ts;
          ts.tv_sec = 0;
          ts.tv_nsec = 10000000;
          nanosleep(&ts, NULL);
#endif
        }
        // find free slot
        int k = -1;
        for (int t = 0; t < maxp; t++)
          if (!pool[t].running) {
            k = t;
            break;
          }
        if (k >= 0) {
          printf(COLOR_CYAN "[run] %s (parallel)\n" COLOR_RESET, argv[0]);
          if (proc_start_run(&pool[k], proj, argv) != 0) {
            fprintf(stderr,
                    COLOR_RED "[error] Failed to start %s\n" COLOR_RESET,
                    argv[0]);
          }
        }
        // argv memory: argv[0] was strdup'ed; the child process duplicates
        // memory; we can free now
        free(argv[0]);
        free(argv);
      }
    }
    if (maxp > 1) {
      proc_wait_all(pool, maxp);
    }
    free(pool);
  }

cleanup:
#ifdef _CB_LOG_TO_FILE
  if (log)
    fclose(log);
#endif
  for (int i = 0; i < nproj; i++) {
    free(items[i].old_checksum);
    free(items[i].new_checksum);
  }
  free(items);
}

#endif // _CB_IMPLEMENTATION
#endif // _STB_CB_H
