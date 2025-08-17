#ifndef _STB_CB_H
#define _STB_CB_H
#include <openssl/md5.h> // Requires OpenSSL
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// arglist.h
typedef struct {
  char **list;
  int count;
  int capacity;
} CB_ARGLIST;

static inline CB_ARGLIST *arglist_new();
static inline void arglist_append(CB_ARGLIST *arglist, ...);
static inline void arglist_append_array(CB_ARGLIST *arglist, const char **arr);
static inline void arglist_free(CB_ARGLIST *arglist);

#ifdef _CB_IMPLEMENTATION
static inline CB_ARGLIST *arglist_new() {
  CB_ARGLIST *arglist = (CB_ARGLIST *)malloc(sizeof(CB_ARGLIST));
  arglist->count = 0;
  arglist->capacity = 8;
  arglist->list = (char **)malloc(sizeof(char *) * arglist->capacity);
  return arglist;
}

static inline void arglist_append(CB_ARGLIST *arglist, ...) {
  va_list args;
  va_start(args, arglist);
  char *arg;
  while ((arg = va_arg(args, char *)) != NULL) {
    if (arglist->count >= arglist->capacity) {
      arglist->capacity *= 2;
      arglist->list =
          (char **)realloc(arglist->list, sizeof(char *) * arglist->capacity);
    }
    arglist->list[arglist->count++] = strdup(arg);
  }
  va_end(args);
}

static inline void arglist_append_array(CB_ARGLIST *arglist, const char **arr) {
  for (int i = 0; arr[i] != NULL; i++) {
    arglist_append(arglist, arr[i], NULL);
  }
}

static inline void arglist_free(CB_ARGLIST *arglist) {
  for (int i = 0; i < arglist->count; i++) {
    free(arglist->list[i]);
  }
  free(arglist->list);
  free(arglist);
}
#endif

//--------------------------------------------------------------------------------
//-----------------------------------cbuild.h-------------------------------------

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
#include <sys/types.h>
#endif

#if OS_UNIX
#define COMPILER_NAME "cc"
#elif OS_WIN
#define COMPILER_NAME "cl"
#elif OS_MACOS
#define COMPILER_NAME "clang"
#endif

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_CYAN "\x1b[36m"

typedef struct _CB_PROJECT {
  char *name;
  char *output;
  CB_ARGLIST *files;
  CB_ARGLIST *buildflags;
  CB_ARGLIST *flags;
  char *compile_command;
  int is_rebuild;
} _CB_PROJECT;

typedef struct {
  _CB_PROJECT **projects;
  int run;
  int run_if_skipped; // New: run even if build skipped
  int parallel;       // Number of parallel jobs
} CB_PROJECT_BUILD_CONFIG;

#define CB_STRLIST(...) ((const char *[]){__VA_ARGS__, NULL})
#define CB_PROJECT_LIST(...) ((_CB_PROJECT *[]){__VA_ARGS__, NULL})

#define _CB_CREATE_PROJECT(var, ...)                                           \
  _CB_PROJECT *var = malloc(sizeof(_CB_PROJECT));                              \
  memset(var, 0, sizeof(_CB_PROJECT));                                         \
  struct {                                                                     \
    char *name;                                                                \
    char *output;                                                              \
    const char **files;                                                        \
    const char **buildflags;                                                   \
    const char **flags;                                                        \
    int is_rebuild;                                                            \
  } var##_init = {__VA_ARGS__};                                                \
  var->name = var##_init.name;                                                 \
  var->output = var##_init.output;                                             \
  var->files = arglist_new();                                                  \
  var->buildflags = arglist_new();                                             \
  var->flags = arglist_new();                                                  \
  var->is_rebuild = var##_init.is_rebuild;                                     \
  if (var##_init.files)                                                        \
    arglist_append_array(var->files, var##_init.files);                        \
  if (var##_init.buildflags)                                                   \
    arglist_append_array(var->buildflags, var##_init.buildflags);              \
  if (var##_init.flags)                                                        \
  arglist_append_array(var->flags, var##_init.flags)

#define CB_NEEDED_LIBS "-lssl -lcrypto"

static char *cb_concat_compile_command(_CB_PROJECT *proj);
#define _CB_BUILD_COMPILE_COMMAND(proj)                                        \
  do {                                                                         \
    if ((proj)->compile_command) {                                             \
      CB_DEBUG_LOG("Freeing old compile command for project %s",               \
                   (proj)->name);                                              \
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

typedef struct {
#if OS_WIN
  PROCESS_INFORMATION pi;
#else
  pid_t pid;
#endif
  int running;
  _CB_PROJECT *project;
} proc_t;

static int proc_start(proc_t *proc, _CB_PROJECT *proj, char **argv);
static int proc_poll(proc_t *proc);
static void proc_wait_all(proc_t *procs, int count);

#define _CB_PROJECT_BUILD(...)                                                 \
  _cb_project_build_internal((CB_PROJECT_BUILD_CONFIG){__VA_ARGS__})

static void _cb_project_build_internal(CB_PROJECT_BUILD_CONFIG config);

#ifdef _CB_IMPLEMENTATION

static char *cb_concat_compile_command(_CB_PROJECT *proj) {
  if (!proj || !proj->files || proj->files->count == 0)
    return strdup("[error] No source files");

  size_t total_len = strlen(COMPILER_NAME) + 32;

  if (proj->is_rebuild)
    total_len += strlen(CB_NEEDED_LIBS) + 2;
  for (int i = 0; i < proj->buildflags->count; i++)
    total_len += strlen(proj->buildflags->list[i]) + 2;
  for (int i = 0; i < proj->files->count; i++)
    total_len += strlen(proj->files->list[i]) + 2;
  if (proj->output)
    total_len += strlen("-o ") + strlen(proj->output) + 2;
  for (int i = 0; i < proj->flags->count; i++)
    total_len += strlen(proj->flags->list[i]) + 2;

  char *cmd = (char *)malloc(total_len);
  if (!cmd)
    return NULL;

  strcpy(cmd, COMPILER_NAME);

  for (int i = 0; i < proj->buildflags->count; i++) {
    strcat(cmd, " ");
    strcat(cmd, proj->buildflags->list[i]);
  }

  if (proj->is_rebuild) {
    strcat(cmd, " ");
    strcat(cmd, CB_NEEDED_LIBS);
  }

  for (int i = 0; i < proj->files->count; i++) {
    strcat(cmd, " ");
    strcat(cmd, proj->files->list[i]);
  }

  if (proj->output) {
    strcat(cmd, " -o ");
    strcat(cmd, proj->output);
  }

  CB_DEBUG_LOG("Generated compile command: %s", cmd);
  return cmd;
}

static void cb_dump_to_console(const _CB_PROJECT *project) {
  if (!project) {
    printf("[error] Null project pointer\n");
    return;
  }

  printf(COLOR_CYAN "=== Project Info ===\n" COLOR_RESET);
  printf("Name       : %s\n", project->name ? project->name : "(null)");
  printf("Output     : %s\n", project->output ? project->output : "(null)");

  printf("\nFiles [%d]:\n", project->files ? project->files->count : 0);
  for (int i = 0; i < (project->files ? project->files->count : 0); i++)
    printf("  [%02d] %s\n", i, project->files->list[i]);

  printf("\nBuild Flags [%d]:\n",
         project->buildflags ? project->buildflags->count : 0);
  for (int i = 0; i < (project->buildflags ? project->buildflags->count : 0);
       i++)
    printf("  [%02d] %s\n", i, project->buildflags->list[i]);

  printf("\nRuntime Flags [%d]:\n", project->flags ? project->flags->count : 0);
  for (int i = 0; i < (project->flags ? project->flags->count : 0); i++)
    printf("  [%02d] %s\n", i, project->flags->list[i]);

  printf("\nCompile Command:\n  %s\n",
         project->compile_command ? project->compile_command : "(null)");

  printf("\nRebuild: %s\n", project->is_rebuild ? "true" : "false");

  printf(COLOR_CYAN "====================\n" COLOR_RESET);
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

static char *cb_compute_md5(const char *data, size_t len) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5((const unsigned char *)data, len, digest);
  char *out = (char *)malloc(MD5_DIGEST_LENGTH * 2 + 1);
  if (!out)
    return NULL;
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(out + i * 2, "%02x", digest[i]);
  }
  out[MD5_DIGEST_LENGTH * 2] = 0;
  return out;
}

static char *cb_read_file_content(const char *filepath, size_t *out_len) {
  FILE *f = fopen(filepath, "rb");
  if (!f) {
    CB_DEBUG_LOG("Failed to open file for checksum: %s", filepath);
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  if (size < 0) {
    CB_DEBUG_LOG("ftell failed for file: %s", filepath);
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *buffer = (char *)malloc(size);
  if (!buffer) {
    CB_DEBUG_LOG("Failed to allocate buffer for file content: %s", filepath);
    fclose(f);
    return NULL;
  }
  size_t read_len = fread(buffer, 1, size, f);
  fclose(f);
  if (out_len)
    *out_len = read_len;
  CB_DEBUG_LOG("Read %zu bytes from file %s for checksum", read_len, filepath);
  return buffer;
}

static char *cb_compute_project_checksum(_CB_PROJECT *proj) {
  if (!proj)
    return NULL;

  CB_DEBUG_LOG("Computing checksum for project %s", proj->name);

  MD5_CTX ctx;
  MD5_Init(&ctx);

  for (int i = 0; i < proj->files->count; i++) {
    size_t flen = 0;
    char *fcontent = cb_read_file_content(proj->files->list[i], &flen);
    if (fcontent) {
      MD5_Update(&ctx, fcontent, flen);
      free(fcontent);
    } else {
      CB_DEBUG_LOG("Warning: failed to read file %s for checksum",
                   proj->files->list[i]);
    }
  }

  if (proj->compile_command) {
    MD5_Update(&ctx, proj->compile_command, strlen(proj->compile_command));
  }

  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5_Final(digest, &ctx);

  char *checksum = (char *)malloc(MD5_DIGEST_LENGTH * 2 + 1);
  if (!checksum)
    return NULL;
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(checksum + i * 2, "%02x", digest[i]);
  }
  checksum[MD5_DIGEST_LENGTH * 2] = 0;

  CB_DEBUG_LOG("Checksum for project %s: %s", proj->name, checksum);
  return checksum;
}

static char *cb_read_checksum(const char *filename) {
  FILE *f = fopen(filename, "r");
  if (!f) {
    CB_DEBUG_LOG("Checksum file not found: %s", filename);
    return NULL;
  }
  char buf[MD5_DIGEST_LENGTH * 2 + 1];
  size_t r = fread(buf, 1, MD5_DIGEST_LENGTH * 2, f);
  fclose(f);
  if (r != MD5_DIGEST_LENGTH * 2) {
    CB_DEBUG_LOG("Checksum file %s incomplete or corrupted", filename);
    return NULL;
  }
  buf[r] = 0;
  CB_DEBUG_LOG("Read checksum from file %s: %s", filename, buf);
  return strdup(buf);
}

static int cb_write_checksum(const char *filename, const char *checksum) {
  FILE *f = fopen(filename, "w");
  if (!f) {
    CB_DEBUG_LOG("Failed to open checksum file for writing: %s", filename);
    return -1;
  }
  size_t w = fwrite(checksum, 1, strlen(checksum), f);
  fclose(f);
  CB_DEBUG_LOG("Wrote checksum to file %s: %s", filename, checksum);
  return (w == strlen(checksum)) ? 0 : -1;
}

static int proc_start(proc_t *proc, _CB_PROJECT *proj, char **argv) {
  CB_DEBUG_LOG("Starting process for project %s with command %s", proj->name,
               argv[0]);
#if OS_WIN
  STARTUPINFO si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&proc->pi, sizeof(proc->pi));

  size_t cmdlen = 0;
  for (int i = 0; argv[i]; i++) {
    size_t arglen = strlen(argv[i]);
    int needs_quotes = strchr(argv[i], ' ') != NULL;
    cmdlen += arglen + (needs_quotes ? 2 : 0) + 1;
  }

  char *cmdline = malloc(cmdlen + 1);
  if (!cmdline) {
    CB_DEBUG_LOG("Failed to allocate memory for cmdline");
    return -1;
  }

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

  BOOL success = CreateProcess(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL,
                               &si, &proc->pi);
  free(cmdline);

  if (!success) {
    fprintf(stderr,
            COLOR_RED "[error] Failed to start process %s\n" COLOR_RESET,
            argv[0]);
    proc->running = 0;
    return -1;
  }
  proc->running = 1;
  proc->project = proj;
  CB_DEBUG_LOG("Process started successfully for project %s", proj->name);
  return 0;
#else
  pid_t pid = fork();
  if (pid == 0) {
    execvp(argv[0], argv);
    perror("execvp");
    exit(1);
  } else if (pid > 0) {
    proc->pid = pid;
    proc->running = 1;
    proc->project = proj;
    CB_DEBUG_LOG("Forked child process %d for project %s", pid, proj->name);
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
    CB_DEBUG_LOG("Process finished for project %s with exit code %d",
                 proc->project->name, (int)code);
    return (int)code;
  }
  return -1;
#else
  int status;
  pid_t ret = waitpid(proc->pid, &status, WNOHANG);
  if (ret == 0)
    return -1; // Still running
  else if (ret == proc->pid) {
    proc->running = 0;
    if (WIFEXITED(status)) {
      int exit_code = WEXITSTATUS(status);
      CB_DEBUG_LOG("Process finished for project %s with exit code %d",
                   proc->project->name, exit_code);
      return exit_code;
    } else {
      CB_DEBUG_LOG("Process for project %s ended abnormally",
                   proc->project->name);
      return -1;
    }
  }
  return -1;
#endif
}

static void proc_wait_all(proc_t *procs, int count) {
  CB_DEBUG_LOG("Waiting for all parallel processes to finish (%d procs)",
               count);
  int running = count;
  while (running > 0) {
    running = 0;
    for (int i = 0; i < count; i++) {
      if (procs[i].running) {
        int ret = proc_poll(&procs[i]);
        if (ret >= 0) {
          // Process finished
        } else {
          running++;
        }
      }
    }
#if OS_WIN
    Sleep(10);
#else
    usleep(10000);
#endif
  }
  CB_DEBUG_LOG("All parallel processes have finished");
}

static void _cb_project_build_internal(CB_PROJECT_BUILD_CONFIG config) {
  if (!config.projects) {
    fprintf(stderr, COLOR_RED "[error] No projects to build.\n" COLOR_RESET);
    return;
  }

#ifdef _CB_LOG_TO_FILE
  FILE *log = fopen(".cb_build.out", "a");
  if (!log) {
    perror("fopen");
    return;
  }
  time_t now = time(NULL);
  fprintf(log, "\n=== Build Started: %s", ctime(&now));
#endif

  int max_parallel = config.parallel > 0 ? config.parallel : 1;
  proc_t *proc_pool = NULL;
  if (config.parallel > 0) {
    proc_pool = (proc_t *)calloc(max_parallel, sizeof(proc_t));
    CB_DEBUG_LOG("Initialized process pool for %d parallel jobs", max_parallel);
  }

  for (int i = 0; config.projects[i]; i++) {
    _CB_PROJECT *proj = config.projects[i];
    _CB_BUILD_COMPILE_COMMAND(proj);

    char checksum_file[512];
    snprintf(checksum_file, sizeof(checksum_file), ".cb_checksum_%s",
             proj->name);

    char *new_checksum = cb_compute_project_checksum(proj);
    char *old_checksum = cb_read_checksum(checksum_file);

    int should_build = 1;
    if (new_checksum && old_checksum &&
        strcmp(new_checksum, old_checksum) == 0) {
      should_build = 0;
      CB_DEBUG_LOG("No changes detected for project %s, skipping build",
                   proj->name);
    }

    if (!should_build) {
      printf(COLOR_YELLOW
             "[build] Skipping %s (no changes detected)\n" COLOR_RESET,
             proj->name);
#ifdef _CB_LOG_TO_FILE
      fprintf(log, "[build] Skipped project: %s\n", proj->name);
#endif
    } else {
      printf(COLOR_YELLOW "[build] Building %s\n" COLOR_RESET, proj->name);
      printf("  %s\n", proj->compile_command);
#ifdef _CB_LOG_TO_FILE
      fprintf(log, "[build] Project: %s\nCommand: %s\n", proj->name,
              proj->compile_command);
#endif

      clock_t start = clock();

      int ret = system(proj->compile_command);

      clock_t end = clock();

      CB_DEBUG_LOG("Build command exited with code %d for project %s", ret,
                   proj->name);

      if (ret != 0) {
        fprintf(stderr, COLOR_RED "[error] Build failed for %s\n" COLOR_RESET,
                proj->name);
#ifdef _CB_LOG_TO_FILE
        fprintf(log, "[error] Build failed for %s\n", proj->name);
#endif
        free(new_checksum);
        free(old_checksum);
        continue;
      }

      double duration = (double)(end - start) / CLOCKS_PER_SEC;
      printf(COLOR_GREEN "[success] Built in %.2fs\n" COLOR_RESET, duration);
#ifdef _CB_LOG_TO_FILE
      fprintf(log, "[success] Built in %.2fs\n", duration);
#endif

      cb_write_checksum(checksum_file, new_checksum);
      CB_DEBUG_LOG("Checksum updated for project %s", proj->name);
    }

    free(old_checksum);
    free(new_checksum);

    // Run executable if requested (and output specified)
    if (config.run && proj->output) {
      int argc = proj->flags ? proj->flags->count : 0;
      char **argv = (char **)malloc(sizeof(char *) * (argc + 2));
      if (!argv) {
        perror("malloc");
        continue;
      }

      char output_path[512];
#if OS_WIN
      snprintf(output_path, sizeof(output_path), "%s", proj->output);
#else
      snprintf(output_path, sizeof(output_path), "./%s", proj->output);
#endif
      argv[0] = strdup(output_path);
      for (int j = 0; j < argc; j++)
        argv[j + 1] = proj->flags->list[j];
      argv[argc + 1] = NULL;

      CB_DEBUG_LOG("Preparing to run project %s with executable %s", proj->name,
                   argv[0]);

      if (should_build || config.run_if_skipped) {
        if (config.parallel > 0) {
          int running_count = 0;
          for (int k = 0; k < max_parallel; k++) {
            if (proc_pool[k].running)
              running_count++;
          }
          CB_DEBUG_LOG("Currently running %d parallel processes",
                       running_count);

          while (running_count >= max_parallel) {
            for (int k = 0; k < max_parallel; k++) {
              int ret = proc_poll(&proc_pool[k]);
              if (ret >= 0) {
                CB_DEBUG_LOG("Parallel process slot freed");
                running_count--;
              }
            }
#if OS_WIN
            Sleep(10);
#else
            usleep(10000);
#endif
          }

          for (int k = 0; k < max_parallel; k++) {
            if (!proc_pool[k].running) {
              if (proc_start(&proc_pool[k], proj, argv) == 0) {
                running_count++;
                CB_DEBUG_LOG("Started parallel process for project %s",
                             proj->name);
              } else {
                CB_DEBUG_LOG("Failed to start parallel process for project %s",
                             proj->name);
              }
              break;
            }
          }
        } else {
          CB_DEBUG_LOG("Running project %s serially", proj->name);
#if OS_WIN
          PROCESS_INFORMATION pi;
          STARTUPINFO si;
          ZeroMemory(&si, sizeof(si));
          si.cb = sizeof(si);
          if (!CreateProcess(NULL, argv[0], NULL, NULL, FALSE, 0, NULL, NULL,
                             &si, &pi)) {
            fprintf(stderr, COLOR_RED "[error] Failed to run %s\n" COLOR_RESET,
                    argv[0]);
            CB_DEBUG_LOG("Failed to CreateProcess for %s", argv[0]);
          } else {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CB_DEBUG_LOG("Finished running process %s", argv[0]);
          }
#else
          pid_t pid = fork();
          if (pid == 0) {
            execvp(argv[0], argv);
            perror("execvp");
            exit(1);
          } else if (pid > 0) {
            waitpid(pid, NULL, 0);
            CB_DEBUG_LOG("Finished running process %s", argv[0]);
            if (proj->is_rebuild) {
              CB_DEBUG_LOG("%s is just a rebuild. Therefore not continuing in "
                           "the program. If this blocks something you have to "
                           "run this as the last or rewrite ur logic.",
                           proj->name);
              exit(1);
            }
          } else {
            perror("fork");
            CB_DEBUG_LOG("Failed to fork for running process %s", argv[0]);
          }
#endif
        }
      } else {
        CB_DEBUG_LOG("Skipping run for project %s because build was skipped "
                     "and run_if_skipped not set",
                     proj->name);
      }

      free(argv[0]);
      free(argv);
    }
  }

  if (config.parallel > 0 && proc_pool) {
    proc_wait_all(proc_pool, max_parallel);
    free(proc_pool);
  }

#ifdef _CB_LOG_TO_FILE
  fclose(log);
#endif
}

#endif

#endif
