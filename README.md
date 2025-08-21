# C BUILD

## Description

A lightweight single-header build system library for managing **one or more C projects** — without Makefiles.

It lets you:

* Define build logic directly in C.
* Build **sequentially** or **in parallel**.
* Run executables right after building.
* Automatically handle **self-rebuilding** build scripts.
* Use **wildcards** for file lists.
* Extend with your own macros.

---

## Installation

```bash
wget https://raw.githubusercontent.com/AnAnnoyinGoose/cbuild/refs/heads/main/src/lib/stb_cbuild.h -O cbuild.h
sudo mkdir -p /usr/local/include/cbuild
sudo cp cbuild.h /usr/local/include/cbuild
```

Now include it in your projects:

```c
#include <cbuild/cbuild.h>
```

---

## Showcase

This section shows **all functionality** of CBuild.

---

### 1. A simple project

```c
#include <cbuild/cbuild.h>

static _CB_PROJECT *hello = {0};

int main(void) {
    _CB_CREATE_PROJECT(hello,
        .name   = "Hello",
        .files  = CB_STRLIST("hello.c"),
        .output = "hello"
    );

    _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(hello), .run = 1);
}
```

➡️ Builds `hello.c`, produces `./hello`, and runs it.

---

### 2. Rebuild mode

```c
#include <cbuild/cbuild.h>
#include <stdio.h>

static _CB_PROJECT *self = {0};

int main(void) {
    _CB_CREATE_PROJECT(self,
        .name       = "Rebuild",
        .files      = CB_STRLIST("main.c"),
        .output     = "rebuild",
        .is_rebuild = 1
    );

    _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(self), .run = 1);

    printf("You will never see this if rebuild triggers.\n");
}
```

➡️ With `.is_rebuild = 1`:

* Builds the project.
* Runs it.
* Exits the whole process immediately.

---

### 3. Multiple projects

```c
#include <cbuild/cbuild.h>

static _CB_PROJECT *a = {0};
static _CB_PROJECT *b = {0};
static _CB_PROJECT *c = {0};

int main(void) {
    _CB_CREATE_PROJECT(a, .name = "A", .files = CB_STRLIST("a.c"), .output = "a");
    _CB_CREATE_PROJECT(b, .name = "B", .files = CB_STRLIST("b.c"), .output = "b");
    _CB_CREATE_PROJECT(c, .name = "C", .files = CB_STRLIST("c.c"), .output = "c");

    _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(a, b, c), .run = 1);
}
```

➡️ Builds projects **sequentially** and runs them in order.

---

### 4. Parallel builds

```c
_CB_PROJECT_BUILD(
    .projects = CB_PROJECT_LIST(a, b, c),
    .run = 0,
    .parallel = 3
);
```

➡️ Builds 3 projects at the same time, **without running them**.

---

### 5. Wildcards

```c
_CB_CREATE_PROJECT(a,
    .name   = "Wildcard Example",
    .files  = CB_STRLIST("src/*.c"),   // expands to all C files in src/
    .output = "app"
);
```

➡️ Automatically expands `*.c` into a list of files.

---

### 6. Build flags

```c
_CB_CREATE_PROJECT(crypto,
    .name       = "CryptoTool",
    .files      = CB_STRLIST("main.c"),
    .output     = "cryptotool",
    .buildflags = CB_STRLIST("-lssl -lcrypto")
);
```

➡️ Adds extra compiler/linker flags.
*(Rebuild projects automatically add `-lssl -lcrypto`.)*

---

### 7. Dumping project info

```c
cb_dump_to_console(crypto);
```

➡️ Prints details of the project (name, files, output, flags).

---

### 8. Freeing resources

```c
cb_free_project(crypto);
```

➡️ Frees memory used by a project.

---

## API Reference

### Macros

```c
#define     CB_DEBUG              // Enable debug logging
#define     _CB_LOG_TO_FILE       // Write logs to cbuild.log

MACRO       CB_DEBUG_LOG(fmt, ...); 
MACRO       _CB_PROJECT_BUILD(projects, run, parallel, run_if_skipped);
MACRO       _CB_CREATE_PROJECT(name, output, CB_STRLIST(files), CB_STRLIST(buildflags), CB_STRLIST(flags), is_rebuild);
MACRO       CB_PROJECT_LIST(...);
MACRO       CB_STRLIST(...);
```

### Types

```c
TYPE        _CB_PROJECT   // Represents a single project
```

### Functions

```c
static void cb_dump_to_console(const _CB_PROJECT*);  // Print project info
static void cb_free_project(const _CB_PROJECT*);     // Free memory
```

---

## Full Demo Program

This example uses **all features at once**:

```c
#include <cbuild/cbuild.h>
#include <stdio.h>

static _CB_PROJECT *self   = {0};
static _CB_PROJECT *lib    = {0};
static _CB_PROJECT *tool   = {0};
static _CB_PROJECT *tests  = {0};

int main(void) {
    // Self-rebuild project (bootstrap)
    _CB_CREATE_PROJECT(self,
        .name       = "BuildScript",
        .files      = CB_STRLIST("main.c"),
        .output     = "rebuild",
        .is_rebuild = 1
    );

    // Library project with wildcards
    _CB_CREATE_PROJECT(lib,
        .name   = "MyLibrary",
        .files  = CB_STRLIST("src/*.c"),   // collect all .c files
        .output = "libmylib.a"
    );

    // Tool project with custom flags
    _CB_CREATE_PROJECT(tool,
        .name       = "Tool",
        .files      = CB_STRLIST("tool.c"),
        .output     = "tool",
        .buildflags = CB_STRLIST("-lssl -lcrypto")
    );

    // Test suite project
    _CB_CREATE_PROJECT(tests,
        .name   = "Tests",
        .files  = CB_STRLIST("tests/*.c"),
        .output = "tests"
    );

    // Print project info
    cb_dump_to_console(lib);
    cb_dump_to_console(tool);

    // Build all projects, run only tests, build others in parallel 

    // Cleanup
    cb_free_project(lib);
    cb_free_project(tool);
    cb_free_project(tests);

    return 0;
}
```

➡️ What happens here:

1. **Self-rebuilds** the build script.
2. Builds a **library** from all `src/*.c`.
3. Builds a **tool** with extra flags.
4. Builds and runs a **test suite**.
5. Uses **parallelism** (`.parallel = 2`).
6. Dumps project info for debugging.
7. Frees resources before exiting.

---


## Py DSL

This is a [Py DSL](https://en.wikipedia.org/wiki/Domain-specific_language) for CBuild.
It allows the user to write Python in C projects.
CBuild translates it to C and compiles it.

### Example
`main.c`
```C
#define _CB_IMPLEMENTATION
#define CB_DEBUG
#define _CB_PY // Enable Python support
#include <cbuild/cbuild.h>

static _CB_PROJECT *this = {0};
static _CB_PROJECT *CB_PY = {0};

int main(int argc, char *argv[]) {
  _CB_CREATE_PROJECT(
      this, .name = "cmpy-rebuild", 
      .files = CB_STRLIST("src/main.c"), .build_type = BUILD_EXEC, .is_rebuild = 1,
      .output = "bin/cmpy-rebuild",
      .buildflags =
          CB_STRLIST("-std=c99 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE"));
  _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(this));

  _CB_CREATE_PROJECT(
      CB_PY, .name = "cmpy", 
      .files = CB_STRLIST("src/cmpy.c"), .build_type = BUILD_EXEC, .CB_PYTHON = 1, // Sets the project to use the DSL
      .output = "bin/cmpy",
      .buildflags =
          CB_STRLIST("-std=c99"));
  _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(CB_PY), .run = 1, .run_if_skipped = 1);

  printf("rebuild complete\n");
  return 0;
}
```

`src/cmpy.c`
```C
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
int main(void) {
// __CB_PY_BEGIN
// x = 1
// x = 2
// 
// name = "John"
// surname = "Doe"
//
//
// for i in range(10):
//    print(x)
//    x = x*2
// print("Name: ", name, surname)
// __CB_PY_END
  return EXIT_SUCCESS;
}
```


## Notes

* Rebuild projects auto-add `-lssl -lcrypto`.
* Supports **wildcards**, **parallel builds**, and **macro-based configuration**.
* Debug logging can be redirected to console or file.

---

## License

MIT License – free to use, modify, and distribute.
