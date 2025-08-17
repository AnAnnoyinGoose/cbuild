# C BUILD
## Description
A build system library for 1+ C projects.

## Installation
```bash
wget https://raw.githubusercontent.com/AnAnnoyinGoose/cbuild/refs/heads/main/src/lib/cbuild.h -O cbuild.h
wget https://raw.githubusercontent.com/AnAnnoyinGoose/cbuild/refs/heads/main/src/lib/arglist.h -O arglist.h
sudo mkdir -p /usr/local/include/cbuild
sudo cp cbuild.h arglist.h /usr/local/include/cbuild
```

## Usage
### For rebuilding
```c
#include <cbuild/cbuild.h>
#include <stdio.h>

static _CB_PROJECT *this = {0};

int main() {
  _CB_CREATE_PROJECT(this, .name = "Rebuild", .files = CB_STRLIST("main.c"),
                     .output = "rebuild", .buildflags = CB_STRLIST("-lssl -lcrypto"), .is_rebuild = 1);
  _CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(this), .run = 1);
  printf("Hello world from the rebuild!\n");
  return 0;
}
```
This will rebuild the project and run the executable. And then exit out of the entire program.
This is because of the `.is_rebuild = 1` flag. That ensures that the project will get built and run.
After that *the program will ENTIRELY exit*.

### For building projects
```c
#include <cbuild/cbuild.h>

static _CB_PROJECT *this = {0};
static _CB_PROJECT *that = {0};
static _CB_PROJECT *other = {0};
```
Let's say you have 3 projects that you want to build. You can do it like this:
```c
_CB_CREATE_PROJECT(this, .name = "This", .files = CB_STRLIST("main.c"),
                   .output = "this", .is_rebuild = 1);
_CB_CREATE_PROJECT(that, .name = "That", .files = CB_STRLIST("main1.c"),
                   .output = "that");
_CB_CREATE_PROJECT(other, .name = "Other", .files = CB_STRLIST("main2.c"),
                   .output = "other");
```
~~FYI if you have CBUILD in ANY of your projects you need to add the `-lssl` and `-lcrypto` flags.~~
- no longer needed as the `.is_rebuild = 1` flag adds them by default
Then you can build them like this:
```c
_CB_PROJECT_BUILD(.projects = CB_PROJECT_LIST(this, that, other), .run = 1);
```
This will make them run after each other.
If you want parallel builds, you can use the `.parallel = n` flag.
Where `n` means how many processes at once will run.
You can also use the `.run = 0` flag to just build them.


## Signatures
```c
#define     CB_DEBUG
#define     _CB_LOG_TO_FILE
MACRO       CB_DEBUG_LOG(fmt, ...); 
TYPE        _CB_PROJECT
MACRO       _CB_PROJECT_BUILD(projects, run, parallel, run_if_skipped);
MACRO       _CB_CREATE_PROJECT(name, output, CB_STRLIST(files), CB_STRLIST(buildflags), CB_STRLIST(flags), is_rebuild); 
MACRO       CB_PROJECT_LIST(...);
MACRO       CB_STRLIST(...);
FUNC        static void cb_dump_to_console(const _CB_PROJECT*);
FUNC        static void cb_free_project(const _CB_PROJECT*);
```
These are all of the functions, macros, and types you can use to build your projects.
The other functions are for internal use.

