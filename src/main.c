#define _CB_LOG_TO_FILE
#define CB_DEBUG
#include "./lib/cbuild.h"







static _CB_PROJECT *rebuild = {0};
static _CB_PROJECT *pjt = {0};

int main(int argc, char **argv) {
  _CB_CREATE_PROJECT(pjt,
    .name = "test",
    .output = "./bin/test",
    .files = CB_STRLIST("main.c"),
    .buildflags = CB_STRLIST("-Wall"),
    .is_rebuild = 1,
    .flags = CB_STRLIST("C Build") 
  );
  _CB_CREATE_PROJECT(rebuild,
      .name = "cb_rebuild",
      .output = "./bin/cbuild",
      .files = CB_STRLIST("./src/main.c"),
      .is_rebuild = 1,
      .buildflags = CB_STRLIST("-Wall -lssl -lcrypto")
      );

  _CB_PROJECT_BUILD(
      .projects = CB_PROJECT_LIST(rebuild),
      .parallel = 0,
      .run = 0,
     );

  _CB_PROJECT_BUILD(
      .projects = CB_PROJECT_LIST(pjt),
      .run = 1,
      .parallel = 0,
      .run_if_skipped = 1
      );

  return EXIT_SUCCESS;
}
