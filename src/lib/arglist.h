#ifndef _CB_ARGLIST_H
#define _CB_ARGLIST_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **list;
    int count;
    int capacity;
} CB_ARGLIST;

static inline CB_ARGLIST *arglist_new() {
    CB_ARGLIST *arglist = (CB_ARGLIST*) malloc(sizeof(CB_ARGLIST));
    arglist->count = 0;
    arglist->capacity = 8;
    arglist->list = (char**) malloc(sizeof(char *) * arglist->capacity);
    return arglist;
}

static inline void arglist_append(CB_ARGLIST *arglist, ...) {
    va_list args;
    va_start(args, arglist);
    char *arg;
    while ((arg = va_arg(args, char *)) != NULL) {
        if (arglist->count >= arglist->capacity) {
            arglist->capacity *= 2;
            arglist->list = (char**) realloc(arglist->list, sizeof(char *) * arglist->capacity);
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

#endif // _CB_ARGLIST_H

