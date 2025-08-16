#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
  sleep(2);
  if (argc < 2) {
    printf("Usage: %s <name>\n", argv[1]);
    return EXIT_FAILURE;
  }
  printf("Hello World from %s\n", argv[1]);
  return EXIT_SUCCESS;
}
