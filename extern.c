/*
even though functions are considered "extern" by default in C,
you still need to use the "extern" keyword
when you want to explicitly declare a function that is defined in a different source file,
making it clear that the function's definition is located elsewhere
and not being defined in the current file; this helps with code clarity and modularity. 

in file "header.h"*/
extern int add(int a, int b); /*declares the "add" function, indicating it's defined elsewhere*/

/*in file "main.c"*/
#include "header.h"

int main() {
  int result = add(5, 3); /*uses the "add" function which is defined in another file*/
}

/*in another file "math_functions.c"*/
int add(int a, int b) { /*actual definition of the "add" function
  return a + b;
} 
