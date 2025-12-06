#ifndef __HELPER_H__
#define __HELPER_H__

#define GLUE(a, b) __GLUE(a, b)
#define __GLUE(a, b) a##b

#define CVERIFY(expr, msg)                                                     \
  typedef char GLUE(compiler_verify_, msg)[(expr) ? (+1) : (-1)]

#define COMPILER_VERIFY(exp) CVERIFY(exp, __LINE__)

#endif // __HELPER_H__
