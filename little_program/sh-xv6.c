// Linux port of xv6-riscv shell (no libc)
// Compile with "-ffreestanding"!
// 这是一个及其简易的shell实现，没有使用任何C语言的标准库，没有main函数，通过添加编译选项-ffreestanding编译即可
// 编译：gcc -c -ffreestanding sh-xv6.c -o sh-xv6.o
//      ld sh-xv6.o -o sh
//运行：./sh（需要先切换到系统中的/bin目录下，因为这个shell也是利用/bin下面的ls、chmod等可执行命令实现的

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/syscall.h>

// Parsed command representation
enum { EXEC = 1, REDIR, PIPE, LIST, BACK };

#define MAXARGS 10
#define NULL ((void *)0)

struct cmd {
  int type;
};

struct execcmd {
  int type;
  char *argv[MAXARGS], *eargv[MAXARGS];
};

struct redircmd {
  int type, fd, mode;
  char *file, *efile;
  struct cmd* cmd;
};

struct pipecmd {
  int type;
  struct cmd *left, *right;
};

struct listcmd {
  int type;
  struct cmd *left, *right;
};

struct backcmd {
  int type;
  struct cmd* cmd;
};

struct cmd* parsecmd(char*);

// Minimum runtime library
long syscall(int num, ...) {
  va_list ap;
  va_start(ap, num);
  register long a0 asm ("rax") = num;
  register long a1 asm ("rdi") = va_arg(ap, long);//将num后面的第一个参数传递给a1，后面依此类推
  register long a2 asm ("rsi") = va_arg(ap, long);
  register long a3 asm ("rdx") = va_arg(ap, long);
  register long a4 asm ("r10") = va_arg(ap, long);
  va_end(ap);
  asm volatile("syscall"
    : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4)
    : "memory", "rcx", "r8", "r9", "r11");
  return a0;
}

size_t strlen(const char *s) {
  size_t len = 0;
  for (; *s; s++) len++;
  return len;
}

char *strchr(const char *s, int c) {//在字符串中查找指定字符
  for (; *s; s++) {
    if (*s == c) return (char *)s;
  }
  return NULL;
}

void print(const char *s, ...) {
  va_list ap;
  va_start(ap, s);
  while (s) {
    syscall(SYS_write, 2, s, strlen(s));
    s = va_arg(ap, const char *);
  }
  va_end(ap);
}

#define assert(cond) \
  do { if (!(cond)) { \
    print("Panicked.\n", NULL); \
    syscall(SYS_exit, 1); } \
  } while (0)

static char mem[4096], *freem = mem;

void *zalloc(size_t sz) {
  assert(freem + sz < mem + sizeof(mem));
  void *ret = freem;
  freem += sz;
  return ret;
}

// Execute cmd.  Never returns.
void runcmd(struct cmd* cmd) {
  int p[2];
  struct backcmd* bcmd;
  struct execcmd* ecmd;
  struct listcmd* lcmd;
  struct pipecmd* pcmd;
  struct redircmd* rcmd;

  if (cmd == 0) syscall(SYS_exit, 1);

  switch (cmd->type) {
    case EXEC:
      ecmd = (struct execcmd*)cmd;
      if (ecmd->argv[0] == 0) syscall(SYS_exit, 1);
      syscall(SYS_execve, ecmd->argv[0], ecmd->argv, NULL);
      print("fail to exec ", ecmd->argv[0], "\n", NULL);
      break;

    case REDIR:
      rcmd = (struct redircmd*)cmd;
      syscall(SYS_close, rcmd->fd);//打开文件再关闭是为了实现文件描述符重新分配，就实现了重定向
      if (syscall(SYS_open, rcmd->file, rcmd->mode, 0644) < 0) {
        print("fail to open ", rcmd->file, "\n", NULL);
        syscall(SYS_exit, 1);
      }
      runcmd(rcmd->cmd);
      break;

    case LIST:
      lcmd = (struct listcmd*)cmd;
      if (syscall(SYS_fork) == 0) runcmd(lcmd->left);
      syscall(SYS_wait4, -1, 0, 0, 0);
      runcmd(lcmd->right);
      break;

    case PIPE:
      pcmd = (struct pipecmd*)cmd;
      assert(syscall(SYS_pipe, p) >= 0);
      if (syscall(SYS_fork) == 0) {
        syscall(SYS_close, 1);
        syscall(SYS_dup, p[1]);
        syscall(SYS_close, p[0]);
        syscall(SYS_close, p[1]);
        runcmd(pcmd->left);
      }
      if (syscall(SYS_fork) == 0) {
        syscall(SYS_close, 0);
        syscall(SYS_dup, p[0]);
        syscall(SYS_close, p[0]);
        syscall(SYS_close, p[1]);
        runcmd(pcmd->right);
      }
      syscall(SYS_close, p[0]);
      syscall(SYS_close, p[1]);
      syscall(SYS_wait4, -1, 0, 0, 0);
      syscall(SYS_wait4, -1, 0, 0, 0);
      break;

    case BACK:
      bcmd = (struct backcmd*)cmd;
      if (syscall(SYS_fork) == 0) runcmd(bcmd->cmd);
      break;

    default:
      assert(0);
  }
  syscall(SYS_exit, 0);
}

int getcmd(char* buf, int nbuf) {//从终端读取命令字符串
  print("> ", NULL);
  for (int i = 0; i < nbuf; i++) buf[i] = '\0';

  while (nbuf-- > 1) {
    int nread = syscall(SYS_read, 0, buf, 1);//一个字符一个字符地读取
    if (nread <= 0) return -1;
    if (*(buf++) == '\n') break;
  }
  return 0;
}

void _start() {   //程序从这里开始运行
  static char buf[100];

  // Read and run input commands.
  while (getcmd(buf, sizeof(buf)) >= 0) {
    if (buf[0] == 'c' && buf[1] == 'd' && buf[2] == ' ') {
      // Chdir 命令只能被当前(父)进程处理
      buf[strlen(buf) - 1] = 0;  // chop \n
      if (syscall(SYS_chdir, buf + 3) < 0) print("cannot cd ", buf + 3, "\n", NULL);
      continue;
    }
    if (syscall(SYS_fork) == 0) runcmd(parsecmd(buf));
    syscall(SYS_wait4, -1, 0, 0, 0);
  }
  syscall(SYS_exit, 0);
}

// Constructors

struct cmd* execcmd(void) {
  struct execcmd* cmd;

  cmd = zalloc(sizeof(*cmd));
  cmd->type = EXEC;
  return (struct cmd*)cmd;
}

struct cmd* redircmd(struct cmd* subcmd, char* file, char* efile, int mode,
                     int fd) {
  struct redircmd* cmd;

  cmd = zalloc(sizeof(*cmd));
  cmd->type = REDIR;
  cmd->cmd = subcmd;
  cmd->file = file;
  cmd->efile = efile;
  cmd->mode = mode;
  cmd->fd = fd;
  return (struct cmd*)cmd;
}

struct cmd* pipecmd(struct cmd* left, struct cmd* right) {
  struct pipecmd* cmd;

  cmd = zalloc(sizeof(*cmd));
  cmd->type = PIPE;
  cmd->left = left;
  cmd->right = right;
  return (struct cmd*)cmd;
}

struct cmd* listcmd(struct cmd* left, struct cmd* right) {
  struct listcmd* cmd;

  cmd = zalloc(sizeof(*cmd));
  cmd->type = LIST;
  cmd->left = left;
  cmd->right = right;
  return (struct cmd*)cmd;
}

struct cmd* backcmd(struct cmd* subcmd) {
  struct backcmd* cmd;

  cmd = zalloc(sizeof(*cmd));
  cmd->type = BACK;
  cmd->cmd = subcmd;
  return (struct cmd*)cmd;
}

// Parsing

char whitespace[] = " \t\r\n\v";
char symbols[] = "<|>&;()";

int gettoken(char** ps, char* es, char** q, char** eq) {//字符（令牌）解析
  char* s;
  int ret;

  s = *ps;
  while (s < es && strchr(whitespace, *s)) s++;//跳过空白字符
  if (q) *q = s;//如果参数 q 不为 NULL，则将当前位置 s 赋给 q 指针，用于记录令牌的起始位置。
  ret = *s;
  switch (*s) {
    case 0://说明s>=es了
      break;
    case '|': case '(': case ')': case ';': case '&': case '<':
      s++;
      break;
    case '>'://若令牌为上述字符，直接返回其ASCII码值即可
      s++;
      if (*s == '>') {//若是>>则表示令牌为追加重定向
        ret = '+'; s++;
      }
      break;
    default://若是其他字符，则令牌类型为字母，继续往后移动直到遇见空白或特殊字符
      ret = 'a';
      while (s < es && !strchr(whitespace, *s) && !strchr(symbols, *s)) s++;
      break;
  }
  if (eq) *eq = s;//如果参数 eq 不为 NULL，则将当前位置 s 赋给 eq 指针，用于记录令牌的结束位置。

  while (s < es && strchr(whitespace, *s)) s++;//跳过空白
  *ps = s;//将*ps指向下一个令牌
  return ret;
}

int peek(char** ps, char* es, char* toks) { //使得*ps跳过whitespace中的字符（空格）并返回
  char* s;

  s = *ps;
  while (s < es && strchr(whitespace, *s)) s++;
  *ps = s;
  return *s && strchr(toks, *s);
}

struct cmd* parseline(char**, char*);
struct cmd* parsepipe(char**, char*);
struct cmd* parseexec(char**, char*);
struct cmd* nulterminate(struct cmd*);

struct cmd* parsecmd(char* s) {
  char* es;
  struct cmd* cmd;

  es = s + strlen(s);
  cmd = parseline(&s, es);
  peek(&s, es, "");
  assert(s == es);
  nulterminate(cmd);
  return cmd;
}

struct cmd* parseline(char** ps, char* es) {//解析这一行命令，
  struct cmd* cmd;

  cmd = parsepipe(ps, es);
  while (peek(ps, es, "&")) {
    gettoken(ps, es, 0, 0);
    cmd = backcmd(cmd);
  }
  if (peek(ps, es, ";")) {
    gettoken(ps, es, 0, 0);
    cmd = listcmd(cmd, parseline(ps, es));
  }
  return cmd;
}

struct cmd* parsepipe(char** ps, char* es) {//解析管道，
  struct cmd* cmd;

  cmd = parseexec(ps, es);
  if (peek(ps, es, "|")) {
    gettoken(ps, es, 0, 0);
    cmd = pipecmd(cmd, parsepipe(ps, es));
  }
  return cmd;
}

struct cmd* parseredirs(struct cmd* cmd, char** ps, char* es) {//文件目录解析，只有遇见>或<时才会解析，返回一条具体与读写文件相关的命令，否则原样返回
  int tok;
  char *q, *eq;

  while (peek(ps, es, "<>")) {
    tok = gettoken(ps, es, 0, 0);
    assert(gettoken(ps, es, &q, &eq) == 'a');
    switch (tok) {
      case '<':
        cmd = redircmd(cmd, q, eq, O_RDONLY, 0);//最后一个0是文件描述符，后续会关闭这个文件描述符，即关闭标准输入，然后打开文件，新打开的文件的文件描述符会被分配为0，就可以实现重定向功能
        break;
      case '>':
        cmd = redircmd(cmd, q, eq, O_WRONLY | O_CREAT | O_TRUNC, 1);
        break;
      case '+':  // >>
        cmd = redircmd(cmd, q, eq, O_WRONLY | O_CREAT, 1);
        break;
    }
  }
  return cmd;
}

struct cmd* parseblock(char** ps, char* es) {//处理被()包裹的命令字符串
  struct cmd* cmd;

  assert(peek(ps, es, "("));
  gettoken(ps, es, 0, 0);//将ps指向(后一个字符，会跳过后面的空白
  cmd = parseline(ps, es);
  assert(peek(ps, es, ")"));
  gettoken(ps, es, 0, 0);
  cmd = parseredirs(cmd, ps, es);
  return cmd;
}

struct cmd* parseexec(char** ps, char* es) {//解析可执行的命令，
  char *q, *eq;
  int tok, argc;
  struct execcmd* cmd;
  struct cmd* ret;

  if (peek(ps, es, "(")) return parseblock(ps, es);

  ret = execcmd();
  cmd = (struct execcmd*)ret;

  argc = 0;
  ret = parseredirs(ret, ps, es);
  while (!peek(ps, es, "|)&;")) {
    if ((tok = gettoken(ps, es, &q, &eq)) == 0) break;
    assert(tok == 'a');//能走到这里说明一定是字母，不是其他特殊符号所以返回的tok一定是a
    cmd->argv[argc] = q;
    cmd->eargv[argc] = eq;
    assert(++argc < MAXARGS);
    ret = parseredirs(ret, ps, es);
  }
  cmd->argv[argc] = 0;//将最后的位置补上NULL
  cmd->eargv[argc] = 0;
  return ret;
}

// NUL-terminate all the counted strings.
struct cmd* nulterminate(struct cmd* cmd) {//这个函数用来递归释放已经分配的内存
  int i;
  struct backcmd* bcmd;
  struct execcmd* ecmd;
  struct listcmd* lcmd;
  struct pipecmd* pcmd;
  struct redircmd* rcmd;

  if (cmd == 0) return 0;

  switch (cmd->type) {
    case EXEC:
      ecmd = (struct execcmd*)cmd;
      for (i = 0; ecmd->argv[i]; i++) *ecmd->eargv[i] = 0;
      break;

    case REDIR:
      rcmd = (struct redircmd*)cmd;
      nulterminate(rcmd->cmd);
      *rcmd->efile = 0;
      break;

    case PIPE:
      pcmd = (struct pipecmd*)cmd;
      nulterminate(pcmd->left);
      nulterminate(pcmd->right);
      break;

    case LIST:
      lcmd = (struct listcmd*)cmd;
      nulterminate(lcmd->left);
      nulterminate(lcmd->right);
      break;

    case BACK:
      bcmd = (struct backcmd*)cmd;
      nulterminate(bcmd->cmd);
      break;
  }
  return cmd;
}
