typedef __SIZE_TYPE__ size_t;

extern void *kmalloc(size_t size, int flags);

struct node {
  int v;
};

static void sink_direct(struct node *p) {
  p->v = 1;
}

static void sink_guarded(struct node *p) {
  if (!p)
    return;
  p->v = 2;
}

static void sink_callee(struct node *p) {
  p->v = 3;
}

struct node *wrapper_alloc(void) {
  return (struct node *)kmalloc(sizeof(struct node), 0);
}

static struct node *return_null_direct(void) {
  return (struct node *)0;
}

static struct node *return_wrapper_chain(void) {
  struct node *p = wrapper_alloc();
  return p;
}

void test_direct(void) {
  struct node *p = (struct node *)kmalloc(sizeof(struct node), 0);
  sink_direct(p);
}

void test_guarded(void) {
  struct node *p = (struct node *)kmalloc(sizeof(struct node), 0);
  sink_guarded(p);
}

void test_wrapper(void) {
  struct node *p = wrapper_alloc();
  sink_callee(p);
}

void test_return_null_direct(void) {
  struct node *p = return_null_direct();
  sink_direct(p);
}

void test_return_wrapper_chain(void) {
  struct node *p = return_wrapper_chain();
  sink_callee(p);
}
