typedef __SIZE_TYPE__ size_t;

extern void *kmalloc(size_t size, int flags);

struct node {
  int v;
};

void test_nofail(void) {
  struct node *p = (struct node *)kmalloc(sizeof(struct node), 32768);
  p->v = 1;
}

void test_mayfail(void) {
  struct node *p = (struct node *)kmalloc(sizeof(struct node), 0);
  p->v = 2;
}
