#include <linux/rculist.h>

void foo(struct hlist_node *n, struct hlist_head *h)
{
	hlist_add_tail_rcu(n, h);
}
