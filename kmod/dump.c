#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>

static void dump_mempage(char *addr) {
    int i;
    printk(KERN_ALERT "dump page at %lx\n", addr);
    for (i = 0; i < 0x1000; i++) {
        printk(KERN_CONT "%02hhx.", addr[i]);
        if (i%16==15)   printk(KERN_CONT " - ");
        if (i%32==31)   printk(KERN_CONT "\n");
    }
}

static int __init dump_init(void) {
    printk("DEBUG %lx\n", PAGE_OFFSET);
    //dump_mempage((char*)0x80000000);
    //dump_mempage((char*)0x80008000);
    void *p = &ioremap;
    printk("ioremap %px - %pK\n", p, p);
    if (p == 0x801182c0)
        printk("DEBUG yess\n");
    dump_mempage(p);
    dump_mempage(0x8000);
    return 0;
}

static void __exit dump_exit(void) {
}

module_init(dump_init);
module_exit(dump_exit);
