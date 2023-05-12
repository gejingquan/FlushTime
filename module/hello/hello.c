#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/string.h>


MODULE_AUTHOR("Gerty");
MODULE_DESCRIPTION("hello_driver");
MODULE_VERSION("v1.0");
MODULE_LICENSE("GPL");


#define ARMV8_SCTLR_EL1_UCI        (1 << 26) /* EL0 access enable */
#define ARMV8_CNTKCTL_EL1_EL0VCTEN (1 << 1)


#define DEVICE_NAME "hello_module"

extern unsigned long FlushTime_enable;


static int hello_driver_major;
static struct class*  hello_driver_class   = NULL;
static struct device* hello_driver_device  = NULL;

static int hello_open(struct inode * inode, struct file * filp)
{
  return 0;
}


static int hello_release(struct inode * inode, struct file *filp)
{
  return 0;
}

ssize_t hello_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{	
	char str[10];
	strcpy(str, "spectre");
	printk("current->pid=%lx,current->comm=%s!\n",current->pid,current->comm);
	if(strcmp(current->comm,str)==0)
	{
		printk("current->comm==spectre");
	}
	
	if(size==10)
		FlushTime_enable=0xdeadbeaf;
	if(size==0)
		FlushTime_enable=0;
    return 0;
}

static struct file_operations hello_driver_fops = {
	.owner   =    THIS_MODULE,
	.open    =    hello_open,
	.release =    hello_release,
	.read    =    hello_read,
};


static void smp_open_trap(void *t)
{
	uint32_t value = 0;
	uint32_t mask = 0;
    	
	asm volatile("MRS %0, SCTLR_EL1" : "=r" (value));
	printk("Before trap,SCTLR_EL1=%x,cpuid=%d",value,get_cpu());
	mask = 0;
	mask |= ARMV8_SCTLR_EL1_UCI;
	asm volatile("MSR SCTLR_EL1, %0" : : "r" (value & ~mask));
	asm volatile("MRS %0, SCTLR_EL1" : "=r" (value));
	printk("After trap,SCTLR_EL1=%x,cpuid=%d",value,get_cpu());
	
	
	

	asm volatile("MRS %0, CNTKCTL_EL1" : "=r" (value));
	printk("Before trap, CNTKCTL_EL1=%x,cpuid=%d",value,get_cpu());
	mask = 0;
	mask |= ARMV8_CNTKCTL_EL1_EL0VCTEN;
	asm volatile("MSR CNTKCTL_EL1, %0" : : "r" (value & ~mask));
	asm volatile("MRS %0, CNTKCTL_EL1" : "=r" (value));
	printk("After trap, CNTKCTL_EL1=%x,cpuid=%d",value,get_cpu());	
	
	
}


static void smp_close_trap(void *t)
{
	uint32_t value = 0;
	uint32_t mask = 0;
    	
	asm volatile("MRS %0, SCTLR_EL1" : "=r" (value));
	printk("Before trap, SCTLR_EL1=%x,cpuid=%d",value,get_cpu());
	mask = 0;
	mask |= ARMV8_SCTLR_EL1_UCI;
	asm volatile("MSR SCTLR_EL1, %0" : : "r" (value | mask));
	asm volatile("MRS %0, SCTLR_EL1" : "=r" (value));
	printk("After trap, SCTLR_EL1=%x,cpuid=%d",value,get_cpu());
	
	

	
	asm volatile("MRS %0, CNTKCTL_EL1" : "=r" (value));
	printk("Before trap, CNTKCTL_EL1=%x,cpuid=%d",value,get_cpu());
	mask = 0;
	mask |= ARMV8_CNTKCTL_EL1_EL0VCTEN;
	asm volatile("MSR CNTKCTL_EL1, %0" : : "r" (value | mask));
	asm volatile("MRS %0, CNTKCTL_EL1" : "=r" (value));
	printk("After trap, CNTKCTL_EL1=%x,cpuid=%d",value,get_cpu());	
	
	
}

static int __init hello_init(void)
{	
		
	on_each_cpu(smp_open_trap, NULL, 1);
	
	hello_driver_major = register_chrdev(0, DEVICE_NAME, &hello_driver_fops);
	if(hello_driver_major < 0){
		printk("failed to register device.\n");
		return -1;
	}

	hello_driver_class = class_create(THIS_MODULE, "hello_driver");
    if (IS_ERR(hello_driver_class)){
        printk("failed to create hello moudle class.\n");
        unregister_chrdev(hello_driver_major, DEVICE_NAME);
        return -1;
    }	

    hello_driver_device = device_create(hello_driver_class, NULL, MKDEV(hello_driver_major, 0), NULL, "hello_device");
    if (IS_ERR(hello_driver_device)){
        printk("failed to create device .\n");
        unregister_chrdev(hello_driver_major, DEVICE_NAME);
        return -1;
    }
	

	
	printk(KERN_ALERT "Trap cache maintenance instructions!\n");
	printk(KERN_ALERT "Hello world!\n");
	return 0;
}
static void __exit hello_exit(void)
{	

    device_destroy(hello_driver_class, MKDEV(hello_driver_major, 0));
    class_unregister(hello_driver_class);
	class_destroy(hello_driver_class);
	unregister_chrdev(hello_driver_major, DEVICE_NAME);


	on_each_cpu(smp_close_trap, NULL, 1);
	printk(KERN_ALERT "Close the trap!\n");	
	printk(KERN_ALERT "Goodbye,cruel world!");
}
module_init(hello_init);
module_exit(hello_exit);


