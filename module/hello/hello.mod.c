#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xbba681f6, "module_layout" },
	{ 0x4e1d7a65, "class_destroy" },
	{ 0x183cb87b, "class_unregister" },
	{ 0x4334def0, "device_destroy" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xbcec5597, "device_create" },
	{ 0x9eb6244f, "__class_create" },
	{ 0x6060d44f, "__register_chrdev" },
	{ 0x5541ea93, "on_each_cpu" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0x7c32d0f0, "printk" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x1fdc7df2, "_mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3AB9ACCEC915CE0F730E628");
