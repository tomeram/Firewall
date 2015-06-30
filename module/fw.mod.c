#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x68d372d2, "module_layout" },
	{ 0x6dcd7881, "class_destroy" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x6d597694, "device_destroy" },
	{ 0x8ad2e126, "device_remove_file" },
	{ 0xbd33dff7, "nf_unregister_hook" },
	{ 0xeb987ea9, "device_create_file" },
	{ 0xc60796c9, "device_create" },
	{ 0xf34131ee, "__register_chrdev" },
	{ 0x34d76c42, "__class_create" },
	{ 0x4a54cfda, "nf_register_hook" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x42224298, "sscanf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x3f9b9190, "kmem_cache_alloc_trace" },
	{ 0x794a2c29, "kmalloc_caches" },
	{ 0x37a0cba, "kfree" },
	{ 0x50eedeb8, "printk" },
	{ 0x1b6314fd, "in_aton" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x61651be, "strcat" },
	{ 0xb81960ca, "snprintf" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "D837152E0AC6B29E62735AB");
