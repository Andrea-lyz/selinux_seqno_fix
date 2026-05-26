// SPDX-License-Identifier: GPL-2.0
/*
 * Keep SELinux userspace access-query seqno metadata aligned with the live
 * SELinux status page. This intentionally does not change the access decision.
 */

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/types.h>

#define pr_fmt(fmt) "selinux_seqno_fix: " fmt

struct av_decision_compat {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

struct selinux_kernel_status_compat {
	u32 version;
	u32 sequence;
	u32 enforcing;
	u32 policyload;
	u32 deny_unknown;
};

typedef struct page *(*selinux_kernel_status_page_fn)(void);

struct seqno_fix_data {
	struct av_decision_compat *avd;
};

static struct selinux_kernel_status_compat *status_page_addr;
static u32 cached_policyload;
static bool enabled = true;

module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable seqno fixups for security_compute_av_user results");

static void *resolve_symbol_with_kprobe(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	void *addr;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return NULL;

	addr = (void *)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static bool read_live_policyload(u32 *out)
{
	struct selinux_kernel_status_compat *status;
	u32 sequence_before;
	u32 sequence_after;
	u32 policyload;
	int attempt;

	status = READ_ONCE(status_page_addr);
	if (!status || !READ_ONCE(status->version))
		goto fallback;

	for (attempt = 0; attempt < 3; attempt++) {
		sequence_before = READ_ONCE(status->sequence);
		if (sequence_before & 1U) {
			cpu_relax();
			continue;
		}

		policyload = READ_ONCE(status->policyload);
		sequence_after = READ_ONCE(status->sequence);
		if (sequence_before == sequence_after) {
			if (policyload)
				WRITE_ONCE(cached_policyload, policyload);
			*out = policyload;
			return true;
		}

		cpu_relax();
	}

fallback:
	policyload = READ_ONCE(cached_policyload);
	if (!policyload)
		return false;

	*out = policyload;
	return true;
}

static int seqno_fix_entry_handler(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct seqno_fix_data *data = (struct seqno_fix_data *)ri->data;

#if defined(CONFIG_ARM64)
	data->avd = (struct av_decision_compat *)regs->regs[3];
#else
	data->avd = NULL;
#endif

	return 0;
}

static int seqno_fix_return_handler(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct seqno_fix_data *data = (struct seqno_fix_data *)ri->data;
	struct av_decision_compat *avd = data->avd;
	u32 live_seqno;
	u32 old_seqno;

	if (!enabled || !avd)
		return 0;

	if (!read_live_policyload(&live_seqno))
		return 0;

	old_seqno = READ_ONCE(avd->seqno);
	if (old_seqno != live_seqno) {
		WRITE_ONCE(avd->seqno, live_seqno);
		pr_debug("fixed avd seqno %u -> %u\n", old_seqno, live_seqno);
	}

	return 0;
}

static struct kretprobe compute_av_user_kretprobe = {
	.handler = seqno_fix_return_handler,
	.entry_handler = seqno_fix_entry_handler,
	.data_size = sizeof(struct seqno_fix_data),
	.maxactive = 64,
	.kp = {
		.symbol_name = "security_compute_av_user",
	},
};

static int __init selinux_seqno_fix_init(void)
{
	selinux_kernel_status_page_fn status_page_fn;
	struct page *status_page;
	int ret;

#if !defined(CONFIG_ARM64)
	pr_err("unsupported architecture; this module expects arm64 pt_regs\n");
	return -EOPNOTSUPP;
#endif

	status_page_fn = (selinux_kernel_status_page_fn)
		resolve_symbol_with_kprobe("selinux_kernel_status_page");
	if (!status_page_fn) {
		pr_err("failed to resolve selinux_kernel_status_page\n");
		return -ENOENT;
	}

	status_page = status_page_fn();
	if (!status_page) {
		pr_err("SELinux status page is unavailable\n");
		return -ENOMEM;
	}

	status_page_addr = page_address(status_page);
	if (!status_page_addr) {
		pr_err("SELinux status page has no direct mapping\n");
		return -EFAULT;
	}

	if (!read_live_policyload(&cached_policyload))
		cached_policyload = 0;
	if (!cached_policyload)
		pr_warn("initial SELinux policyload is 0; /access seqno will mirror status\n");

	ret = register_kretprobe(&compute_av_user_kretprobe);
	if (ret) {
		pr_err("failed to register security_compute_av_user kretprobe: %d\n", ret);
		return ret;
	}

	pr_info("loaded, initial policyload=%u\n", cached_policyload);
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	unregister_kretprobe(&compute_av_user_kretprobe);
	pr_info("unloaded\n");
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("Fix SELinux access/status seqno split metadata");
MODULE_LICENSE("GPL");
