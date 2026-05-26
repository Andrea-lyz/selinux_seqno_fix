// SPDX-License-Identifier: GPL-2.0
/*
 * Keep the SELinux status page policyload metadata aligned with userspace
 * access-query seqno metadata. This intentionally does not change the access
 * decision.
 */

#define pr_fmt(fmt) "selinux_seqno_fix: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/types.h>

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
typedef u32 (*avc_policy_seqno_fn)(void);

struct seqno_fix_data {
	struct av_decision_compat *avd;
};

static struct selinux_kernel_status_compat *status_page_addr;
static avc_policy_seqno_fn avc_policy_seqno_ptr;
static u32 cached_avd_seqno;
static bool enabled = true;
static unsigned long av_user_hits;
static unsigned long status_fixups;
static unsigned long av_user_no_status;
static unsigned long av_user_null_avd;
static unsigned int last_status_sequence;
static unsigned int last_status_policyload;
static unsigned int last_avc_policy_seqno;
static unsigned int last_avd_seqno;

module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable seqno fixups for security_compute_av_user results");
module_param_named(hits, av_user_hits, ulong, 0444);
MODULE_PARM_DESC(hits, "Number of security_compute_av_user returns observed");
module_param_named(fixups, status_fixups, ulong, 0444);
MODULE_PARM_DESC(fixups, "Number of SELinux status policyload values rewritten");
module_param_named(status_fixups, status_fixups, ulong, 0444);
MODULE_PARM_DESC(status_fixups, "Number of SELinux status policyload values rewritten");
module_param_named(no_policyload, av_user_no_status, ulong, 0444);
MODULE_PARM_DESC(no_policyload, "Number of returns skipped because SELinux status was unavailable");
module_param_named(no_status, av_user_no_status, ulong, 0444);
MODULE_PARM_DESC(no_status, "Number of returns skipped because SELinux status was unavailable");
module_param_named(null_avd, av_user_null_avd, ulong, 0444);
MODULE_PARM_DESC(null_avd, "Number of returns skipped because the av_decision pointer was missing");
module_param_named(last_status_sequence, last_status_sequence, uint, 0444);
MODULE_PARM_DESC(last_status_sequence, "Last SELinux status sequence observed");
module_param_named(last_status_policyload, last_status_policyload, uint, 0444);
MODULE_PARM_DESC(last_status_policyload, "Last SELinux status policyload observed before alignment");
module_param_named(last_avc_policy_seqno, last_avc_policy_seqno, uint, 0444);
MODULE_PARM_DESC(last_avc_policy_seqno, "Last AVC policy seqno observed");
module_param_named(last_avd_seqno, last_avd_seqno, uint, 0444);
MODULE_PARM_DESC(last_avd_seqno, "Last av_decision seqno observed");
module_param_named(last_old_seqno, last_status_policyload, uint, 0444);
MODULE_PARM_DESC(last_old_seqno, "Compatibility alias for last_status_policyload");
module_param_named(last_live_seqno, last_avd_seqno, uint, 0444);
MODULE_PARM_DESC(last_live_seqno, "Compatibility alias for last_avd_seqno");

static void bump_counter(unsigned long *counter)
{
	WRITE_ONCE(*counter, READ_ONCE(*counter) + 1);
}

static u32 read_avc_policy_seqno(void)
{
	avc_policy_seqno_fn fn = READ_ONCE(avc_policy_seqno_ptr);
	u32 seqno;

	if (!fn)
		return 0;

	seqno = fn();
	if (seqno)
		WRITE_ONCE(last_avc_policy_seqno, seqno);
	return seqno;
}

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

static bool status_page_ready(struct selinux_kernel_status_compat **out)
{
	struct selinux_kernel_status_compat *status;

	status = READ_ONCE(status_page_addr);
	if (!status || !READ_ONCE(status->version))
		return false;

	*out = status;
	return true;
}

static bool align_status_policyload(u32 avd_seqno)
{
	struct selinux_kernel_status_compat *status;
	u32 sequence;
	u32 status_policyload;
	u32 avc_seqno;

	if (!avd_seqno)
		return false;

	if (!status_page_ready(&status))
		return false;

	sequence = READ_ONCE(status->sequence);
	status_policyload = READ_ONCE(status->policyload);
	avc_seqno = read_avc_policy_seqno();
	WRITE_ONCE(last_status_sequence, sequence);
	WRITE_ONCE(last_status_policyload, status_policyload);
	if (avc_seqno)
		WRITE_ONCE(last_avc_policy_seqno, avc_seqno);
	WRITE_ONCE(last_avd_seqno, avd_seqno);
	WRITE_ONCE(cached_avd_seqno, avd_seqno);

	if (sequence & 1U)
		return true;

	if (status_policyload != avd_seqno) {
		WRITE_ONCE(status->policyload, avd_seqno);
		bump_counter(&status_fixups);
		pr_debug("fixed status policyload %u -> %u\n",
			 status_policyload, avd_seqno);
	}

	return true;
}

static void seed_zero_status_policyload(u32 seed_seqno)
{
	struct selinux_kernel_status_compat *status;
	u32 sequence;
	u32 status_policyload;

	if (!seed_seqno || !status_page_ready(&status))
		return;

	sequence = READ_ONCE(status->sequence);
	status_policyload = READ_ONCE(status->policyload);
	WRITE_ONCE(last_status_sequence, sequence);
	WRITE_ONCE(last_status_policyload, status_policyload);
	WRITE_ONCE(last_avd_seqno, seed_seqno);

	if ((sequence & 1U) || status_policyload)
		return;

	WRITE_ONCE(status->policyload, seed_seqno);
	bump_counter(&status_fixups);
	pr_debug("seeded zero status policyload -> %u\n", seed_seqno);
}

static int seqno_fix_entry_handler(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct seqno_fix_data *data = (struct seqno_fix_data *)ri->data;

#if defined(CONFIG_ARM64)
	/* security_compute_av_user(..., avd) passes avd as the fourth argument. */
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
	u32 avd_seqno;

	if (!enabled)
		return 0;

	bump_counter(&av_user_hits);

	if (!avd) {
		bump_counter(&av_user_null_avd);
		return 0;
	}

	avd_seqno = READ_ONCE(avd->seqno);
	if (!align_status_policyload(avd_seqno))
		bump_counter(&av_user_no_status);

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
	u32 seed_seqno;
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

	avc_policy_seqno_ptr = (avc_policy_seqno_fn)
		resolve_symbol_with_kprobe("avc_policy_seqno");
	if (!avc_policy_seqno_ptr)
		pr_warn("failed to resolve avc_policy_seqno; using observed avd seqno only\n");

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

	seed_seqno = read_avc_policy_seqno();
	if (!seed_seqno)
		seed_seqno = 1;
	WRITE_ONCE(cached_avd_seqno, seed_seqno);
	seed_zero_status_policyload(seed_seqno);

	ret = register_kretprobe(&compute_av_user_kretprobe);
	if (ret) {
		pr_err("failed to register security_compute_av_user kretprobe: %d\n", ret);
		return ret;
	}

	pr_info("loaded, initial status policyload=%u cached_avd_seqno=%u\n",
		READ_ONCE(last_status_policyload), READ_ONCE(cached_avd_seqno));
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
