// SPDX-License-Identifier: GPL-2.0
/*
 * Restore the SELinux status page policyload back to the live AVC seqno when
 * KernelSU zeroes it via selinux_status_update_policyload(0). The repair is
 * applied through a seqlock dance that mirrors the kernel's own writer path,
 * so user-space readers of /sys/fs/selinux/status see a coherent
 *   status.policyload == access.avd.seqno
 * baseline whenever the AVC has produced a positive seqno.
 *
 * This module never alters allowed/auditallow/auditdeny/flags and never
 * influences access decisions; it only patches the metadata page.
 */

#define pr_fmt(fmt) "selinux_seqno_fix: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
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
static DEFINE_SPINLOCK(status_repair_lock);

static bool enabled = true;
static unsigned long av_user_hits;
static unsigned long policyload_hook_hits;
static unsigned long status_fixups;
static unsigned long av_user_no_status;
static unsigned long av_user_null_avd;
static unsigned int last_status_sequence;
static unsigned int last_status_policyload;
static unsigned int last_avc_policy_seqno;
static unsigned int last_avd_seqno;
static unsigned int last_repair_target;

module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable seqlock-style policyload repair on the SELinux status page");
module_param_named(hits, av_user_hits, ulong, 0444);
MODULE_PARM_DESC(hits, "Number of security_compute_av_user returns observed");
module_param_named(policyload_hook_hits, policyload_hook_hits, ulong, 0444);
MODULE_PARM_DESC(policyload_hook_hits, "Number of selinux_status_update_policyload returns observed");
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
MODULE_PARM_DESC(last_status_sequence, "Last SELinux status sequence observed before repair");
module_param_named(last_status_policyload, last_status_policyload, uint, 0444);
MODULE_PARM_DESC(last_status_policyload, "Last SELinux status policyload observed before repair");
module_param_named(last_avc_policy_seqno, last_avc_policy_seqno, uint, 0444);
MODULE_PARM_DESC(last_avc_policy_seqno, "Last AVC policy seqno observed");
module_param_named(last_avd_seqno, last_avd_seqno, uint, 0444);
MODULE_PARM_DESC(last_avd_seqno, "Last av_decision seqno observed via security_compute_av_user");
module_param_named(last_repair_target, last_repair_target, uint, 0444);
MODULE_PARM_DESC(last_repair_target, "Last value written into status.policyload by the repair path");
module_param_named(last_old_seqno, last_status_policyload, uint, 0444);
MODULE_PARM_DESC(last_old_seqno, "Compatibility alias for last_status_policyload");
module_param_named(last_live_seqno, last_repair_target, uint, 0444);
MODULE_PARM_DESC(last_live_seqno, "Compatibility alias for last_repair_target");

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

/*
 * Mirror selinux_status_update_status()'s seqlock writer side: bump sequence
 * to an odd value, publish the new policyload, then bump back to even. This
 * keeps userspace readers (the demo's seqlock-stable read loop in
 * KsuEdgeDetector.readSelinuxStatusStable) from seeing a torn intermediate
 * state.
 */
static void seqlock_publish_policyload(struct selinux_kernel_status_compat *status,
				       u32 target)
{
	u32 sequence = READ_ONCE(status->sequence);

	/* Make sure we start from an even baseline. */
	if (sequence & 1U)
		sequence++;

	WRITE_ONCE(status->sequence, sequence + 1);
	smp_wmb();
	WRITE_ONCE(status->policyload, target);
	smp_wmb();
	WRITE_ONCE(status->sequence, sequence + 2);
}

/*
 * Restore status.policyload to the supplied target. Skipped when target is 0
 * (we never want to advertise a fresh-policy baseline if we don't actually
 * have a positive AVC seqno) or when status already matches.
 */
static bool repair_status_policyload(u32 target)
{
	struct selinux_kernel_status_compat *status;
	unsigned long flags;
	u32 sequence_before;
	u32 policyload_before;

	if (!target)
		return false;

	if (!status_page_ready(&status))
		return false;

	spin_lock_irqsave(&status_repair_lock, flags);

	sequence_before = READ_ONCE(status->sequence);
	policyload_before = READ_ONCE(status->policyload);
	WRITE_ONCE(last_status_sequence, sequence_before);
	WRITE_ONCE(last_status_policyload, policyload_before);

	if (policyload_before == target) {
		spin_unlock_irqrestore(&status_repair_lock, flags);
		return true;
	}

	seqlock_publish_policyload(status, target);
	WRITE_ONCE(last_repair_target, target);
	bump_counter(&status_fixups);

	spin_unlock_irqrestore(&status_repair_lock, flags);

	pr_debug("repaired status.policyload %u -> %u (seq %u)\n",
		 policyload_before, target, sequence_before);
	return true;
}

/*
 * security_compute_av_user kretprobe: a continuous safety net that observes
 * the live av_decision and re-aligns the status page if KSU's policyload
 * stomp slipped through between the policy-load hook firing and the
 * userspace probe issuing its /access transaction.
 */
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
	struct selinux_kernel_status_compat *status;
	u32 avd_seqno;
	u32 avc_seqno;
	u32 target;

	if (!READ_ONCE(enabled))
		return 0;

	bump_counter(&av_user_hits);

	if (!avd) {
		bump_counter(&av_user_null_avd);
		return 0;
	}

	avd_seqno = READ_ONCE(avd->seqno);
	if (avd_seqno)
		WRITE_ONCE(last_avd_seqno, avd_seqno);

	if (!status_page_ready(&status)) {
		bump_counter(&av_user_no_status);
		return 0;
	}

	avc_seqno = read_avc_policy_seqno();
	target = avc_seqno ? avc_seqno : avd_seqno;
	repair_status_policyload(target);
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

/*
 * selinux_status_update_policyload kretprobe: the primary trigger. Whenever
 * something (the legitimate policy load, or KSU's apply_kernelsu_rules ->
 * selinux_status_update_policyload(0) stomp) updates the status page, we
 * compare against the live AVC seqno and, if they disagree, republish the
 * page with avc_policy_seqno() so detectors see the AOSP coherence contract
 * status.policyload == access.avd.seqno.
 */
static int policyload_update_return_handler(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct selinux_kernel_status_compat *status;
	u32 avc_seqno;

	if (!READ_ONCE(enabled))
		return 0;

	bump_counter(&policyload_hook_hits);

	if (!status_page_ready(&status))
		return 0;

	avc_seqno = read_avc_policy_seqno();
	if (!avc_seqno)
		return 0;

	if (READ_ONCE(status->policyload) != avc_seqno)
		repair_status_policyload(avc_seqno);
	return 0;
}

static struct kretprobe policyload_update_kretprobe = {
	.handler = policyload_update_return_handler,
	.maxactive = 16,
	.kp = {
		.symbol_name = "selinux_status_update_policyload",
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
		pr_warn("failed to resolve avc_policy_seqno; status repair will use observed avd seqno only\n");

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

	/* Seed the page once at load time so detectors that probe before any
	 * kretprobe fires already see the AOSP coherence contract.
	 */
	seed_seqno = read_avc_policy_seqno();
	if (seed_seqno)
		repair_status_policyload(seed_seqno);

	ret = register_kretprobe(&policyload_update_kretprobe);
	if (ret) {
		pr_warn("failed to register selinux_status_update_policyload kretprobe: %d (continuing with /access path only)\n",
			ret);
		policyload_update_kretprobe.kp.addr = NULL;
	}

	ret = register_kretprobe(&compute_av_user_kretprobe);
	if (ret) {
		pr_err("failed to register security_compute_av_user kretprobe: %d\n", ret);
		if (policyload_update_kretprobe.kp.addr)
			unregister_kretprobe(&policyload_update_kretprobe);
		return ret;
	}

	pr_info("loaded; seed avc_seqno=%u status.policyload=%u\n",
		seed_seqno, READ_ONCE(last_status_policyload));
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	unregister_kretprobe(&compute_av_user_kretprobe);
	if (policyload_update_kretprobe.kp.addr)
		unregister_kretprobe(&policyload_update_kretprobe);
	pr_info("unloaded\n");
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("Restore SELinux status.policyload after KSU stomps it on policy load");
MODULE_LICENSE("GPL");
