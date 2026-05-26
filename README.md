# selinux_seqno_fix

Tiny Android kernel module for the SELinux `/sys/fs/selinux/status` and
`/sys/fs/selinux/access` seqno split exposed by KernelSU policy hiding.

The module restores `status.policyload` to the live AVC `seqno` whenever
something (typically KernelSU's `apply_kernelsu_rules() ->
selinux_status_update_policyload(0)`) zeroes it. The repair is performed
through the same seqlock dance used by the kernel's own writer, so userspace
readers never observe a torn intermediate state. It does not change `allowed`,
`auditallow`, `auditdeny`, or `flags` and never affects access decisions.

## Detection model

The Duck Detector / `ksu-edge-seqno-demo` clean baseline is:

```text
status.sequence is even and stable
status.policyload > 0
access.avd.seqno > 0
status.policyload == access.avd.seqno
```

Detectors flag a split when `status.policyload == 0` (or otherwise diverges
from `access.avd.seqno`) while `status.sequence` is nonzero. Pulling
`access.avd.seqno` to zero would be visible too, so this module instead
restores `status.policyload` to the live `avc_policy_seqno()` value, matching
the AOSP coherence contract.

## How it works

1. At load, the module resolves `selinux_kernel_status_page()` and
   `avc_policy_seqno()` with one-shot kprobes, maps the status page, and seeds
   `status.policyload` from `avc_policy_seqno()`.
2. A kretprobe on `selinux_status_update_policyload` republishes the AVC seqno
   into the status page right after every update, including KSU's `update(0)`
   stomp. The republish bumps `status.sequence` to odd, writes the new
   `policyload`, then bumps `status.sequence` back to even, with `smp_wmb()`
   between, mirroring `selinux_status_update_status()`.
3. A kretprobe on `security_compute_av_user` acts as a continuous safety net:
   if any path slips through (or `selinux_status_update_policyload` cannot be
   probed), the userspace `/access` query path will trigger the same repair
   using the `avd.seqno` it just produced.

## Build

You need the exact kernel build tree for the running kernel, including matching
`.config`, `Module.symvers`, compiler, and vermagic.

```sh
make KDIR=/path/to/kernel/source O=/path/to/kernel/out ARCH=arm64 LLVM=1
```

If the kernel was built in-tree, omit `O`:

```sh
make KDIR=/path/to/kernel/source ARCH=arm64 LLVM=1
```

Output:

```text
selinux_seqno_fix.ko
```

The module's `obj-m` declaration lives in `Kbuild`, with `Makefile` only
providing the wrapper targets. Do not collapse them back into a single
`Makefile` with a `KERNELRELEASE` guard: in some Android 6.6 kbuild trees the
guard form silently produces an empty `obj-m` for the external pass and
modpost finishes without compiling anything.

## GitHub Actions

The included workflow builds against the OnePlus/OPlus/Realme SM8750 6.6.89
kernel source used by `fastbuild_6.6.89.yml`:

- kernel repo: `cctv18/android_kernel_common_oneplus_sm8750`
- kernel branch: `oneplus/sm8750_v_16.0.0_oneplus_13_6.6.89`
- toolchain: `LLVM-Clang18-r510928`
- default localversion suffix:
  `android15-8-g7e1f3c083cc6-abogki467167594-4k`

Run **Build selinux_seqno_fix.ko** from the Actions tab. The artifact contains
the raw `.ko` and a flashable KSU/Magisk-style zip that loads it from
`service.sh`.

The workflow tries the fast path first: `gki_defconfig`, `modules_prepare`, and
then the external module build. If `out/Module.symvers` is missing, it
automatically builds in-tree `modules` once to generate the kernel symbol
versions required by modpost. Enable `full_kernel_build` only when you want to
force that slow path from the start.

CI uses GitHub cache for downloaded archives, the unpacked kernel/toolchain, and
`kernel_workspace/out`. The first run for a kernel branch/suffix is still
slow because it has to populate `Module.symvers`; later module-only changes
should reuse the cached `out/` tree and finish much faster.

The module must be built for the exact kernel release running on the phone.
If `uname -r` differs, rerun the workflow with a matching `kernel_suffix` and
kernel branch.
The KSU service script writes load diagnostics to `load.log` in the module
directory.
The module also exposes diagnostic counters under
`/sys/module/selinux_seqno_fix/parameters/`.

## Load

```sh
su -c 'insmod /data/local/tmp/selinux_seqno_fix.ko'
su -c 'dmesg | grep selinux_seqno_fix'
```

After loading, confirm the kretprobes are firing and the repair has happened:

```sh
su -c 'cat /sys/module/selinux_seqno_fix/parameters/policyload_hook_hits'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/hits'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/fixups'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_status_sequence'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_status_policyload'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_avc_policy_seqno'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_avd_seqno'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_repair_target'
```

Disable without unloading:

```sh
su -c 'echo 0 > /sys/module/selinux_seqno_fix/parameters/enabled'
```

Unload:

```sh
su -c 'rmmod selinux_seqno_fix'
```

## Notes

- Requires `CONFIG_KPROBES` and `CONFIG_KRETPROBES`.
- Resolves `selinux_kernel_status_page()`, `selinux_status_update_policyload()`
  and `avc_policy_seqno()` via temporary kprobes at load time.
- Designed for arm64 Android kernels.
- If the primary `selinux_status_update_policyload` kretprobe cannot be
  registered, the module continues with the `security_compute_av_user`-only
  safety-net path. If `selinux_kernel_status_page()` cannot be resolved at
  all, the module refuses to load rather than guessing structure offsets.
