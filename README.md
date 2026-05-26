# selinux_seqno_fix

Tiny Android kernel module for the SELinux `/sys/fs/selinux/status` and
`/sys/fs/selinux/access` seqno split.

The module hooks `security_compute_av_user()` and aligns the SELinux status
page `policyload` value to the returned `av_decision.seqno`. It does not change
`allowed`, `auditallow`, `auditdeny`, or `flags`.

## Why

KernelSU-style SELinux hiding can call `selinux_status_update_policyload(0)`
after applying policy rules. That leaves `/sys/fs/selinux/status` with a
nonzero sequence but zero `policyload`, while `/sys/fs/selinux/access` still
returns a positive `av_decision.seqno`. Detectors can compare the two and report
a seqno split.

This module makes the metadata consistent by restoring status `policyload` to
the observed access decision seqno.

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

After loading, confirm that the kretprobe is seeing SELinux userspace access
queries:

```sh
su -c 'cat /sys/module/selinux_seqno_fix/parameters/hits'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/fixups'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_status_policyload'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_avc_policy_seqno'
su -c 'cat /sys/module/selinux_seqno_fix/parameters/last_avd_seqno'
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
- Resolves `selinux_kernel_status_page()` with a temporary kprobe at load time,
  then updates the mapped status page from the return handler.
- Resolves `avc_policy_seqno()` when available so the initial status repair can
  use the live AVC seqno before the first `/access` probe returns.
- Designed for arm64 Android kernels.
- If symbol resolution fails, the module refuses to load rather than guessing
  structure offsets.
