# selinux_seqno_fix

Tiny Android kernel module for the SELinux `/sys/fs/selinux/access` seqno split.

The module only hooks `security_compute_av_user()` and rewrites the returned
`av_decision.seqno` to the live SELinux status `policyload` value. It does not
change `allowed`, `auditallow`, `auditdeny`, or `flags`.

## Why

Some SELinux hide implementations compute userspace access queries against a
backup policy. If that whole `av_decision` is returned, `/sys/fs/selinux/access`
can expose the backup policy `seqno`, while `/sys/fs/selinux/status` exposes the
live policy `policyload`. Detectors can compare the two and report a seqno split.

This module makes the metadata consistent by keeping the live policy seqno.

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
  `android15-8-g29d86c5fc9dd-abogki428889875-4k`

Run **Build selinux_seqno_fix.ko** from the Actions tab. The artifact contains
the raw `.ko` and a flashable KSU/Magisk-style zip that loads it from
`service.sh`.

The workflow tries the fast path first: `gki_defconfig`, `modules_prepare`, and
then the external module build. If `out/Module.symvers` is missing, it
automatically builds `Image` once to generate the kernel symbol versions required
by modpost. Enable `full_kernel_build` only when you want to force that slow path
from the start.

The module must be built for the exact kernel release running on the phone.
If `uname -r` differs, rerun the workflow with a matching `kernel_suffix` and
kernel branch.

## Load

```sh
su -c 'insmod /data/local/tmp/selinux_seqno_fix.ko'
su -c 'dmesg | grep selinux_seqno_fix'
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
  then only reads the mapped status page from the return handler.
- Designed for arm64 Android kernels.
- If symbol resolution fails, the module refuses to load rather than guessing
  structure offsets.
