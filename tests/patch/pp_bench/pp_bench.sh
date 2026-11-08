#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
NIPA patch-level check that builds and runs pp-bench (bench_page_pool.ko) in
virtme-ng / virtme-run before (HEAD~) and after (HEAD) a patch when page_pool,
netmem, ptr_ring, or pp-bench files are modified, and warns (exit 250) if
benchmark cycle counts regressed.
"""

import hashlib
import os
import pty
import re
import select
import shutil
import statistics
import subprocess
import sys
import tempfile

RELEVANT_RE = re.compile(
    r"^(net/core/page_pool\.c|net/core/netmem_priv\.h|"
    r"include/net/page_pool/|include/net/netmem\.h|"
    r"include/linux/ptr_ring\.h|"
    r"tools/testing/selftests/net/bench/page_pool/)"
)

KERNEL_RE = re.compile(
    r"^(net/core/page_pool\.c|net/core/netmem_priv\.h|"
    r"include/net/page_pool/|include/net/netmem\.h|"
    r"include/linux/ptr_ring\.h)"
)

SLOW_BENCHMARKS = {
    "bh-ring-full-return",
    "bh-slow-page-alloc",
    "bh-dma-slow-map-unmap",
    "cross-cpu-ptr-ring",
    "concurrent-percpu-fast",
    "no-softirq-page_pool03",
}

TYPE_RE = re.compile(
    r"(?:Type:|Sum Type:)(\S+)\s+(?:Per elem:|Average:)\s+(\d+)\s+cycles\(tsc\)"
)


def write_desc(msg: str) -> None:
    desc_fd = os.environ.get("DESC_FD")
    if desc_fd is not None:
        with os.fdopen(int(desc_fd), "w", closefd=False) as f:
            f.write(msg + "\n")
    print(msg, flush=True)


def run_cmd(cmd, cwd=None, check=True):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, check=check, text=True)


def git_out(args, cwd=None) -> str:
    return subprocess.check_output(["git"] + args, cwd=cwd, text=True).strip()


def prepare_fast_guest_tools(tmpdir: str) -> str:
    sys_gt = subprocess.check_output(
        [
            "python3",
            "-c",
            "import virtme.resources; print(virtme.resources.find_guest_tools())",
        ],
        text=True,
    ).strip()
    guest_dir = os.path.join(tmpdir, "guest")
    shutil.copytree(sys_gt, guest_dir)
    init_path = os.path.join(guest_dir, "virtme-init")
    if os.path.exists(init_path):
        with open(init_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Replace udevd coldplug + 300s settle hang with direct virtio-ports symlinks
        content = re.sub(
            r"if command -v systemd-tmpfiles.*?fi\n",
            "# Skip systemd-tmpfiles\n",
            content,
            flags=re.DOTALL,
        )
        udev_replacement = """mkdir -p /dev/virtio-ports
for vp in /sys/class/virtio-ports/*; do
    if [[ -e "$vp/name" ]]; then
        vp_name=$(cat "$vp/name")
        ln -sf "/dev/$(basename "$vp")" "/dev/virtio-ports/$vp_name"
    fi
done
"""
        content = re.sub(
            r"# Try to get udevd to coldplug everything\..*?log \"udevd not found\"\nfi\n",
            udev_replacement,
            content,
            flags=re.DOTALL,
        )
        with open(init_path, "w", encoding="utf-8") as f:
            f.write(content)
    return guest_dir


def ensure_kernel_built(tree_dir: str, build_dir: str) -> str:
    os.makedirs(build_dir, exist_ok=True)
    cache_dir = os.path.join(build_dir, "pp_bench_cache")
    os.makedirs(cache_dir, exist_ok=True)
    bzimage = os.path.join(build_dir, "arch/x86/boot/bzImage")
    symvers = os.path.join(build_dir, "Module.symvers")
    config_file = os.path.join(build_dir, ".config")

    tree_hashes = git_out(
        ["rev-parse", "HEAD:net", "HEAD:include", "HEAD:kernel"],
        cwd=tree_dir,
    )
    kernel_commit = hashlib.sha1(tree_hashes.encode()).hexdigest()
    cached_bz = os.path.join(cache_dir, f"bzImage.{kernel_commit}")
    cached_sym = os.path.join(cache_dir, f"Module.symvers.{kernel_commit}")

    if os.path.exists(cached_bz):
        print(
            f"Reusing cached bzImage for kernel commit {kernel_commit[:12]}",
            flush=True,
        )
        if os.path.exists(cached_sym):
            shutil.copy2(cached_sym, symvers)
        return cached_bz

    ncpu = str(os.cpu_count() or 8)
    if not os.path.exists(config_file):
        run_cmd(
            ["virtme-configkernel", "--defconfig", "--update", f"O={build_dir}"],
            cwd=tree_dir,
        )
        bench_cfg = os.path.join(
            tree_dir, "tools/testing/selftests/net/bench/config"
        )
        if os.path.exists(bench_cfg):
            run_cmd(
                [
                    "./scripts/kconfig/merge_config.sh",
                    "-m",
                    "-O",
                    build_dir,
                    config_file,
                    bench_cfg,
                ],
                cwd=tree_dir,
            )
            run_cmd(["make", f"O={build_dir}", "olddefconfig"], cwd=tree_dir)

    run_cmd(
        ["make", f"-j{ncpu}", f"O={build_dir}", "bzImage", "modules_prepare"],
        cwd=tree_dir,
    )
    shutil.copy2(bzimage, cached_bz)
    if os.path.exists(symvers):
        shutil.copy2(symvers, cached_sym)
    return cached_bz


def build_bench_module(mod_src_dir: str, build_dir: str, out_ko: str) -> bool:
    makefile = os.path.join(mod_src_dir, "Makefile")
    if not os.path.exists(makefile):
        return False
    with open(makefile, "r", encoding="utf-8") as f:
        if "KDIR ?=" not in f.read():
            return False

    ncpu = str(os.cpu_count() or 8)
    res = subprocess.run(
        ["make", f"-j{ncpu}", "-C", build_dir, f"M={mod_src_dir}", "modules"],
        text=True,
    )
    if res.returncode != 0:
        return False
    built_ko = os.path.join(mod_src_dir, "bench_page_pool.ko")
    if not os.path.exists(built_ko):
        return False
    shutil.copy2(built_ko, out_ko)
    return True


def run_virtme_script(guest_tools: str, bzimage: str, script: str) -> str:
    py_cmd = (
        "import sys, virtme.resources, virtme.commands.run; "
        f"virtme.resources.find_guest_tools = lambda: {guest_tools!r}; "
        f"sys.argv = ['virtme-run', '--mods=none', '--kimg', {bzimage!r}, "
        f"'--cpus', '4', '--memory', '4G', '--disable-microvm', '--script-sh', {script!r}, "
        f"'--qemu-opts', '-cpu', 'max']; "
        "sys.exit(virtme.commands.run.main())"
    )
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["python3", "-c", py_cmd],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)

    chunks = []
    while True:
        r, _, _ = select.select([master_fd], [], [], 1.0)
        if r:
            try:
                data = os.read(master_fd, 65536)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))
            except OSError:
                break
        if proc.poll() is not None:
            while True:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if not r:
                    break
                try:
                    data = os.read(master_fd, 65536)
                    if not data:
                        break
                    chunks.append(data.decode("utf-8", errors="replace"))
                except OSError:
                    break
            break
    os.close(master_fd)
    rc = proc.wait()
    out = "".join(chunks)
    if rc != 0:
        print(out, file=sys.stderr, flush=True)
        raise RuntimeError(f"virtme-run exited with {rc}")
    return out


def parse_runs(output: str):
    runs = {}
    for block in output.split("===RUN_START===")[1:]:
        body = block.split("===RUN_END===")[0]
        if "benchmark failure(s)" in body or "ABORT:" in body:
            return None
        for m in TYPE_RE.finditer(body):
            name, cyc = m.group(1), int(m.group(2))
            runs.setdefault(name, []).append(cyc)
    return runs


def run_vng_single(
    guest_tools: str, bzimage: str, ko_path: str, n_runs: int, loops: int
):
    guest_cmd = (
        "set -e; "
        f"for i in $(seq 1 {n_runs}); do "
        "dmesg -C; "
        f"insmod {ko_path} loops={loops} && rmmod bench_page_pool; "
        "echo ===RUN_START===; "
        "dmesg; "
        "echo ===RUN_END===; "
        "done"
    )
    out = run_virtme_script(guest_tools, bzimage, guest_cmd)
    return parse_runs(out)


def merge_runs(dst: dict, src: dict) -> None:
    for k, v in src.items():
        dst.setdefault(k, []).extend(v)


def evaluate_regressions(before_runs: dict, after_runs: dict):
    common = [k for k in after_runs if k in before_runs]
    regressed = []
    hot_before_sum = 0.0
    hot_after_sum = 0.0
    hot_count = 0
    rows = []

    for name in common:
        b_med = statistics.median(before_runs[name])
        a_med = statistics.median(after_runs[name])
        diff = a_med - b_med
        pct = (diff / b_med * 100.0) if b_med > 0 else 0.0
        is_slow = name in SLOW_BENCHMARKS
        if not is_slow:
            hot_before_sum += b_med
            hot_after_sum += a_med
            hot_count += 1
            if pct > 6.0 and diff > 12.0:
                regressed.append((name, b_med, a_med, pct))
        else:
            if pct > 12.0 and diff > 25.0:
                regressed.append((name, b_med, a_med, pct))
        rows.append((name, b_med, a_med, diff, pct, is_slow))

    hot_pct = (
        ((hot_after_sum - hot_before_sum) / hot_before_sum * 100.0)
        if hot_before_sum > 0
        else 0.0
    )
    hot_regressed = hot_count >= 5 and hot_pct > 2.5
    return common, rows, regressed, hot_before_sum, hot_after_sum, hot_pct, hot_regressed


def print_table(rows, hot_before_sum, hot_after_sum, hot_pct, n_runs):
    print(f"\n=== pp-bench Comparison (median of {n_runs} runs) ===")
    print(f"{'Benchmark':<28} {'Before':>10} {'After':>10} {'Delta':>10} {'Delta %':>9}")
    print("-" * 71)
    for name, b_med, a_med, diff, pct, _ in rows:
        print(f"{name:<28} {b_med:>10.1f} {a_med:>10.1f} {diff:>+10.1f} {pct:>+8.2f}%")
    if hot_before_sum > 0:
        print("-" * 71)
        h_diff = hot_after_sum - hot_before_sum
        print(
            f"{'HOT-PATH MEDIAN SUM':<28} {hot_before_sum:>10.1f} "
            f"{hot_after_sum:>10.1f} {h_diff:>+10.1f} {hot_pct:>+8.2f}%"
        )
    print(flush=True)


def has_scaled_slow_loops(mod_dir: str) -> bool:
    c_file = os.path.join(mod_dir, "bench_page_pool_simple.c")
    if not os.path.exists(c_file):
        return False
    with open(c_file, "r", encoding="utf-8") as f:
        return "scale_slow_loops" in f.read()


def main() -> int:
    tree_dir = os.getcwd()
    changed_files = git_out(["diff", "--name-only", "HEAD~"], cwd=tree_dir).splitlines()
    relevant = [f for f in changed_files if RELEVANT_RE.search(f)]
    if not relevant:
        write_desc("No page_pool/netmem/ptr_ring/bench files touched, skip")
        return 0

    kernel_changed = any(KERNEL_RE.search(f) for f in relevant)
    head_commit = git_out(["rev-parse", "HEAD"], cwd=tree_dir)
    build_dir = os.environ.get("PP_BENCH_BUILD_DIR", "/tmp/pp-bench-build")
    loops = int(os.environ.get("PP_BENCH_LOOPS", "500000"))
    init_runs = int(os.environ.get("PP_BENCH_RUNS", "3"))

    pp_rel = "tools/testing/selftests/net/bench/page_pool"
    pp_dir = os.path.join(tree_dir, pp_rel)
    if not os.path.exists(os.path.join(pp_dir, "Makefile")):
        write_desc("pp-bench directory not present, skip")
        return 0

    tmpdir = tempfile.mkdtemp(prefix="nipa_pp_bench.")
    try:
        guest_tools = prepare_fast_guest_tools(tmpdir)
        mod_after_src = os.path.join(tmpdir, "mod_after")
        shutil.copytree(pp_dir, mod_after_src)

        if kernel_changed:
            # Benchmark the same HEAD benchmark suite against HEAD~ and HEAD kernels
            try:
                run_cmd(["git", "checkout", "-q", "HEAD~"], cwd=tree_dir)
                bz_before = ensure_kernel_built(tree_dir, build_dir)
                shutil.copy2(bz_before, os.path.join(tmpdir, "bzImage.before"))
                mod_before_src = os.path.join(tmpdir, "mod_before")
                shutil.copytree(mod_after_src, mod_before_src)
                before_ko = os.path.join(tmpdir, "before.ko")
                if not build_bench_module(mod_before_src, build_dir, before_ko):
                    write_desc("Failed to build pp-bench module on HEAD~")
                    return 1
            finally:
                run_cmd(["git", "checkout", "-q", head_commit], cwd=tree_dir)

            bz_after = ensure_kernel_built(tree_dir, build_dir)
            shutil.copy2(bz_after, os.path.join(tmpdir, "bzImage.after"))
            after_ko = os.path.join(tmpdir, "after.ko")
            if not build_bench_module(mod_after_src, build_dir, after_ko):
                write_desc("Failed to build pp-bench module on HEAD")
                return 1

            run_loops = loops if has_scaled_slow_loops(mod_after_src) else 100000
            before_runs = run_vng_single(
                guest_tools,
                os.path.join(tmpdir, "bzImage.before"),
                before_ko,
                init_runs,
                run_loops,
            )
            after_runs = run_vng_single(
                guest_tools,
                os.path.join(tmpdir, "bzImage.after"),
                after_ko,
                init_runs,
                run_loops,
            )
            if before_runs is None or after_runs is None:
                write_desc("pp-bench reported benchmark failure(s)")
                return 1

            total_runs = init_runs
            common, rows, regressed, hb, ha, hpct, hreg = evaluate_regressions(
                before_runs, after_runs
            )
            if regressed or hreg:
                print(
                    "Initial pass flagged potential regression; running 4 tie-breaker iterations...",
                    flush=True,
                )
                b_extra = run_vng_single(
                    guest_tools,
                    os.path.join(tmpdir, "bzImage.before"),
                    before_ko,
                    4,
                    run_loops,
                )
                a_extra = run_vng_single(
                    guest_tools,
                    os.path.join(tmpdir, "bzImage.after"),
                    after_ko,
                    4,
                    run_loops,
                )
                if b_extra is None or a_extra is None:
                    write_desc("pp-bench reported benchmark failure(s) on re-run")
                    return 1
                merge_runs(before_runs, b_extra)
                merge_runs(after_runs, a_extra)
                total_runs += 4
                common, rows, regressed, hb, ha, hpct, hreg = evaluate_regressions(
                    before_runs, after_runs
                )
        else:
            # Only tools/testing/selftests/net/bench/page_pool/ changed:
            # verify the updated benchmark module builds and passes in vng.
            bzimage = ensure_kernel_built(tree_dir, build_dir)
            after_ko = os.path.join(tmpdir, "after.ko")
            if not build_bench_module(mod_after_src, build_dir, after_ko):
                write_desc("pp-bench out-of-tree KDIR support not present, skip")
                return 0

            loops_after = loops if has_scaled_slow_loops(mod_after_src) else 100000
            after_runs = run_vng_single(
                guest_tools, bzimage, after_ko, 1, loops_after
            )
            if after_runs is None:
                write_desc("pp-bench reported benchmark failure(s)")
                return 1
            write_desc(f"All {len(after_runs)} pp-bench benchmarks built and passed")
            return 0

        if not common:
            write_desc(
                f"Before: {len(before_runs)} benchmarks passed; After: {len(after_runs)} benchmarks passed"
            )
            return 0

        print_table(rows, hb, ha, hpct, total_runs)

        if regressed or hreg:
            parts = [
                f"{n} ({b:.0f}->{a:.0f}, {p:+.1f}%)" for n, b, a, p in regressed
            ]
            if hreg:
                parts.append(f"hot-path sum ({hb:.0f}->{ha:.0f}, {hpct:+.1f}%)")
            write_desc("REGRESSED: " + ", ".join(parts))
            return 250

        if hb > 0:
            write_desc(
                f"Hot-path sum: {hb:.0f} -> {ha:.0f} cycles ({hpct:+.1f}%), "
                f"0 regressions ({len(common)} benchmarks)"
            )
        else:
            write_desc(f"0 regressions across {len(common)} benchmarks")
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
