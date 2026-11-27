import glob
import os
import re
import sys

# 1. Reconcile include/linux/sched.h.rej (SUSFS task_struct fields)
if os.path.exists("include/linux/sched.h.rej"):
    rej_txt = open("include/linux/sched.h.rej").read()
    print(">>> Reconciling include/linux/sched.h.rej:")
    print(rej_txt)
    added = [line[1:] for line in rej_txt.splitlines() if line.startswith("+") and not line.startswith("+++")]
    if added and any("SUSFS" in l or "susfs" in l for l in added):
        sched = open("include/linux/sched.h").read()
        block = "\n".join(added) + "\n"
        anchor = "\trandomized_struct_fields_end"
        if anchor not in sched:
            anchor = "\t/* CPU-specific state of this task: */"
        assert anchor in sched, "No anchor in include/linux/sched.h"
        sched = sched.replace(anchor, block + anchor, 1)
        open("include/linux/sched.h", "w").write(sched)
        os.remove("include/linux/sched.h.rej")
        print(">>> Resolved include/linux/sched.h.rej cleanly")

# 2. Reconcile fs/proc/task_mmu.c.rej (5-arg walk_page_range backport) if present
if os.path.exists("fs/proc/task_mmu.c.rej"):
    print(">>> Reconciling fs/proc/task_mmu.c.rej")
    print(open("fs/proc/task_mmu.c.rej").read())
    txt = open("fs/proc/task_mmu.c").read()
    if "#include <linux/susfs_def.h>" not in txt:
        txt = "#include <linux/susfs_def.h>\n" + txt
    if "AS_FLAGS_SUS_MAP" in txt:
        sus_cond = "unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags)) && susfs_is_current_proc_umounted()"
    elif "BIT_SUS_MAP" in txt:
        sus_cond = "unlikely(inode->i_mapping->flags & BIT_SUS_MAP) && susfs_is_current_proc_umounted()"
    else:
        sus_cond = "0"
    print(">>> Detected SUS_MAP condition in task_mmu.c:", sus_cond)
    target = "ret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);"
    if target in txt:
        replacement = (
            "#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n"
            "\t\t\t{\n"
            "\t\t\t\tstruct vm_area_struct *vma = find_vma(mm, start_vaddr);\n"
            "\t\t\t\tif (vma && vma->vm_file) {\n"
            "\t\t\t\t\tstruct inode *inode = file_inode(vma->vm_file);\n"
            f"\t\t\t\t\tif ({sus_cond}) {{\n"
            "\t\t\t\t\t\tmemset(pm.buffer, 0, sizeof(pagemap_entry_t) * pm.len);\n"
            "\t\t\t\t\t\tpm.pos = pm.len;\n"
            "\t\t\t\t\t\tret = 0;\n"
            "\t\t\t\t\t} else {\n"
            "\t\t\t\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "\t\t\t\t\t}\n"
            "\t\t\t\t} else {\n"
            "\t\t\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "\t\t\t\t}\n"
            "\t\t\t}\n"
            "#else\n"
            "\t\t\tret = walk_page_range(mm, start_vaddr, end, &pagemap_ops, &pm);\n"
            "#endif"
        )
        txt = txt.replace(target, replacement, 1)
        open("fs/proc/task_mmu.c", "w").write(txt)
        os.remove("fs/proc/task_mmu.c.rej")
        print(">>> Resolved fs/proc/task_mmu.c.rej cleanly")

# 3. Abort if any unresolved .rej remains
rejs = glob.glob("**/*.rej", recursive=True)
if rejs:
    print("ERROR: Unresolved .rej files:", rejs, file=sys.stderr)
    for r in rejs:
        print(f"=== {r} ===")
        print(open(r).read())
    sys.exit(1)

# 4. Inspect KSUN exported hook signatures
su_files = [
    p for p in [
        "drivers/kernelsu/sucompat.c",
        "drivers/kernelsu/sucompat.h",
        "drivers/kernelsu/setuid_hook.c",
        "drivers/kernelsu/supercalls.c",
        "drivers/kernelsu/ksud.c",
        "drivers/kernelsu/ksu.c",
    ]
    if os.path.exists(p)
]
su_blob = "\n".join(open(p, errors="ignore").read() for p in su_files)
print("=== Detected KSUN hook signatures ===")
for fn in [
    "ksu_handle_faccessat",
    "ksu_handle_stat",
    "ksu_handle_execve_sucompat",
    "ksu_handle_execveat_sucompat",
    "ksu_handle_execveat",
    "ksu_handle_vfs_read",
    "ksu_handle_sys_reboot",
    "ksu_handle_setresuid",
    "ksu_handle_devpts",
]:
    matches = re.findall(r"^[^\n]*\b" + fn + r"\s*\([^\)]*\)", su_blob, re.M)
    print(f"  {fn}: {matches[:2]}")

# 5. Wire ksu_handle_sys_reboot in kernel/reboot.c
reb = open("kernel/reboot.c").read()
if "ksu_handle_sys_reboot" not in reb:
    anchor = "SYSCALL_DEFINE4(reboot,"
    cap_anchor = "\tif (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))"
    assert anchor in reb and cap_anchor in reb, "kernel/reboot.c anchors missing"
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
        "#endif\n\n"
    )
    reb = reb.replace(anchor, decl + anchor, 1)
    hook = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
        "#endif\n"
    )
    reb = reb.replace(cap_anchor, hook + cap_anchor, 1)
    open("kernel/reboot.c", "w").write(reb)
    print(">>> Wired ksu_handle_sys_reboot in kernel/reboot.c")

# 6. Wire ksu_handle_setresuid in kernel/sys.c
sysc = open("kernel/sys.c").read()
if "ksu_handle_setresuid" not in sysc:
    fn_anchor = "long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)"
    sec_anchor = "\tretval = security_task_fix_setuid(new, old, LSM_SETID_RES);"
    assert fn_anchor in sysc and sec_anchor in sysc, "kernel/sys.c anchors missing"
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n"
        "#endif\n\n"
    )
    sysc = sysc.replace(fn_anchor, decl + fn_anchor, 1)
    hook = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_setresuid(ruid, euid, suid);\n"
        "#endif\n"
    )
    sysc = sysc.replace(sec_anchor, hook + sec_anchor, 1)
    open("kernel/sys.c", "w").write(sysc)
    print(">>> Wired ksu_handle_setresuid in kernel/sys.c")

# 7. Remove obsolete ksu_handle_devpts if KSUN no longer defines it
if "ksu_handle_devpts" not in su_blob and os.path.exists("fs/devpts/inode.c"):
    devpts = open("fs/devpts/inode.c").read()
    if "ksu_handle_devpts" in devpts:
        devpts = re.sub(r"#ifdef CONFIG_KSU\s*extern int ksu_handle_devpts\([^\)]*\);\s*#endif", "", devpts, flags=re.S)
        devpts = re.sub(r"#ifdef CONFIG_KSU\s*ksu_handle_devpts\([^\)]*\);\s*#endif", "", devpts, flags=re.S)
        open("fs/devpts/inode.c", "w").write(devpts)
        print(">>> Removed obsolete ksu_handle_devpts from fs/devpts/inode.c")

# 8. Relax init/Kconfig KALLSYMS_ALL dependency
ik = open("init/Kconfig").read()
ik2 = re.sub(
    r'(config KALLSYMS_ALL\n\s+bool "Include all symbols in kallsyms"\n\s+)depends on DEBUG_KERNEL && KALLSYMS',
    r"\1depends on KALLSYMS",
    ik,
)
if ik2 != ik:
    open("init/Kconfig", "w").write(ik2)
    print(">>> Relaxed init/Kconfig KALLSYMS_ALL dependency")

# 9. Update arch/arm64/configs/vendor/pipa_defconfig
defcfg_path = "arch/arm64/configs/vendor/pipa_defconfig"
defcfg = open(defcfg_path).read()
required_opts = [
    "CONFIG_KSU=y",
    "CONFIG_KSU_SUSFS=y",
    "CONFIG_KALLSYMS=y",
    "CONFIG_KALLSYMS_ALL=y",
]
kcfg_blob = open("drivers/kernelsu/Kconfig", errors="ignore").read()
if "config KSU_MANUAL_HOOK" in kcfg_blob:
    required_opts.append("CONFIG_KSU_MANUAL_HOOK=y")
if "config KSU_WITH_KPROBES" in kcfg_blob:
    required_opts.append("# CONFIG_KSU_WITH_KPROBES is not set")
for opt in required_opts:
    key = opt.split("=")[0].replace("# ", "").replace(" is not set", "")
    if re.search(rf"^(# )?{re.escape(key)}[= ]", defcfg, re.M):
        defcfg = re.sub(rf"^(# )?{re.escape(key)}[= ].*$", opt, defcfg, flags=re.M)
    else:
        defcfg += f"\n{opt}\n"
open(defcfg_path, "w").write(defcfg)
print(">>> Updated vendor/pipa_defconfig with:", required_opts)

# 10. Reconcile SUSFS v2.1.0 <-> KSUN v3.1.0-legacy-susfs API bridge
susfs_def_path = "include/linux/susfs_def.h"
susfs_def = open(susfs_def_path).read()
susfs_h = open("include/linux/susfs.h").read()
print("=== include/linux/susfs_def.h (tail) ===")
print("\n".join(susfs_def.splitlines()[-40:]))

sh_path = "drivers/kernelsu/setuid_hook.c"
if os.path.exists(sh_path):
    sh = open(sh_path).read()
    if "#include <linux/susfs_def.h>" not in sh:
        sh = "#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n" + sh
        open(sh_path, "w").write(sh)
        print(">>> Added #include <linux/susfs_def.h> to drivers/kernelsu/setuid_hook.c")

if "susfs_set_current_proc_umounted(" not in susfs_def and "susfs_set_current_proc_umounted(" not in susfs_h:
    if "susfs_set_current_proc_umounted_app(" in susfs_def:
        body = "susfs_set_current_proc_umounted_app();"
    elif "TIF_PROC_UMOUNTED" in susfs_def:
        body = "set_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);"
    else:
        m = re.search(r"current->susfs_task_state\s*&\s*([A-Za-z0-9_]+)", susfs_def)
        if m:
            body = f"current->susfs_task_state |= {m.group(1)};"
        else:
            body = "(void)0;"
    wrapper = f"\nstatic inline void susfs_set_current_proc_umounted(void) {{ {body} }}\n"
    lines = susfs_def.splitlines(keepends=True)
    endif_indices = [i for i, l in enumerate(lines) if l.lstrip().startswith("#endif")]
    if endif_indices:
        lines.insert(endif_indices[-1], wrapper)
    else:
        lines.append(wrapper)
    open(susfs_def_path, "w").write("".join(lines))
    assert "susfs_set_current_proc_umounted(" in open(susfs_def_path).read(), "Wrapper insertion failed"
    print(">>> Injected compat wrapper into include/linux/susfs_def.h:", wrapper.strip())
# 11. Stub removed SUSFS v2.0.0 helpers expected by KSUN ba4422f supercalls.c
susfs_h_path = "include/linux/susfs.h"
susfs_h_txt = open(susfs_h_path).read()
compat_stubs = []
if "susfs_set_i_state_on_external_dir(" not in susfs_h_txt:
    compat_stubs.append("static inline void susfs_set_i_state_on_external_dir(void __user **user_info) { (void)user_info; }")
if "susfs_add_try_umount(" not in susfs_h_txt:
    compat_stubs.append("static inline void susfs_add_try_umount(void __user **user_info) { (void)user_info; }")
if "susfs_try_umount(" not in susfs_h_txt:
    compat_stubs.append("static inline void susfs_try_umount(uid_t uid) { (void)uid; }")
if compat_stubs:
    h_lines = susfs_h_txt.splitlines(keepends=True)
    h_endifs = [i for i, l in enumerate(h_lines) if l.lstrip().startswith("#endif")]
    stub_block = "\n/* KSUN v3.1.0-legacy-susfs <-> SUSFS v2.4.0 compat stubs */\n" + "\n".join(compat_stubs) + "\n"
    if h_endifs:
        h_lines.insert(h_endifs[-1], stub_block)
    else:
        h_lines.append(stub_block)
    open(susfs_h_path, "w").write("".join(h_lines))
    print(">>> Injected SUSFS compat stubs into include/linux/susfs.h:", compat_stubs)
