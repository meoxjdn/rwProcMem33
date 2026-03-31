#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h> // ⭐ 解决 6.6 内核 proc_ops 报错
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/atomic.h>

// 引入你项目原有的头文件
#include "ver_control.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"
#include "proc_pid.h"
#include "cvector.h"
#include "hide_procfs_dir.h"

// --- 1. 通讯协议与偏移量定义 ---
#pragma pack(push,1)
struct ioctl_request {
    char     cmd;        /* 1 字节命令 */
    uint64_t param1;     /* 参数1 */
    uint64_t param2;     /* 参数2 */
    uint64_t param3;     /* 参数3 */
    uint64_t buf_size;    /* 紧随其后的动态数据长度 */
};
#pragma pack(pop)

// 游戏逻辑专属硬编码偏移
#define OFF_SKIP     0x2639fd8
#define OFF_SKIP_JMP 0x53709a0
#define OFF_MAXHP    0x33b2ffc

// 指令 ID 定义 (完全对接你的用户态测试脚本)
#define CMD_OPEN_PROCESS         0
#define CMD_CLOSE_PROCESS        1
#define CMD_GET_NUM_BRPS         2
#define CMD_GET_NUM_WRPS         3
#define CMD_INST_PROCESS_HWBP    4
#define CMD_SET_GAME_BASE        22

// --- 2. 全局管理变量 ---
static atomic64_t g_game_base = ATOMIC64_INIT(0);
static atomic64_t g_hook_pc;
static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;

static dev_t g_devno;
static struct cdev g_cdev;
static struct class *g_class = NULL;

struct hwBreakpointProcDev {
    struct proc_dir_entry *proc_parent;
    struct proc_dir_entry *proc_entry;
    bool is_hidden_module;
};
static struct hwBreakpointProcDev *g_hwBreakpointProc_devp = NULL;

// --- 3. 辅助功能函数 ---

// 记录详细的断点命中寄存器快照
static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs) {
    struct HWBP_HIT_ITEM hit_item = {0};
    if (!info || !regs) return;
    hit_item.task_id = info->task_id;
    hit_item.hit_addr = regs->pc;
    hit_item.hit_time = ktime_get_real_seconds();
    memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
    hit_item.regs_info.sp = regs->sp;
    hit_item.regs_info.pc = regs->pc;
    hit_item.regs_info.pstate = regs->pstate;
    
    if (info->hit_item_arr && cvector_length(info->hit_item_arr) < MIN_LEN) {
        cvector_pushback(info->hit_item_arr, &hit_item);
    }
}

// --- 4. ⭐ 核心劫持 Handler (复刻 Ptrace 并修复 PSTATE) ---
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    citerator iter;
    uint64_t base = atomic64_read(&g_game_base);
    uint64_t bp_addr = bp->attr.bp_addr;

    // 核心拦截判断：只要匹配到了游戏的基址，就执行暴力篡改
    if (base != 0) {
        // A. 秒杀逻辑：将 X0 改为 1，并强行跳转 PC 到 LR 返回
        if (bp_addr == base + OFF_MAXHP) {
            regs->regs[0] = 1;
            regs->pc = regs->regs[30];
            
            // ❗ 终极修复：抹除 PSTATE 里的单步调试标志 (bit 21)
            // 在内核 perf_event 框架下，如果你改了 PC 却不抹除这个位，
            // 内核恢复执行后会因找不到原本的单步断点而导致 CPU 进入无限异常循环(卡死)。
            regs->pstate &= ~(1ULL << 21); 
            return;
        }

        // B. 秒过逻辑：强行跳转 PC 到目标汇编段地址
        if (bp_addr == base + OFF_SKIP) {
            regs->pc = base + OFF_SKIP_JMP;
            regs->pstate &= ~(1ULL << 21);
            return;
        }
    }

    // 常规逻辑：处理常规的断点命中记录与寄存器解锁
    mutex_lock(&g_hwbp_handle_info_mutex);
    if (g_hwbp_handle_info_arr) {
        for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
            struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
            if (info->sample_hbp == bp) {
                info->hit_total_count++;
                record_hit_details(info, regs);
                // 暂时解除断点锁定，允许执行下一条指令 (防死循环)
                toggle_bp_registers_directly(&info->original_attr, info->is_32bit_task, 0);
                break;
            }
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
}

// --- 5. 业务指令深度实现 ---

static ssize_t OnCmdOpenProcess(struct ioctl_request *hdr, char __user* buf) {
    struct pid *proc_pid_struct = get_proc_pid_struct(hdr->param1);
    if (!proc_pid_struct) return -EINVAL;
    if (x_copy_to_user(buf, &proc_pid_struct, sizeof(uint64_t))) return -EFAULT;
    return 0;
}

static ssize_t OnCmdInstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
    struct pid *pid_struct = (struct pid *)hdr->param1;
    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) return -EINVAL;

    struct HWBP_HANDLE_INFO info = { 0 };
    info.task_id = pid_nr(pid_struct);
    info.is_32bit_task = is_compat_thread(task_thread_info(task));
    
    ptrace_breakpoint_init(&info.original_attr);
    info.original_attr.bp_addr = hdr->param2;
    info.original_attr.bp_len = hdr->param3 & 0xFF;
    info.original_attr.bp_type = (hdr->param3 >> 8) & 0xFF;
    info.original_attr.disabled = 0;

    // 向内核正式注册硬件断点对象
    info.sample_hbp = x_register_user_hw_breakpoint(&info.original_attr, hwbp_handler, NULL, task);
    if (IS_ERR(info.sample_hbp)) {
        return PTR_ERR(info.sample_hbp);
    }

    info.hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
    
    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector_pushback(g_hwbp_handle_info_arr, &info);
    mutex_unlock(&g_hwbp_handle_info_mutex);

    if (x_copy_to_user(buf, &info.sample_hbp, sizeof(uint64_t))) return -EFAULT;
    return 0;
}

static ssize_t OnCmdGetHwbpHitDetail(struct ioctl_request *hdr, char __user* buf) {
    struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
    size_t size = hdr->buf_size;
    ssize_t count = 0;
    size_t copy_pos = (size_t)buf;
    size_t end_pos = copy_pos + size;
    citerator iter, child;

    mutex_lock(&g_hwbp_handle_info_mutex);
    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->sample_hbp == sample_hbp && info->hit_item_arr) {
            for (child = cvector_begin(info->hit_item_arr); child != cvector_end(info->hit_item_arr); child = cvector_next(info->hit_item_arr, child)) {
                if (copy_pos + sizeof(struct HWBP_HIT_ITEM) > end_pos) break;
                if (x_copy_to_user((void*)copy_pos, child, sizeof(struct HWBP_HIT_ITEM))) break;
                copy_pos += sizeof(struct HWBP_HIT_ITEM);
                count++;
            }
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return count;
}

// --- 6. 通讯协议解析分发层 ---

static inline ssize_t DispatchCommand(struct ioctl_request *hdr, char __user* buf) {
    switch (hdr->cmd) {
        case CMD_OPEN_PROCESS:      return OnCmdOpenProcess(hdr, buf);
        case CMD_CLOSE_PROCESS:     release_proc_pid_struct((struct pid *)hdr->param1); return 0;
        case CMD_INST_PROCESS_HWBP: return OnCmdInstProcessHwbp(hdr, buf);
        case 9:                     // GET_HWBP_HIT_DETAIL
                                    return OnCmdGetHwbpHitDetail(hdr, buf);
        case CMD_SET_GAME_BASE:     atomic64_set(&g_game_base, hdr->param1); return 0;
        default: return -EINVAL;
    }
}

static ssize_t hwBreakpointProc_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos) {
    struct ioctl_request hdr;
    if (size < sizeof(hdr)) return -EINVAL;
    if (x_copy_from_user(&hdr, buf, sizeof(hdr))) return -EFAULT;
    // 调用分发器并传递剩余缓冲区
    return DispatchCommand(&hdr, buf + sizeof(hdr));
}

// --- 7. 清理与释放逻辑 ---

static void clean_hwbp(void) {
    citerator iter;
    mutex_lock(&g_hwbp_handle_info_mutex);
    if (g_hwbp_handle_info_arr) {
        for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
            struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
            if (info->sample_hbp) {
                x_unregister_hw_breakpoint(info->sample_hbp);
                info->sample_hbp = NULL;
            }
            if (info->hit_item_arr) {
                cvector_destroy(info->hit_item_arr);
                info->hit_item_arr = NULL;
            }
        }
        cvector_destroy(g_hwbp_handle_info_arr);
        g_hwbp_handle_info_arr = NULL;
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
}

static int hwBreakpointProc_release(struct inode *inode, struct file *filp) {
    clean_hwbp();
    // 释放后立即重建容器，保证下次打开依然可用
    mutex_lock(&g_hwbp_handle_info_mutex);
    g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return 0;
}

// --- 8. 驱动初始化与 6.6 内核适配 ---

// ⭐ 核心：适配 5.6+ 内核的 proc_ops 结构体
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops hwBreakpointProc_proc_ops = {
    .proc_read    = hwBreakpointProc_read,
    .proc_release = hwBreakpointProc_release,
};
#endif

// 核心：适配 /dev 字符设备
static const struct file_operations dev_fops = {
    .owner   = THIS_MODULE,
    .read    = hwBreakpointProc_read,
    .release = hwBreakpointProc_release,
};

static int hwBreakpointProc_dev_init(void) {
    int result;

#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
    if(!init_kallsyms_lookup()) {
        printk(KERN_EMERG "init_kallsyms_lookup failed\n");
        return -EBADF;
    }
#endif

    g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
    mutex_init(&g_hwbp_handle_info_mutex);

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    start_anti_ptrace_detection(&g_hwbp_handle_info_mutex, &g_hwbp_handle_info_arr);
#endif

    // A. 自动生成 /dev/hwBreakpointProcMod 节点
    result = alloc_chrdev_region(&g_devno, 0, 1, "hwBreakpointProcMod");
    if (result < 0) return result;

    cdev_init(&g_cdev, &dev_fops);
    g_cdev.owner = THIS_MODULE;
    if (cdev_add(&g_cdev, g_devno, 1) < 0) {
        unregister_chrdev_region(g_devno, 1);
        return -1;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    g_class = class_create("hwBreakpointProcMod");
#else
    g_class = class_create(THIS_MODULE, "hwBreakpointProcMod");
#endif
    if (IS_ERR(g_class)) {
        cdev_del(&g_cdev);
        unregister_chrdev_region(g_devno, 1);
        return -1;
    }
    device_create(g_class, NULL, g_devno, NULL, "hwBreakpointProcMod");

    // B. 根据配置创建 /proc 隐藏节点
#ifdef CONFIG_USE_PROC_FILE_NODE
    g_hwBreakpointProc_devp = kzalloc(sizeof(struct hwBreakpointProcDev), GFP_KERNEL);
    g_hwBreakpointProc_devp->proc_parent = proc_mkdir(CONFIG_PROC_NODE_AUTH_KEY, NULL);
    if (g_hwBreakpointProc_devp->proc_parent) {
        proc_create(CONFIG_PROC_NODE_AUTH_KEY, 0666, g_hwBreakpointProc_devp->proc_parent, &hwBreakpointProc_proc_ops);
        start_hide_procfs_dir(CONFIG_PROC_NODE_AUTH_KEY);
    }
#endif

    printk(KERN_EMERG "hwBreakpointProc Full Driver (6.6 GKI) Loaded.\n");
    return 0;
}

static void hwBreakpointProc_dev_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    stop_anti_ptrace_detection();
#endif

    clean_hwbp();
    mutex_destroy(&g_hwbp_handle_info_mutex);

    // 清理 /dev 资源
    if (g_class) {
        device_destroy(g_class, g_devno);
        class_destroy(g_class);
    }
    cdev_del(&g_cdev);
    unregister_chrdev_region(g_devno, 1);

    // 清理 /proc 资源
#ifdef CONFIG_USE_PROC_FILE_NODE
    if (g_hwBreakpointProc_devp) {
        if (g_hwBreakpointProc_devp->proc_parent) {
            remove_proc_subtree(CONFIG_PROC_NODE_AUTH_KEY, NULL);
        }
        stop_hide_procfs_dir();
        kfree(g_hwBreakpointProc_devp);
    }
#endif
    printk(KERN_EMERG "hwBreakpointProc Full Driver Unloaded.\n");
}

int __init init_module(void) { return hwBreakpointProc_dev_init(); }
void __exit cleanup_module(void) { hwBreakpointProc_dev_exit(); }

// CFI 检查桩函数，防止高版本内核签名冲突
#ifndef CONFIG_MODULE_GUIDE_ENTRY
unsigned char* __check_(unsigned char* result, void *ptr, void *diag) { return result; }
unsigned char * __check_fail_(unsigned char *result) { return result; }
#endif

unsigned long __stack_chk_guard;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
MODULE_DESCRIPTION("Hardware Breakpoint God-Mode Processor for 6.6 Kernel");
