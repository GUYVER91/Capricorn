/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#include <linux/lglock.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/task_work.h>
#include <linux/ima.h>

#include <linux/atomic.h>

#include "internal.h"

/* sysctl tunables... */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

/* SLAB cache for file structures */
static struct kmem_cache *filp_cachep __read_mostly;

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

#ifdef CONFIG_FILE_TABLE_DEBUG
#include <linux/hashtable.h>
#include <mount.h>
static DEFINE_MUTEX(global_files_lock);
static DEFINE_HASHTABLE(global_files_hashtable, 10);

struct global_filetable_lookup_key {
	struct work_struct work;
	uintptr_t value;
};

static void global_filetable_print_warning_once(void)
{
	pr_err_once("\n**********************************************************\n");
	pr_err_once("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_err_once("**                                                      **\n");
	pr_err_once("**      VFS FILE TABLE DEBUG is enabled .               **\n");
	pr_err_once("**  Allocating extra memory and slowing access to files **\n");
	pr_err_once("**                                                      **\n");
	pr_err_once("** This means that this is a DEBUG kernel and it is     **\n");
	pr_err_once("** unsafe for production use.                           **\n");
	pr_err_once("**                                                      **\n");
	pr_err_once("** If you see this message and you are not debugging    **\n");
	pr_err_once("** the kernel, report this immediately to your vendor!  **\n");
	pr_err_once("**                                                      **\n");
	pr_err_once("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_err_once("**********************************************************\n");
}

void global_filetable_add(struct file *filp)
{
	struct mount *mnt;

	if (filp->f_path.dentry->d_iname == NULL ||
	    strlen(filp->f_path.dentry->d_iname) == 0)
		return;

	mnt = real_mount(filp->f_path.mnt);

	mutex_lock(&global_files_lock);
	hash_add(global_files_hashtable, &filp->f_hash, (uintptr_t)mnt);
	mutex_unlock(&global_files_lock);
}

void global_filetable_del(struct file *filp)
{
	mutex_lock(&global_files_lock);
	hash_del(&filp->f_hash);
	mutex_unlock(&global_files_lock);
}

static void global_print_file(struct file *filp, char *path_buffer, int *count)
{
	char *pathname;

	pathname = d_path(&filp->f_path, path_buffer, PAGE_SIZE);
	if (IS_ERR(pathname))
		pr_err("VFS: File %d Address : %pa partial filename: %s ref_count=%ld\n",
			++(*count), &filp, filp->f_path.dentry->d_iname,
			atomic_long_read(&filp->f_count));
	else
		pr_err("VFS: File %d Address : %pa full filepath: %s ref_count=%ld\n",
			++(*count), &filp, pathname,
			atomic_long_read(&filp->f_count));
}

static void global_filetable_print(uintptr_t lookup_mnt)
{
	struct hlist_node *tmp;
	struct file *filp;
	struct mount *mnt;
	int index;
	int count = 0;
	char *path_buffer = (char *)__get_free_page(GFP_TEMPORARY);

	mutex_lock(&global_files_lock);
	pr_err("\n**********************************************************\n");
	pr_err("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");

	pr_err("\n");
	pr_err("VFS: The following files hold a reference to the mount\n");
	pr_err("\n");
	hash_for_each_possible_safe(global_files_hashtable, filp, tmp, f_hash,
				    lookup_mnt) {
		mnt = real_mount(filp->f_path.mnt);
		if ((uintptr_t)mnt == lookup_mnt)
			global_print_file(filp, path_buffer, &count);
	}
	pr_err("\n");
	pr_err("VFS: Found total of %d open files\n", count);
	pr_err("\n");

	count = 0;
	pr_err("\n");
	pr_err("VFS: The following files need to cleaned up\n");
	pr_err("\n");
	hash_for_each_safe(global_files_hashtable, index, tmp, filp, f_hash) {
		if (atomic_long_read(&filp->f_count) == 0)
			global_print_file(filp, path_buffer, &count);
	}

	pr_err("\n");
	pr_err("VFS: Found total of %d files awaiting clean-up\n", count);
	pr_err("\n");
	pr_err("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_err("\n**********************************************************\n");

	mutex_unlock(&global_files_lock);
	free_page((unsigned long)path_buffer);
}

static void global_filetable_print_work_fn(struct work_struct *work)
{
	struct global_filetable_lookup_key *key;
	uintptr_t lookup_mnt;

	key = container_of(work, struct global_filetable_lookup_key, work);
	lookup_mnt = key->value;
	kfree(key);
	global_filetable_print(lookup_mnt);
}

void global_filetable_delayed_print(struct mount *mnt)
{
	struct global_filetable_lookup_key *key;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (key == NULL)
		return;
	key->value = (uintptr_t)mnt;
	INIT_WORK(&key->work, global_filetable_print_work_fn);
	schedule_work(&key->work);
}
#endif /* CONFIG_FILE_TABLE_DEBUG */

static void file_free_rcu(struct rcu_head *head)
{
	struct file *f = container_of(head, struct file, f_u.fu_rcuhead);

	put_cred(f->f_cred);
	kmem_cache_free(filp_cachep, f);
}

static inline void file_free(struct file *f)
{
	percpu_counter_dec(&nr_files);
	call_rcu(&f->f_u.fu_rcuhead, file_free_rcu);
}

/*
 * Return the total number of open files in the system
 */
static long get_nr_files(void)
{
	return percpu_counter_read_positive(&nr_files);
}

/*
 * Return the maximum number of open files in the system
 */
unsigned long get_max_files(void)
{
	return files_stat.max_files;
}
EXPORT_SYMBOL_GPL(get_max_files);

/*
 * Handle nr_files sysctl
 */
#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_nr_files(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	files_stat.nr_files = get_nr_files();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#else
int proc_nr_files(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}
#endif

/* Find an unused file structure and return a pointer to it.
 * Returns an error pointer if some error happend e.g. we over file
 * structures limit, run out of memory or operation is not permitted.
 *
 * Be very careful using this.  You are responsible for
 * getting write access to any mount that you might assign
 * to this filp, if it is opened for write.  If this is not
 * done, you will imbalance int the mount's writer count
 * and a warning at __fput() time.
 */
struct file *get_empty_filp(void)
{
	const struct cred *cred = current_cred();
	static long old_max;
	struct file *f;
	int error;

	/*
	 * Privileged users can go above max_files
	 */
	if (get_nr_files() >= files_stat.max_files && !capable(CAP_SYS_ADMIN)) {
		/*
		 * percpu_counters are inaccurate.  Do an expensive check before
		 * we go and fail.
		 */
		if (percpu_counter_sum_positive(&nr_files) >= files_stat.max_files)
			goto over;
	}

	f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
	if (unlikely(!f))
		return ERR_PTR(-ENOMEM);

	percpu_counter_inc(&nr_files);
	f->f_cred = get_cred(cred);
	error = security_file_alloc(f);
	if (unlikely(error)) {
		file_free(f);
		return ERR_PTR(error);
	}

	atomic_long_set(&f->f_count, 1);
	rwlock_init(&f->f_owner.lock);
	spin_lock_init(&f->f_lock);
	mutex_init(&f->f_pos_lock);
	eventpoll_init_file(f);
	/* f->f_version: 0 */
	return f;

over:
	/* Ran out of filps - report that */
	if (get_nr_files() > old_max) {
		pr_info("VFS: file-max limit %lu reached\n", get_max_files());
		old_max = get_nr_files();
	}
	return ERR_PTR(-ENFILE);
}

/**
 * alloc_file - allocate and initialize a 'struct file'
 *
 * @path: the (dentry, vfsmount) pair for the new file
 * @mode: the mode with which the new file will be opened
 * @fop: the 'struct file_operations' for the new file
 */
struct file *alloc_file(struct path *path, fmode_t mode,
		const struct file_operations *fop)
{
	struct file *file;

	file = get_empty_filp();
	if (IS_ERR(file))
		return file;

	file->f_path = *path;
	file->f_inode = path->dentry->d_inode;
	file->f_mapping = path->dentry->d_inode->i_mapping;
	if ((mode & FMODE_READ) &&
	     likely(fop->read || fop->aio_read || fop->read_iter))
		mode |= FMODE_CAN_READ;
	if ((mode & FMODE_WRITE) &&
	     likely(fop->write || fop->aio_write || fop->write_iter))
		mode |= FMODE_CAN_WRITE;
	file->f_mode = mode;
	file->f_op = fop;
	if ((mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_inc(path->dentry->d_inode);
	return file;
}
EXPORT_SYMBOL(alloc_file);

/* the real guts of fput() - releasing the last reference to file
 */
static void __fput(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = file->f_inode;

	might_sleep();

	fsnotify_close(file);
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);
	locks_remove_file(file);

	if (unlikely(file->f_flags & FASYNC)) {
		if (file->f_op->fasync)
			file->f_op->fasync(-1, file, 0);
	}
	ima_file_free(file);
	if (file->f_op->release)
		file->f_op->release(inode, file);
	security_file_free(file);
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL &&
		     !(file->f_mode & FMODE_PATH))) {
		cdev_put(inode->i_cdev);
	}
	fops_put(file->f_op);
	put_pid(file->f_owner.pid);
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(inode);
	if (file->f_mode & FMODE_WRITER) {
		put_write_access(inode);
		__mnt_drop_write(mnt);
	}
	global_filetable_del(file);
	file->f_path.dentry = NULL;
	file->f_path.mnt = NULL;
	file->f_inode = NULL;
	file_free(file);
	dput(dentry);
	mntput(mnt);
}

static LLIST_HEAD(global_fput_list);
static void global_fput(struct work_struct *unused)
{
	struct llist_node *node = llist_del_all(&global_fput_list);
	struct llist_node *next;

	for (; node; node = next) {
		next = llist_next(node);
		__fput(llist_entry(node, struct file, f_u.fu_llist));
	}
}

static void ____fput(struct callback_head *work)
{
	__fput(container_of(work, struct file, f_u.fu_rcuhead));
}

static DECLARE_DELAYED_WORK(global_fput_work, global_fput);

/**
 * fput_global_flush - ensure that all global_fput work is complete
 *
 * If a kernel thread really needs to have the final fput() it has done to
 * complete, call this. One of the main users is the boot - we *do* need to
 * make sure our writes to binaries on initramfs has not left us with opened
 * struct file waiting for __fput() - execve() won't work without that.
 *
 * Please, don't add more callers without very good reasons; in particular,
 * never call that with locks held and never from a thread that might need to
 * do some work on any kind of umount.
 */
void fput_global_flush(void)
{
	flush_delayed_work(&global_fput_work);
}
EXPORT_SYMBOL(fput_global_flush);

/**
 * fput - put a struct file reference
 * @file: file of which to put the reference
 *
 * This function decrements the reference count for the struct file reference,
 * and queues it up for destruction if the count goes to zero. In the case of
 * most tasks we queue it to the task_work infrastructure, which will be run
 * just before the task returns back to userspace. kthreads however never
 * return to userspace, so for those we add them to a global list and schedule
 * a delayed workqueue job to do the final cleanup work.
 *
 * Why not just do it synchronously? __fput can involve taking locks of all
 * sorts, and doing it synchronously means that the callers must take extra care
 * not to deadlock. That can be very difficult to ensure, so by deferring it
 * until just before return to userland or to the workqueue, we sidestep that
 * nastiness. Also, __fput can be quite stack intensive, so doing a final fput
 * has the possibility of blowing up if we don't take steps to ensure that we
 * have enough stack space to make it work.
 */
void fput(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = current;

		if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			if (!task_work_add(task, &file->f_u.fu_rcuhead, true))
				return;
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
		}

		if (llist_add(&file->f_u.fu_llist, &global_fput_list))
			schedule_delayed_work(&global_fput_work, 1);
	}
}

EXPORT_SYMBOL(fput);

/**
 * fput_global - do an fput without using task_work
 * @file: file of which to put the reference
 *
 * When fput is called in the context of a userland process, it'll queue the
 * actual work (__fput()) to be done just before returning to userland. In some
 * cases however, we need to ensure that the __fput runs before that point.
 *
 * There is no safe way to flush work that has been queued via task_work_add
 * however, so to do this we borrow the global_fput infrastructure that
 * kthreads use. The userland process can use fput_global() on one or more
 * struct files and then call fput_global_flush() to ensure that they are
 * completely closed before proceeding.
 *
 * The main user is nfsd, which uses this to ensure that all cached but
 * otherwise unused files are closed to allow a userland request for a lease
 * to proceed.
 *
 * Returns true if the final fput was done, false otherwise. The caller can
 * use this to determine whether to fput_global_flush afterward.
 */
bool fput_global(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		if (llist_add(&file->f_u.fu_llist, &global_fput_list))
			schedule_delayed_work(&global_fput_work, 1);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(fput_global);

/*
 * synchronous analog of fput(); for kernel threads that might be needed
 * in some umount() (and thus can't use fput_global_flush() without
 * risking deadlocks), need to wait for completion of __fput() and know
 * for this specific struct file it won't involve anything that would
 * need them.  Use only if you really need it - at the very least,
 * don't blindly convert fput() by kernel thread to that.
 */
void __fput_sync(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = current;
		BUG_ON(!(task->flags & PF_KTHREAD));
		__fput(file);
	}
}


void put_filp(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_free(file);
	}
}

void __init files_init(unsigned long mempages)
{ 
	unsigned long n;

	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	/*
	 * One file with associated inode and dcache is very roughly 1K.
	 * Per default don't use more than 10% of our memory for files. 
	 */ 

	n = (mempages * (PAGE_SIZE / 1024)) / 10;
	files_stat.max_files = max_t(unsigned long, n, NR_FILE);
	percpu_counter_init(&nr_files, 0, GFP_KERNEL);
	global_filetable_print_warning_once();
} 
