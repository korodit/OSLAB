/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

#define MSG_LEN 256

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len, num_in, num_out;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	int host_fd = -1;
	
	struct virtqueue *vq;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	
	debug("Entering");

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	vq = crdev->vq;
	
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	num_out = 0;
	num_in = 0;
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, &host_fd, sizeof(host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg , GFP_ATOMIC);
	
	/**
	 * Wait for the host to process our data.
	 **/
	virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		{ ; } /* do nothing */

	crof->host_fd = host_fd;


	/* If host failed to open() return -ENODEV. */
	// if (len == 0)
	// 	ret = -ENODEV;
	

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	int host_fd = -1;
	
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	int num_out = 0;
	int num_in = 0;
	
	debug("Entering");
	
	host_fd = crof->host_fd;

	/**
	 * Send data to the host.
	 **/
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, &host_fd, sizeof(host_fd));
	sgs[num_out++] = &host_fd_sg;
	
	virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg , GFP_ATOMIC);
	

	/**
	 * Wait for the host to process our data.
	 **/
	virtqueue_kick(crdev->vq);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, host_fd_sg, cmd_sg, *sgs[8], host_return_val_sg;
	struct session_op sess;
	int host_fd = -1, host_return_val = 0;
	unsigned char output_msg[MSG_LEN], input_msg[MSG_LEN];
	unsigned int num_out, num_in,
	             syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL,
	             len;
	
	
	struct scatterlist session_id_sg;
	uint32_t ses_id;
	

	debug("Entering");

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	 
	host_fd = crof->host_fd;
	 
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sg_init_one(&host_fd_sg, &host_fd, sizeof(host_fd));
	sg_init_one(&cmd_sg, &cmd, sizeof(cmd));
	
	sgs[num_out++] = &syscall_type_sg;
	sgs[num_out++] = &host_fd_sg;
	sgs[num_out++] = &cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		struct scatterlist session_key_sg, session_op_sg;
		struct crypt_op *cryptop;
		unsigned char *src, *dst, *iv;
		struct scatterlist cryptop_sg, src_sg, dst_sg, iv_sg;
		unsigned long _cpy;
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		debug("ARG.CIPHER\t:\t%d", ((struct session_op *) arg)->cipher);
		debug("ARG.KEYLEN\t:\t%d", ((struct session_op *) arg)->keylen);
		debug("ARG.KEY\t:\t%s", ((struct session_op *) arg)->key);
		debug("SESS.CIPHER\t:\t%d", sess.cipher);
		debug("SESS.KEYLEN\t:\t%d", sess.keylen);
		debug("SESS.KEY\t:\t%s", sess.key);
		
		// sess = *((struct session_op *) arg);
		sess.key = kzalloc(sizeof(*(sess.key)) * 32, GFP_KERNEL);
		
		_cpy = copy_from_user(&sess, ((struct session_op *) arg), sizeof(struct session_op));
		_cpy = copy_from_user(sess.key, ((struct session_op *) arg)->key, 32);
		
		debug("ARG.CIPHER\t:\t%d", ((struct session_op *) arg)->cipher);
		debug("ARG.KEYLEN\t:\t%d", ((struct session_op *) arg)->keylen);
		debug("ARG.KEY\t:\t%s", ((struct session_op *) arg)->key);
		debug("SESS.CIPHER\t:\t%d", sess.cipher);
		debug("SESS.KEYLEN\t:\t%d", sess.keylen);
		debug("SESS.KEY\t:\t%s", sess.key);
		
		sg_init_one(&session_key_sg, sess.key, 32);
		sg_init_one(&session_op_sg, &sess, sizeof(sess));
		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out++] = &session_key_sg;
		sgs[num_out + num_in++] = &session_op_sg;
		sgs[num_out + num_in++] = &host_return_val_sg;
		
		err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
		virtqueue_kick(crdev->vq);
		while (virtqueue_get_buf(crdev->vq, &len) == NULL)
			{ ; }/* do nothing */
		
		
		_cpy = copy_to_user(((struct session_op *) arg), &sess, sizeof(struct session_op));
		_cpy = copy_to_user(((struct session_op *) arg)->key, sess.key, 32);
		
		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		
		sess = *((struct session_op *) arg);
		ses_id = sess.ses;
		sg_init_one(&session_id_sg, &ses_id, sizeof(ses_id));
		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out++] = &session_id_sg;
		sgs[num_out + num_in++] = &host_return_val_sg;

		err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
		virtqueue_kick(crdev->vq);
		while (virtqueue_get_buf(crdev->vq, &len) == NULL)
			{ ; }/* do nothing */

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		
		cryptop = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);
		src = kzalloc(sizeof(*src) * MSG_LEN, GFP_KERNEL);
		dst = kzalloc(sizeof(*dst) * MSG_LEN, GFP_KERNEL);
		iv = kzalloc(sizeof(*iv) * MSG_LEN, GFP_KERNEL);
		
		memcpy(cryptop, (struct crypt_op *) arg, sizeof(struct crypt_op));
		memcpy(src, cryptop->src, sizeof(*src) * MSG_LEN);
		memcpy(iv, cryptop->iv, sizeof(*iv) * MSG_LEN);
		
		sg_init_one(&cryptop_sg, cryptop, sizeof(cryptop));
		sg_init_one(&src_sg, src, sizeof(src));
		sg_init_one(&dst_sg, dst, sizeof(dst));
		sg_init_one(&iv_sg, iv, 32);
		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out++] = &cryptop_sg;
		sgs[num_out++] = &src_sg;
		sgs[num_out++] = &iv_sg;
		sgs[num_out + num_in++] = &dst_sg;
		sgs[num_out + num_in++] = &host_return_val_sg;

		err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
		virtqueue_kick(crdev->vq);
		while (virtqueue_get_buf(crdev->vq, &len) == NULL)
			{ ; }/* do nothing */

		memcpy(cryptop->dst, dst, sizeof(*dst) * MSG_LEN);
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	
	// err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	// virtqueue_kick(crdev->vq);
	// while (virtqueue_get_buf(crdev->vq, &len) == NULL)
	// 	{ ; }/* do nothing */
		
	// switch (cmd) {
	// 	case CIOCGSESSION:
	// 		sess = *((struct session_op *) arg);
	// 		memcpy(((struct session_op *) arg)->key, sess.key, 16);
			
	// 	case CIOCCRYPT:
	// 		memcpy(cryptop->dst, dst, sizeof(*dst) * MSG_LEN);
	// 		break;
	// }
	// debug("We said: '%s'", output_msg);
	// debug("Host answered: '%s'", input_msg);

	debug("Leaving");
	ret = host_return_val;
	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
