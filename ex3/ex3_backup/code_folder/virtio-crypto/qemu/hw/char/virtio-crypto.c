/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
/*
 *	typedef struct VirtQueueElement {
 *	    unsigned int index;
 *	    unsigned int out_num;
 *	    unsigned int in_num;
 *	    hwaddr in_addr[VIRTQUEUE_MAX_SIZE];
 *	    hwaddr out_addr[VIRTQUEUE_MAX_SIZE];
 *	    struct iovec in_sg[VIRTQUEUE_MAX_SIZE];
 *	    struct iovec out_sg[VIRTQUEUE_MAX_SIZE];
 *	} VirtQueueElement;
 *
 *	struct iovec {
 *	    void *iov_base;
 *	    size_t iov_len;
 *	};
 */
	DEBUG_IN();
	
	VirtQueueElement elem;
	unsigned int *syscall_type;
	int cfd;
	int host_return_val;

	DEBUG_IN();

	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	}

	DEBUG("I have got an item from VQ :)");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		
		cfd = open("/dev/crypto", O_RDWR);
		memcpy(elem.in_sg[0].iov_base, &cfd, sizeof(cfd));
		elem.in_sg[0].iov_len = sizeof(cfd);
		/* ?? */
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		
		cfd = *((int *)(elem.out_sg[1].iov_base));
		close(cfd);
		/* ?? */
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		
		int host_fd = *((int *)(elem.out_sg[1].iov_base));
		unsigned int cmd = *((unsigned int *)(elem.out_sg[2].iov_base));
		
		
		switch(cmd) {
		case CIOCGSESSION:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCGSESSION");
			unsigned char *session_key;// = (unsigned char *)elem.out_sg[3].iov_base;
			struct session_op sess;
			
			session_key = malloc (elem.out_sg[3].iov_len);
			printf("%d", elem.out_sg[3].iov_len);
			memcpy(session_key, elem.out_sg[3].iov_base, elem.out_sg[3].iov_len);
			memcpy(&sess, elem.in_sg[0].iov_base, elem.in_sg[0].iov_len);
			char *old_keyaddr = sess.key;
			sess.key = session_key;
			
			host_return_val = ioctl(host_fd, CIOCGSESSION, &sess);
			
			sess.key = old_keyaddr;
			memcpy(elem.in_sg[0].iov_base, &sess, sizeof(sess));
			elem.in_sg[0].iov_len = sizeof(sess);
			memcpy(elem.in_sg[1].iov_base, &host_return_val, sizeof(host_return_val));
			elem.in_sg[1].iov_len = sizeof(host_return_val);
			
			break;
			
		case CIOCFSESSION:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCFSESSION");
			uint32_t ses_id = *((uint32_t *)(elem.out_sg[3].iov_base));
			host_return_val = ioctl(host_fd, CIOCFSESSION, ses_id);
			
			memcpy(elem.in_sg[0].iov_base, &host_return_val, sizeof(host_return_val));
			elem.in_sg[0].iov_len = sizeof(host_return_val);
			
			break;
		
		case CIOCCRYPT:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCCRYPT");
			struct crypt_op crypt = *((struct crypt_op *)(elem.out_sg[3].iov_base));
			unsigned char *src = elem.out_sg[4].iov_base;
			unsigned char *iv = elem.out_sg[5].iov_base;
			unsigned char *dst[MSG_LEN];
			*dst = '\0';
			
			crypt.src = (unsigned char *) src;
			crypt.dst = (unsigned char *) dst;
			crypt.iv = (unsigned char *) iv;
			crypt.op = COP_ENCRYPT;
			host_return_val = ioctl(host_fd, CIOCCRYPT, &crypt);
			
			memcpy(elem.in_sg[0].iov_base, dst, sizeof(*dst) * MSG_LEN);
			elem.in_sg[0].iov_len = sizeof(*dst) * MSG_LEN;
			memcpy(elem.in_sg[1].iov_base, &host_return_val, sizeof(host_return_val));
			elem.in_sg[1].iov_len = sizeof(host_return_val);
			
			break;
		}
		
		break;

	default:
		DEBUG("Unknown syscall_type");
	}

	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
	
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}


static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
	DEBUG_IN();
	
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
	DEBUG_IN();
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
