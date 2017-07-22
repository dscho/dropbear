#include "includes.h"
#include "dbutil.h"
#include "buffer.h"
#include "ecdsa.h"
#include "genrsa.h"
#include "gendss.h"
#include "signkey.h"
#include "dbrandom.h"

/* Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_writefile(buffer * buf, const char * filename) {
	int ret = DROPBEAR_FAILURE;
	int fd = -1;

	fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "Couldn't create new file %s: %s",
			filename, strerror(errno));
		goto out;
	}

	/* write the file now */
	while (buf->pos != buf->len) {
		int len = write(fd, buf_getptr(buf, buf->len - buf->pos),
				buf->len - buf->pos);
		if (len == -1 && errno == EINTR) {
			continue;
		}
		if (len <= 0) {
			dropbear_log(LOG_ERR, "Failed writing file %s: %s",
				filename, strerror(errno));
			goto out;
		}
		buf_incrpos(buf, len);
	}

	ret = DROPBEAR_SUCCESS;

out:
#ifndef __MINGW32__
	if (fd >= 0) {
		if (fsync(fd) != 0) {
			dropbear_log(LOG_ERR, "fsync of %s failed: %s", filename, strerror(errno));
		}
		m_close(fd);
	}
#endif
	return ret;
}

/* returns 0 on failure */
static int get_default_bits(enum signkey_type keytype)
{
	switch (keytype) {
#if DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA:
			return DROPBEAR_DEFAULT_RSA_SIZE;
#endif
#if DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS:
			/* DSS for SSH only defines 1024 bits */
			return 1024;
#endif
#if DROPBEAR_ECDSA
		case DROPBEAR_SIGNKEY_ECDSA_KEYGEN:
			return ECDSA_DEFAULT_SIZE;
		case DROPBEAR_SIGNKEY_ECDSA_NISTP521:
			return 521;
		case DROPBEAR_SIGNKEY_ECDSA_NISTP384:
			return 384;
		case DROPBEAR_SIGNKEY_ECDSA_NISTP256:
			return 256;
#endif
		default:
			return 0;
	}
}

int signkey_generate_get_bits(enum signkey_type keytype, int bits) {
	if (bits == 0)
	{
		bits = get_default_bits(keytype);
	}
	return bits;
}

static int err_win_to_posix(DWORD winerr)
{
	int error = ENOSYS;
	switch(winerr) {
	case ERROR_ACCESS_DENIED: error = EACCES; break;
	case ERROR_ACCOUNT_DISABLED: error = EACCES; break;
	case ERROR_ACCOUNT_RESTRICTION: error = EACCES; break;
	case ERROR_ALREADY_ASSIGNED: error = EBUSY; break;
	case ERROR_ALREADY_EXISTS: error = EEXIST; break;
	case ERROR_ARITHMETIC_OVERFLOW: error = ERANGE; break;
	case ERROR_BAD_COMMAND: error = EIO; break;
	case ERROR_BAD_DEVICE: error = ENODEV; break;
	case ERROR_BAD_DRIVER_LEVEL: error = ENXIO; break;
	case ERROR_BAD_EXE_FORMAT: error = ENOEXEC; break;
	case ERROR_BAD_FORMAT: error = ENOEXEC; break;
	case ERROR_BAD_LENGTH: error = EINVAL; break;
	case ERROR_BAD_PATHNAME: error = ENOENT; break;
	case ERROR_BAD_PIPE: error = EPIPE; break;
	case ERROR_BAD_UNIT: error = ENODEV; break;
	case ERROR_BAD_USERNAME: error = EINVAL; break;
	case ERROR_BROKEN_PIPE: error = EPIPE; break;
	case ERROR_BUFFER_OVERFLOW: error = ENAMETOOLONG; break;
	case ERROR_BUSY: error = EBUSY; break;
	case ERROR_BUSY_DRIVE: error = EBUSY; break;
	case ERROR_CALL_NOT_IMPLEMENTED: error = ENOSYS; break;
	case ERROR_CANNOT_MAKE: error = EACCES; break;
	case ERROR_CANTOPEN: error = EIO; break;
	case ERROR_CANTREAD: error = EIO; break;
	case ERROR_CANTWRITE: error = EIO; break;
	case ERROR_CRC: error = EIO; break;
	case ERROR_CURRENT_DIRECTORY: error = EACCES; break;
	case ERROR_DEVICE_IN_USE: error = EBUSY; break;
	case ERROR_DEV_NOT_EXIST: error = ENODEV; break;
	case ERROR_DIRECTORY: error = EINVAL; break;
	case ERROR_DIR_NOT_EMPTY: error = ENOTEMPTY; break;
	case ERROR_DISK_CHANGE: error = EIO; break;
	case ERROR_DISK_FULL: error = ENOSPC; break;
	case ERROR_DRIVE_LOCKED: error = EBUSY; break;
	case ERROR_ENVVAR_NOT_FOUND: error = EINVAL; break;
	case ERROR_EXE_MARKED_INVALID: error = ENOEXEC; break;
	case ERROR_FILENAME_EXCED_RANGE: error = ENAMETOOLONG; break;
	case ERROR_FILE_EXISTS: error = EEXIST; break;
	case ERROR_FILE_INVALID: error = ENODEV; break;
	case ERROR_FILE_NOT_FOUND: error = ENOENT; break;
	case ERROR_GEN_FAILURE: error = EIO; break;
	case ERROR_HANDLE_DISK_FULL: error = ENOSPC; break;
	case ERROR_INSUFFICIENT_BUFFER: error = ENOMEM; break;
	case ERROR_INVALID_ACCESS: error = EACCES; break;
	case ERROR_INVALID_ADDRESS: error = EFAULT; break;
	case ERROR_INVALID_BLOCK: error = EFAULT; break;
	case ERROR_INVALID_DATA: error = EINVAL; break;
	case ERROR_INVALID_DRIVE: error = ENODEV; break;
	case ERROR_INVALID_EXE_SIGNATURE: error = ENOEXEC; break;
	case ERROR_INVALID_FLAGS: error = EINVAL; break;
	case ERROR_INVALID_FUNCTION: error = ENOSYS; break;
	case ERROR_INVALID_HANDLE: error = EBADF; break;
	case ERROR_INVALID_LOGON_HOURS: error = EACCES; break;
	case ERROR_INVALID_NAME: error = EINVAL; break;
	case ERROR_INVALID_OWNER: error = EINVAL; break;
	case ERROR_INVALID_PARAMETER: error = EINVAL; break;
	case ERROR_INVALID_PASSWORD: error = EPERM; break;
	case ERROR_INVALID_PRIMARY_GROUP: error = EINVAL; break;
	case ERROR_INVALID_REPARSE_DATA: error = EINVAL; break;
	case ERROR_INVALID_SIGNAL_NUMBER: error = EINVAL; break;
	case ERROR_INVALID_TARGET_HANDLE: error = EIO; break;
	case ERROR_INVALID_WORKSTATION: error = EACCES; break;
	case ERROR_IO_DEVICE: error = EIO; break;
	case ERROR_IO_INCOMPLETE: error = EINTR; break;
	case ERROR_LOCKED: error = EBUSY; break;
	case ERROR_LOCK_VIOLATION: error = EACCES; break;
	case ERROR_LOGON_FAILURE: error = EACCES; break;
	case ERROR_MAPPED_ALIGNMENT: error = EINVAL; break;
	case ERROR_META_EXPANSION_TOO_LONG: error = E2BIG; break;
	case ERROR_MORE_DATA: error = EPIPE; break;
	case ERROR_NEGATIVE_SEEK: error = ESPIPE; break;
	case ERROR_NOACCESS: error = EFAULT; break;
	case ERROR_NONE_MAPPED: error = EINVAL; break;
	case ERROR_NOT_A_REPARSE_POINT: error = EINVAL; break;
	case ERROR_NOT_ENOUGH_MEMORY: error = ENOMEM; break;
	case ERROR_NOT_READY: error = EAGAIN; break;
	case ERROR_NOT_SAME_DEVICE: error = EXDEV; break;
	case ERROR_NO_DATA: error = EPIPE; break;
	case ERROR_NO_MORE_SEARCH_HANDLES: error = EIO; break;
	case ERROR_NO_PROC_SLOTS: error = EAGAIN; break;
	case ERROR_NO_SUCH_PRIVILEGE: error = EACCES; break;
	case ERROR_OPEN_FAILED: error = EIO; break;
	case ERROR_OPEN_FILES: error = EBUSY; break;
	case ERROR_OPERATION_ABORTED: error = EINTR; break;
	case ERROR_OUTOFMEMORY: error = ENOMEM; break;
	case ERROR_PASSWORD_EXPIRED: error = EACCES; break;
	case ERROR_PATH_BUSY: error = EBUSY; break;
	case ERROR_PATH_NOT_FOUND: error = ENOENT; break;
	case ERROR_PIPE_BUSY: error = EBUSY; break;
	case ERROR_PIPE_CONNECTED: error = EPIPE; break;
	case ERROR_PIPE_LISTENING: error = EPIPE; break;
	case ERROR_PIPE_NOT_CONNECTED: error = EPIPE; break;
	case ERROR_PRIVILEGE_NOT_HELD: error = EACCES; break;
	case ERROR_READ_FAULT: error = EIO; break;
	case ERROR_REPARSE_ATTRIBUTE_CONFLICT: error = EINVAL; break;
	case ERROR_REPARSE_TAG_INVALID: error = EINVAL; break;
	case ERROR_REPARSE_TAG_MISMATCH: error = EINVAL; break;
	case ERROR_SEEK: error = EIO; break;
	case ERROR_SEEK_ON_DEVICE: error = ESPIPE; break;
	case ERROR_SHARING_BUFFER_EXCEEDED: error = ENFILE; break;
	case ERROR_SHARING_VIOLATION: error = EACCES; break;
	case ERROR_STACK_OVERFLOW: error = ENOMEM; break;
	case ERROR_SWAPERROR: error = ENOENT; break;
	case ERROR_TOO_MANY_MODULES: error = EMFILE; break;
	case ERROR_TOO_MANY_OPEN_FILES: error = EMFILE; break;
	case ERROR_UNRECOGNIZED_MEDIA: error = ENXIO; break;
	case ERROR_UNRECOGNIZED_VOLUME: error = ENODEV; break;
	case ERROR_WAIT_NO_CHILDREN: error = ECHILD; break;
	case ERROR_WRITE_FAULT: error = EIO; break;
	case ERROR_WRITE_PROTECT: error = EROFS; break;
	}
	return error;
}

static int link(const char *oldpath, const char *newpath)
{
        if (!CreateHardLinkA(newpath, oldpath, NULL)) {
                mingw_dosmaperr(GetLastError());
                return -1;
        }
        return 0;
}
	
/* if skip_exist is set it will silently return if the key file exists */
int signkey_generate(enum signkey_type keytype, int bits, const char* filename, int skip_exist)
{
	sign_key * key = NULL;
	buffer *buf = NULL;
	char *fn_temp = NULL;
	int ret = DROPBEAR_FAILURE;
	bits = signkey_generate_get_bits(keytype, bits);

	/* now we can generate the key */
	key = new_sign_key();

	seedrandom();

	switch(keytype) {
#if DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA:
			key->rsakey = gen_rsa_priv_key(bits);
			break;
#endif
#if DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS:
			key->dsskey = gen_dss_priv_key(bits);
			break;
#endif
#if DROPBEAR_ECDSA
		case DROPBEAR_SIGNKEY_ECDSA_KEYGEN:
		case DROPBEAR_SIGNKEY_ECDSA_NISTP521:
		case DROPBEAR_SIGNKEY_ECDSA_NISTP384:
		case DROPBEAR_SIGNKEY_ECDSA_NISTP256:
			{
				ecc_key *ecckey = gen_ecdsa_priv_key(bits);
				keytype = ecdsa_signkey_type(ecckey);
				*signkey_key_ptr(key, keytype) = ecckey;
			}
			break;
#endif
		default:
			dropbear_exit("Internal error");
	}

	seedrandom();

	buf = buf_new(MAX_PRIVKEY_SIZE); 

	buf_put_priv_key(buf, key, keytype);
	sign_key_free(key);
	key = NULL;
	buf_setpos(buf, 0);

	fn_temp = m_malloc(strlen(filename) + 30);
	snprintf(fn_temp, strlen(filename)+30, "%s.tmp%d", filename, getpid());
	ret = buf_writefile(buf, fn_temp);

	if (ret == DROPBEAR_FAILURE) {
		goto out;
	}

	if (link(fn_temp, filename) < 0) {
		/* If generating keys on connection (skipexist) it's OK to get EEXIST 
		- we probably just lost a race with another connection to generate the key */
		if (!(skip_exist && errno == EEXIST)) {
			dropbear_log(LOG_ERR, "Failed moving key file to %s: %s", filename,
				strerror(errno));
			/* XXX fallback to non-atomic copy for some filesystems? */
			ret = DROPBEAR_FAILURE;
			goto out;
		}
	}

out:
	if (buf) {
		buf_burn(buf);
		buf_free(buf);
	}
	
	if (fn_temp) {
		unlink(fn_temp);
		m_free(fn_temp);
	}

	return ret;
}
