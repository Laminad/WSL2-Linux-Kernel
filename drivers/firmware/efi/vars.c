// SPDX-License-Identifier: GPL-2.0+
/*
 * Originally from efivars.c
 *
 * Copyright (C) 2001,2003,2004 Dell <Matt_Domsch@dell.com>
 * Copyright (C) 2004 Intel Corporation <matthew.e.tolentino@intel.com>
 */

#define pr_fmt(fmt) "efivars: " fmt

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/efi.h>
#include <linux/ucs2_string.h>

/* Private pointer to registered efivars */
static struct efivars *__efivars;

static DEFINE_SEMAPHORE(efivars_lock, 1);

static efi_status_t check_var_size(bool nonblocking, u32 attributes,
				   unsigned long size)
{
	const struct efivar_operations *fops;
	efi_status_t status;

<<<<<<< HEAD
	fops = __efivars->ops;

	if (!fops->query_variable_store)
		status = EFI_UNSUPPORTED;
=======
	node = (struct efi_generic_dev_path *)buffer;

	if (len < sizeof(*node))
		return false;

	while (offset <= len - sizeof(*node) &&
	       node->length >= sizeof(*node) &&
		node->length <= len - offset) {
		offset += node->length;

		if ((node->type == EFI_DEV_END_PATH ||
		     node->type == EFI_DEV_END_PATH2) &&
		    node->sub_type == EFI_DEV_END_ENTIRE)
			return true;

		node = (struct efi_generic_dev_path *)(buffer + offset);
	}

	/*
	 * If we're here then either node->length pointed past the end
	 * of the buffer or we reached the end of the buffer without
	 * finding a device path end node.
	 */
	return false;
}

static bool
validate_boot_order(efi_char16_t *var_name, int match, u8 *buffer,
		    unsigned long len)
{
	/* An array of 16-bit integers */
	if ((len % 2) != 0)
		return false;

	return true;
}

static bool
validate_load_option(efi_char16_t *var_name, int match, u8 *buffer,
		     unsigned long len)
{
	u16 filepathlength;
	int i, desclength = 0, namelen;

	namelen = ucs2_strnlen(var_name, EFI_VAR_NAME_LEN);

	/* Either "Boot" or "Driver" followed by four digits of hex */
	for (i = match; i < match+4; i++) {
		if (var_name[i] > 127 ||
		    hex_to_bin(var_name[i] & 0xff) < 0)
			return true;
	}

	/* Reject it if there's 4 digits of hex and then further content */
	if (namelen > match + 4)
		return false;

	/* A valid entry must be at least 8 bytes */
	if (len < 8)
		return false;

	filepathlength = buffer[4] | buffer[5] << 8;

	/*
	 * There's no stored length for the description, so it has to be
	 * found by hand
	 */
	desclength = ucs2_strsize((efi_char16_t *)(buffer + 6), len - 6) + 2;

	/* Each boot entry must have a descriptor */
	if (!desclength)
		return false;

	/*
	 * If the sum of the length of the description, the claimed filepath
	 * length and the original header are greater than the length of the
	 * variable, it's malformed
	 */
	if ((desclength + filepathlength + 6) > len)
		return false;

	/*
	 * And, finally, check the filepath
	 */
	return validate_device_path(var_name, match, buffer + desclength + 6,
				    filepathlength);
}

static bool
validate_uint16(efi_char16_t *var_name, int match, u8 *buffer,
		unsigned long len)
{
	/* A single 16-bit integer */
	if (len != 2)
		return false;

	return true;
}

static bool
validate_ascii_string(efi_char16_t *var_name, int match, u8 *buffer,
		      unsigned long len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (buffer[i] > 127)
			return false;

		if (buffer[i] == 0)
			return true;
	}

	return false;
}

struct variable_validate {
	efi_guid_t vendor;
	char *name;
	bool (*validate)(efi_char16_t *var_name, int match, u8 *data,
			 unsigned long len);
};

/*
 * This is the list of variables we need to validate, as well as the
 * whitelist for what we think is safe not to default to immutable.
 *
 * If it has a validate() method that's not NULL, it'll go into the
 * validation routine.  If not, it is assumed valid, but still used for
 * whitelisting.
 *
 * Note that it's sorted by {vendor,name}, but globbed names must come after
 * any other name with the same prefix.
 */
static const struct variable_validate variable_validate[] = {
	{ EFI_GLOBAL_VARIABLE_GUID, "BootNext", validate_uint16 },
	{ EFI_GLOBAL_VARIABLE_GUID, "BootOrder", validate_boot_order },
	{ EFI_GLOBAL_VARIABLE_GUID, "Boot*", validate_load_option },
	{ EFI_GLOBAL_VARIABLE_GUID, "DriverOrder", validate_boot_order },
	{ EFI_GLOBAL_VARIABLE_GUID, "Driver*", validate_load_option },
	{ EFI_GLOBAL_VARIABLE_GUID, "ConIn", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "ConInDev", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "ConOut", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "ConOutDev", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "ErrOut", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "ErrOutDev", validate_device_path },
	{ EFI_GLOBAL_VARIABLE_GUID, "Lang", validate_ascii_string },
	{ EFI_GLOBAL_VARIABLE_GUID, "OsIndications", NULL },
	{ EFI_GLOBAL_VARIABLE_GUID, "PlatformLang", validate_ascii_string },
	{ EFI_GLOBAL_VARIABLE_GUID, "Timeout", validate_uint16 },
	{ LINUX_EFI_CRASH_GUID, "*", NULL },
	{ NULL_GUID, "", NULL },
};

/*
 * Check if @var_name matches the pattern given in @match_name.
 *
 * @var_name: an array of @len non-NUL characters.
 * @match_name: a NUL-terminated pattern string, optionally ending in "*". A
 *              final "*" character matches any trailing characters @var_name,
 *              including the case when there are none left in @var_name.
 * @match: on output, the number of non-wildcard characters in @match_name
 *         that @var_name matches, regardless of the return value.
 * @return: whether @var_name fully matches @match_name.
 */
static bool
variable_matches(const char *var_name, size_t len, const char *match_name,
		 int *match)
{
	for (*match = 0; ; (*match)++) {
		char c = match_name[*match];

		switch (c) {
		case '*':
			/* Wildcard in @match_name means we've matched. */
			return true;

		case '\0':
			/* @match_name has ended. Has @var_name too? */
			return (*match == len);

		default:
			/*
			 * We've reached a non-wildcard char in @match_name.
			 * Continue only if there's an identical character in
			 * @var_name.
			 */
			if (*match < len && c == var_name[*match])
				continue;
			return false;
		}
	}
}

bool
efivar_validate(efi_guid_t vendor, efi_char16_t *var_name, u8 *data,
		unsigned long data_size)
{
	int i;
	unsigned long utf8_size;
	u8 *utf8_name;

	utf8_size = ucs2_utf8size(var_name);
	utf8_name = kmalloc(utf8_size + 1, GFP_KERNEL);
	if (!utf8_name)
		return false;

	ucs2_as_utf8(utf8_name, var_name, utf8_size);
	utf8_name[utf8_size] = '\0';

	for (i = 0; variable_validate[i].name[0] != '\0'; i++) {
		const char *name = variable_validate[i].name;
		int match = 0;

		if (efi_guidcmp(vendor, variable_validate[i].vendor))
			continue;

		if (variable_matches(utf8_name, utf8_size+1, name, &match)) {
			if (variable_validate[i].validate == NULL)
				break;
			kfree(utf8_name);
			return variable_validate[i].validate(var_name, match,
							     data, data_size);
		}
	}
	kfree(utf8_name);
	return true;
}
EXPORT_SYMBOL_GPL(efivar_validate);

bool
efivar_variable_is_removable(efi_guid_t vendor, const char *var_name,
			     size_t len)
{
	int i;
	bool found = false;
	int match = 0;

	/*
	 * Check if our variable is in the validated variables list
	 */
	for (i = 0; variable_validate[i].name[0] != '\0'; i++) {
		if (efi_guidcmp(variable_validate[i].vendor, vendor))
			continue;

		if (variable_matches(var_name, len,
				     variable_validate[i].name, &match)) {
			found = true;
			break;
		}
	}

	/*
	 * If it's in our list, it is removable.
	 */
	return found;
}
EXPORT_SYMBOL_GPL(efivar_variable_is_removable);

static efi_status_t
check_var_size(u32 attributes, unsigned long size)
{
	const struct efivar_operations *fops;

	if (!__efivars)
		return EFI_UNSUPPORTED;

	fops = __efivars->ops;

	if (!fops->query_variable_store)
		return EFI_UNSUPPORTED;

	return fops->query_variable_store(attributes, size, false);
}

static efi_status_t
check_var_size_nonblocking(u32 attributes, unsigned long size)
{
	const struct efivar_operations *fops;

	if (!__efivars)
		return EFI_UNSUPPORTED;

	fops = __efivars->ops;

	if (!fops->query_variable_store)
		return EFI_UNSUPPORTED;

	return fops->query_variable_store(attributes, size, true);
}

static bool variable_is_present(efi_char16_t *variable_name, efi_guid_t *vendor,
				struct list_head *head)
{
	struct efivar_entry *entry, *n;
	unsigned long strsize1, strsize2;
	bool found = false;

	strsize1 = ucs2_strsize(variable_name, 1024);
	list_for_each_entry_safe(entry, n, head, list) {
		strsize2 = ucs2_strsize(entry->var.VariableName, 1024);
		if (strsize1 == strsize2 &&
			!memcmp(variable_name, &(entry->var.VariableName),
				strsize2) &&
			!efi_guidcmp(entry->var.VendorGuid,
				*vendor)) {
			found = true;
			break;
		}
	}
	return found;
}

/*
 * Returns the size of variable_name, in bytes, including the
 * terminating NULL character, or variable_name_size if no NULL
 * character is found among the first variable_name_size bytes.
 */
static unsigned long var_name_strnsize(efi_char16_t *variable_name,
				       unsigned long variable_name_size)
{
	unsigned long len;
	efi_char16_t c;

	/*
	 * The variable name is, by definition, a NULL-terminated
	 * string, so make absolutely sure that variable_name_size is
	 * the value we expect it to be. If not, return the real size.
	 */
	for (len = 2; len <= variable_name_size; len += sizeof(c)) {
		c = variable_name[(len / sizeof(c)) - 1];
		if (!c)
			break;
	}

	return min(len, variable_name_size);
}

/*
 * Print a warning when duplicate EFI variables are encountered and
 * disable the sysfs workqueue since the firmware is buggy.
 */
static void dup_variable_bug(efi_char16_t *str16, efi_guid_t *vendor_guid,
			     unsigned long len16)
{
	size_t i, len8 = len16 / sizeof(efi_char16_t);
	char *str8;

	/*
	 * Disable the workqueue since the algorithm it uses for
	 * detecting new variables won't work with this buggy
	 * implementation of GetNextVariableName().
	 */
	efivar_wq_enabled = false;

	str8 = kzalloc(len8, GFP_KERNEL);
	if (!str8)
		return;

	for (i = 0; i < len8; i++)
		str8[i] = str16[i];

	printk(KERN_WARNING "efivars: duplicate variable: %s-%pUl\n",
	       str8, vendor_guid);
	kfree(str8);
}

/**
 * efivar_init - build the initial list of EFI variables
 * @func: callback function to invoke for every variable
 * @data: function-specific data to pass to @func
 * @atomic: do we need to execute the @func-loop atomically?
 * @duplicates: error if we encounter duplicates on @head?
 * @head: initialised head of variable list
 *
 * Get every EFI variable from the firmware and invoke @func. @func
 * should call efivar_entry_add() to build the list of variables.
 *
 * Returns 0 on success, or a kernel error code on failure.
 */
int efivar_init(int (*func)(efi_char16_t *, efi_guid_t, unsigned long, void *),
		void *data, bool duplicates, struct list_head *head)
{
	const struct efivar_operations *ops;
	unsigned long variable_name_size = 1024;
	efi_char16_t *variable_name;
	efi_status_t status;
	efi_guid_t vendor_guid;
	int err = 0;

	if (!__efivars)
		return -EFAULT;

	ops = __efivars->ops;

	variable_name = kzalloc(variable_name_size, GFP_KERNEL);
	if (!variable_name) {
		printk(KERN_ERR "efivars: Memory allocation failed.\n");
		return -ENOMEM;
	}

	if (down_interruptible(&efivars_lock)) {
		err = -EINTR;
		goto free;
	}

	/*
	 * Per EFI spec, the maximum storage allocated for both
	 * the variable name and variable data is 1024 bytes.
	 */

	do {
		variable_name_size = 1024;

		status = ops->get_next_variable(&variable_name_size,
						variable_name,
						&vendor_guid);
		switch (status) {
		case EFI_SUCCESS:
			if (duplicates)
				up(&efivars_lock);

			variable_name_size = var_name_strnsize(variable_name,
							       variable_name_size);

			/*
			 * Some firmware implementations return the
			 * same variable name on multiple calls to
			 * get_next_variable(). Terminate the loop
			 * immediately as there is no guarantee that
			 * we'll ever see a different variable name,
			 * and may end up looping here forever.
			 */
			if (duplicates &&
			    variable_is_present(variable_name, &vendor_guid,
						head)) {
				dup_variable_bug(variable_name, &vendor_guid,
						 variable_name_size);
				status = EFI_NOT_FOUND;
			} else {
				err = func(variable_name, vendor_guid,
					   variable_name_size, data);
				if (err)
					status = EFI_NOT_FOUND;
			}

			if (duplicates) {
				if (down_interruptible(&efivars_lock)) {
					err = -EINTR;
					goto free;
				}
			}

			break;
		case EFI_NOT_FOUND:
			break;
		default:
			printk(KERN_WARNING "efivars: get_next_variable: status=%lx\n",
				status);
			status = EFI_NOT_FOUND;
			break;
		}

	} while (status != EFI_NOT_FOUND);

	up(&efivars_lock);
free:
	kfree(variable_name);

	return err;
}
EXPORT_SYMBOL_GPL(efivar_init);

/**
 * efivar_entry_add - add entry to variable list
 * @entry: entry to add to list
 * @head: list head
 *
 * Returns 0 on success, or a kernel error code on failure.
 */
int efivar_entry_add(struct efivar_entry *entry, struct list_head *head)
{
	if (down_interruptible(&efivars_lock))
		return -EINTR;
	list_add(&entry->list, head);
	up(&efivars_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(efivar_entry_add);

/**
 * efivar_entry_remove - remove entry from variable list
 * @entry: entry to remove from list
 *
 * Returns 0 on success, or a kernel error code on failure.
 */
int efivar_entry_remove(struct efivar_entry *entry)
{
	if (down_interruptible(&efivars_lock))
		return -EINTR;
	list_del(&entry->list);
	up(&efivars_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(efivar_entry_remove);

/*
 * efivar_entry_list_del_unlock - remove entry from variable list
 * @entry: entry to remove
 *
 * Remove @entry from the variable list and release the list lock.
 *
 * NOTE: slightly weird locking semantics here - we expect to be
 * called with the efivars lock already held, and we release it before
 * returning. This is because this function is usually called after
 * set_variable() while the lock is still held.
 */
static void efivar_entry_list_del_unlock(struct efivar_entry *entry)
{
	list_del(&entry->list);
	up(&efivars_lock);
}

/**
 * __efivar_entry_delete - delete an EFI variable
 * @entry: entry containing EFI variable to delete
 *
 * Delete the variable from the firmware but leave @entry on the
 * variable list.
 *
 * This function differs from efivar_entry_delete() because it does
 * not remove @entry from the variable list. Also, it is safe to be
 * called from within a efivar_entry_iter_begin() and
 * efivar_entry_iter_end() region, unlike efivar_entry_delete().
 *
 * Returns 0 on success, or a converted EFI status code if
 * set_variable() fails.
 */
int __efivar_entry_delete(struct efivar_entry *entry)
{
	efi_status_t status;

	if (!__efivars)
		return -EINVAL;

	status = __efivars->ops->set_variable(entry->var.VariableName,
					      &entry->var.VendorGuid,
					      0, 0, NULL);

	return efi_status_to_err(status);
}
EXPORT_SYMBOL_GPL(__efivar_entry_delete);

/**
 * efivar_entry_delete - delete variable and remove entry from list
 * @entry: entry containing variable to delete
 *
 * Delete the variable from the firmware and remove @entry from the
 * variable list. It is the caller's responsibility to free @entry
 * once we return.
 *
 * Returns 0 on success, -EINTR if we can't grab the semaphore,
 * converted EFI status code if set_variable() fails.
 */
int efivar_entry_delete(struct efivar_entry *entry)
{
	const struct efivar_operations *ops;
	efi_status_t status;

	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (!__efivars) {
		up(&efivars_lock);
		return -EINVAL;
	}
	ops = __efivars->ops;
	status = ops->set_variable(entry->var.VariableName,
				   &entry->var.VendorGuid,
				   0, 0, NULL);
	if (!(status == EFI_SUCCESS || status == EFI_NOT_FOUND)) {
		up(&efivars_lock);
		return efi_status_to_err(status);
	}

	efivar_entry_list_del_unlock(entry);
	return 0;
}
EXPORT_SYMBOL_GPL(efivar_entry_delete);

/**
 * efivar_entry_set - call set_variable()
 * @entry: entry containing the EFI variable to write
 * @attributes: variable attributes
 * @size: size of @data buffer
 * @data: buffer containing variable data
 * @head: head of variable list
 *
 * Calls set_variable() for an EFI variable. If creating a new EFI
 * variable, this function is usually followed by efivar_entry_add().
 *
 * Before writing the variable, the remaining EFI variable storage
 * space is checked to ensure there is enough room available.
 *
 * If @head is not NULL a lookup is performed to determine whether
 * the entry is already on the list.
 *
 * Returns 0 on success, -EINTR if we can't grab the semaphore,
 * -EEXIST if a lookup is performed and the entry already exists on
 * the list, or a converted EFI status code if set_variable() fails.
 */
int efivar_entry_set(struct efivar_entry *entry, u32 attributes,
		     unsigned long size, void *data, struct list_head *head)
{
	const struct efivar_operations *ops;
	efi_status_t status;
	efi_char16_t *name = entry->var.VariableName;
	efi_guid_t vendor = entry->var.VendorGuid;

	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (!__efivars) {
		up(&efivars_lock);
		return -EINVAL;
	}
	ops = __efivars->ops;
	if (head && efivar_entry_find(name, vendor, head, false)) {
		up(&efivars_lock);
		return -EEXIST;
	}

	status = check_var_size(attributes, size + ucs2_strsize(name, 1024));
	if (status == EFI_SUCCESS || status == EFI_UNSUPPORTED)
		status = ops->set_variable(name, &vendor,
					   attributes, size, data);

	up(&efivars_lock);

	return efi_status_to_err(status);

}
EXPORT_SYMBOL_GPL(efivar_entry_set);

/*
 * efivar_entry_set_nonblocking - call set_variable_nonblocking()
 *
 * This function is guaranteed to not block and is suitable for calling
 * from crash/panic handlers.
 *
 * Crucially, this function will not block if it cannot acquire
 * efivars_lock. Instead, it returns -EBUSY.
 */
static int
efivar_entry_set_nonblocking(efi_char16_t *name, efi_guid_t vendor,
			     u32 attributes, unsigned long size, void *data)
{
	const struct efivar_operations *ops;
	efi_status_t status;

	if (down_trylock(&efivars_lock))
		return -EBUSY;

	if (!__efivars) {
		up(&efivars_lock);
		return -EINVAL;
	}

	status = check_var_size_nonblocking(attributes,
					    size + ucs2_strsize(name, 1024));
	if (status != EFI_SUCCESS) {
		up(&efivars_lock);
		return -ENOSPC;
	}

	ops = __efivars->ops;
	status = ops->set_variable_nonblocking(name, &vendor, attributes,
					       size, data);

	up(&efivars_lock);
	return efi_status_to_err(status);
}

/**
 * efivar_entry_set_safe - call set_variable() if enough space in firmware
 * @name: buffer containing the variable name
 * @vendor: variable vendor guid
 * @attributes: variable attributes
 * @block: can we block in this context?
 * @size: size of @data buffer
 * @data: buffer containing variable data
 *
 * Ensures there is enough free storage in the firmware for this variable, and
 * if so, calls set_variable(). If creating a new EFI variable, this function
 * is usually followed by efivar_entry_add().
 *
 * Returns 0 on success, -ENOSPC if the firmware does not have enough
 * space for set_variable() to succeed, or a converted EFI status code
 * if set_variable() fails.
 */
int efivar_entry_set_safe(efi_char16_t *name, efi_guid_t vendor, u32 attributes,
			  bool block, unsigned long size, void *data)
{
	const struct efivar_operations *ops;
	efi_status_t status;

	if (!__efivars)
		return -EINVAL;

	ops = __efivars->ops;
	if (!ops->query_variable_store)
		return -ENOSYS;

	/*
	 * If the EFI variable backend provides a non-blocking
	 * ->set_variable() operation and we're in a context where we
	 * cannot block, then we need to use it to avoid live-locks,
	 * since the implication is that the regular ->set_variable()
	 * will block.
	 *
	 * If no ->set_variable_nonblocking() is provided then
	 * ->set_variable() is assumed to be non-blocking.
	 */
	if (!block && ops->set_variable_nonblocking)
		return efivar_entry_set_nonblocking(name, vendor, attributes,
						    size, data);

	if (!block) {
		if (down_trylock(&efivars_lock))
			return -EBUSY;
	} else {
		if (down_interruptible(&efivars_lock))
			return -EINTR;
	}

	status = check_var_size(attributes, size + ucs2_strsize(name, 1024));
	if (status != EFI_SUCCESS) {
		up(&efivars_lock);
		return -ENOSPC;
	}

	status = ops->set_variable(name, &vendor, attributes, size, data);

	up(&efivars_lock);

	return efi_status_to_err(status);
}
EXPORT_SYMBOL_GPL(efivar_entry_set_safe);

/**
 * efivar_entry_find - search for an entry
 * @name: the EFI variable name
 * @guid: the EFI variable vendor's guid
 * @head: head of the variable list
 * @remove: should we remove the entry from the list?
 *
 * Search for an entry on the variable list that has the EFI variable
 * name @name and vendor guid @guid. If an entry is found on the list
 * and @remove is true, the entry is removed from the list.
 *
 * The caller MUST call efivar_entry_iter_begin() and
 * efivar_entry_iter_end() before and after the invocation of this
 * function, respectively.
 *
 * Returns the entry if found on the list, %NULL otherwise.
 */
struct efivar_entry *efivar_entry_find(efi_char16_t *name, efi_guid_t guid,
				       struct list_head *head, bool remove)
{
	struct efivar_entry *entry, *n;
	int strsize1, strsize2;
	bool found = false;

	list_for_each_entry_safe(entry, n, head, list) {
		strsize1 = ucs2_strsize(name, 1024);
		strsize2 = ucs2_strsize(entry->var.VariableName, 1024);
		if (strsize1 == strsize2 &&
		    !memcmp(name, &(entry->var.VariableName), strsize1) &&
		    !efi_guidcmp(guid, entry->var.VendorGuid)) {
			found = true;
			break;
		}
	}

	if (!found)
		return NULL;

	if (remove) {
		if (entry->scanning) {
			/*
			 * The entry will be deleted
			 * after scanning is completed.
			 */
			entry->deleting = true;
		} else
			list_del(&entry->list);
	}

	return entry;
}
EXPORT_SYMBOL_GPL(efivar_entry_find);

/**
 * efivar_entry_size - obtain the size of a variable
 * @entry: entry for this variable
 * @size: location to store the variable's size
 */
int efivar_entry_size(struct efivar_entry *entry, unsigned long *size)
{
	const struct efivar_operations *ops;
	efi_status_t status;

	*size = 0;

	if (down_interruptible(&efivars_lock))
		return -EINTR;
	if (!__efivars) {
		up(&efivars_lock);
		return -EINVAL;
	}
	ops = __efivars->ops;
	status = ops->get_variable(entry->var.VariableName,
				   &entry->var.VendorGuid, NULL, size, NULL);
	up(&efivars_lock);

	if (status != EFI_BUFFER_TOO_SMALL)
		return efi_status_to_err(status);

	return 0;
}
EXPORT_SYMBOL_GPL(efivar_entry_size);

/**
 * __efivar_entry_get - call get_variable()
 * @entry: read data for this variable
 * @attributes: variable attributes
 * @size: size of @data buffer
 * @data: buffer to store variable data
 *
 * The caller MUST call efivar_entry_iter_begin() and
 * efivar_entry_iter_end() before and after the invocation of this
 * function, respectively.
 */
int __efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		       unsigned long *size, void *data)
{
	efi_status_t status;

	if (!__efivars)
		return -EINVAL;

	status = __efivars->ops->get_variable(entry->var.VariableName,
					      &entry->var.VendorGuid,
					      attributes, size, data);

	return efi_status_to_err(status);
}
EXPORT_SYMBOL_GPL(__efivar_entry_get);

/**
 * efivar_entry_get - call get_variable()
 * @entry: read data for this variable
 * @attributes: variable attributes
 * @size: size of @data buffer
 * @data: buffer to store variable data
 */
int efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		     unsigned long *size, void *data)
{
	efi_status_t status;

	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (!__efivars) {
		up(&efivars_lock);
		return -EINVAL;
	}

	status = __efivars->ops->get_variable(entry->var.VariableName,
					      &entry->var.VendorGuid,
					      attributes, size, data);
	up(&efivars_lock);

	return efi_status_to_err(status);
}
EXPORT_SYMBOL_GPL(efivar_entry_get);

/**
 * efivar_entry_set_get_size - call set_variable() and get new size (atomic)
 * @entry: entry containing variable to set and get
 * @attributes: attributes of variable to be written
 * @size: size of data buffer
 * @data: buffer containing data to write
 * @set: did the set_variable() call succeed?
 *
 * This is a pretty special (complex) function. See efivarfs_file_write().
 *
 * Atomically call set_variable() for @entry and if the call is
 * successful, return the new size of the variable from get_variable()
 * in @size. The success of set_variable() is indicated by @set.
 *
 * Returns 0 on success, -EINVAL if the variable data is invalid,
 * -ENOSPC if the firmware does not have enough available space, or a
 * converted EFI status code if either of set_variable() or
 * get_variable() fail.
 *
 * If the EFI variable does not exist when calling set_variable()
 * (EFI_NOT_FOUND), @entry is removed from the variable list.
 */
int efivar_entry_set_get_size(struct efivar_entry *entry, u32 attributes,
			      unsigned long *size, void *data, bool *set)
{
	const struct efivar_operations *ops;
	efi_char16_t *name = entry->var.VariableName;
	efi_guid_t *vendor = &entry->var.VendorGuid;
	efi_status_t status;
	int err;

	*set = false;

	if (efivar_validate(*vendor, name, data, *size) == false)
		return -EINVAL;

	/*
	 * The lock here protects the get_variable call, the conditional
	 * set_variable call, and removal of the variable from the efivars
	 * list (in the case of an authenticated delete).
	 */
	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (!__efivars) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * Ensure that the available space hasn't shrunk below the safe level
	 */
	status = check_var_size(attributes, *size + ucs2_strsize(name, 1024));
	if (status != EFI_SUCCESS) {
		if (status != EFI_UNSUPPORTED) {
			err = efi_status_to_err(status);
			goto out;
		}

		if (*size > 65536) {
			err = -ENOSPC;
			goto out;
		}
	}

	ops = __efivars->ops;

	status = ops->set_variable(name, vendor, attributes, *size, data);
	if (status != EFI_SUCCESS) {
		err = efi_status_to_err(status);
		goto out;
	}

	*set = true;

	/*
	 * Writing to the variable may have caused a change in size (which
	 * could either be an append or an overwrite), or the variable to be
	 * deleted. Perform a GetVariable() so we can tell what actually
	 * happened.
	 */
	*size = 0;
	status = ops->get_variable(entry->var.VariableName,
				   &entry->var.VendorGuid,
				   NULL, size, NULL);

	if (status == EFI_NOT_FOUND)
		efivar_entry_list_del_unlock(entry);
>>>>>>> master
	else
		status = fops->query_variable_store(attributes, size,
						    nonblocking);
	if (status == EFI_UNSUPPORTED)
		return (size <= SZ_64K) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
	return status;
}

/**
 * efivar_is_available - check if efivars is available
 *
 * @return true iff evivars is currently registered
 */
bool efivar_is_available(void)
{
	return __efivars != NULL;
}
EXPORT_SYMBOL_GPL(efivar_is_available);

/**
 * efivars_register - register an efivars
 * @efivars: efivars to register
 * @ops: efivars operations
 *
 * Only a single efivars can be registered at any time.
 */
int efivars_register(struct efivars *efivars,
		     const struct efivar_operations *ops)
{
	int rv;

	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (__efivars) {
		pr_warn("efivars already registered\n");
		rv = -EBUSY;
		goto out;
	}

	efivars->ops = ops;

	__efivars = efivars;

	pr_info("Registered efivars operations\n");
	rv = 0;
out:
	up(&efivars_lock);

	return rv;
}
EXPORT_SYMBOL_GPL(efivars_register);

/**
 * efivars_unregister - unregister an efivars
 * @efivars: efivars to unregister
 *
 * The caller must have already removed every entry from the list,
 * failure to do so is an error.
 */
int efivars_unregister(struct efivars *efivars)
{
	int rv;

	if (down_interruptible(&efivars_lock))
		return -EINTR;

	if (!__efivars) {
		pr_err("efivars not registered\n");
		rv = -EINVAL;
		goto out;
	}

	if (__efivars != efivars) {
		rv = -EINVAL;
		goto out;
	}

	pr_info("Unregistered efivars operations\n");
	__efivars = NULL;

	rv = 0;
out:
	up(&efivars_lock);
	return rv;
}
EXPORT_SYMBOL_GPL(efivars_unregister);

bool efivar_supports_writes(void)
{
	return __efivars && __efivars->ops->set_variable;
}
EXPORT_SYMBOL_GPL(efivar_supports_writes);

/*
 * efivar_lock() - obtain the efivar lock, wait for it if needed
 * @return 0 on success, error code on failure
 */
int efivar_lock(void)
{
	if (down_interruptible(&efivars_lock))
		return -EINTR;
	if (!__efivars->ops) {
		up(&efivars_lock);
		return -ENODEV;
	}
	return 0;
}
EXPORT_SYMBOL_NS_GPL(efivar_lock, EFIVAR);

/*
 * efivar_lock() - obtain the efivar lock if it is free
 * @return 0 on success, error code on failure
 */
int efivar_trylock(void)
{
	if (down_trylock(&efivars_lock))
		 return -EBUSY;
	if (!__efivars->ops) {
		up(&efivars_lock);
		return -ENODEV;
	}
	return 0;
}
EXPORT_SYMBOL_NS_GPL(efivar_trylock, EFIVAR);

/*
 * efivar_unlock() - release the efivar lock
 */
void efivar_unlock(void)
{
	up(&efivars_lock);
}
EXPORT_SYMBOL_NS_GPL(efivar_unlock, EFIVAR);

/*
 * efivar_get_variable() - retrieve a variable identified by name/vendor
 *
 * Must be called with efivars_lock held.
 */
efi_status_t efivar_get_variable(efi_char16_t *name, efi_guid_t *vendor,
				 u32 *attr, unsigned long *size, void *data)
{
	return __efivars->ops->get_variable(name, vendor, attr, size, data);
}
EXPORT_SYMBOL_NS_GPL(efivar_get_variable, EFIVAR);

/*
 * efivar_get_next_variable() - enumerate the next name/vendor pair
 *
 * Must be called with efivars_lock held.
 */
efi_status_t efivar_get_next_variable(unsigned long *name_size,
				      efi_char16_t *name, efi_guid_t *vendor)
{
	return __efivars->ops->get_next_variable(name_size, name, vendor);
}
EXPORT_SYMBOL_NS_GPL(efivar_get_next_variable, EFIVAR);

/*
 * efivar_set_variable_locked() - set a variable identified by name/vendor
 *
 * Must be called with efivars_lock held. If @nonblocking is set, it will use
 * non-blocking primitives so it is guaranteed not to sleep.
 */
efi_status_t efivar_set_variable_locked(efi_char16_t *name, efi_guid_t *vendor,
					u32 attr, unsigned long data_size,
					void *data, bool nonblocking)
{
	efi_set_variable_t *setvar;
	efi_status_t status;

	if (data_size > 0) {
		status = check_var_size(nonblocking, attr,
					data_size + ucs2_strsize(name, 1024));
		if (status != EFI_SUCCESS)
			return status;
	}

	/*
	 * If no _nonblocking variant exists, the ordinary one
	 * is assumed to be non-blocking.
	 */
	setvar = __efivars->ops->set_variable_nonblocking;
	if (!setvar || !nonblocking)
		 setvar = __efivars->ops->set_variable;

	return setvar(name, vendor, attr, data_size, data);
}
EXPORT_SYMBOL_NS_GPL(efivar_set_variable_locked, EFIVAR);

/*
 * efivar_set_variable() - set a variable identified by name/vendor
 *
 * Can be called without holding the efivars_lock. Will sleep on obtaining the
 * lock, or on obtaining other locks that are needed in order to complete the
 * call.
 */
efi_status_t efivar_set_variable(efi_char16_t *name, efi_guid_t *vendor,
				 u32 attr, unsigned long data_size, void *data)
{
	efi_status_t status;

	if (efivar_lock())
		return EFI_ABORTED;

	status = efivar_set_variable_locked(name, vendor, attr, data_size,
					    data, false);
	efivar_unlock();
	return status;
}
EXPORT_SYMBOL_NS_GPL(efivar_set_variable, EFIVAR);

efi_status_t efivar_query_variable_info(u32 attr,
					u64 *storage_space,
					u64 *remaining_space,
					u64 *max_variable_size)
{
	if (!__efivars->ops->query_variable_info)
		return EFI_UNSUPPORTED;
	return __efivars->ops->query_variable_info(attr, storage_space,
			remaining_space, max_variable_size);
}
EXPORT_SYMBOL_NS_GPL(efivar_query_variable_info, EFIVAR);
