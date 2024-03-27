#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/version.h>
#include <linux/uio.h> 

#include "singlefilefs.h"

// //this would be used for .write file operation (writes from userspace) but in this case we don't need it... leaving it because i already implemented it
// ssize_t onefilefs_append_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
//     struct inode *inode = filp->f_inode;
//     struct super_block *sb = inode->i_sb;
//     struct buffer_head *bh;
//     int block_to_write;
//     loff_t offset;
//     size_t remaining_bytes = len;
    
//     //Use the current file size as the offset for appending (we ignore the off, as we allow append only).
//     loff_t append_offset = inode->i_size;

//     //Calculate the block where the append operation should start.
//     block_to_write = append_offset / DEFAULT_BLOCK_SIZE + 2; // +2 for superblock and inode block.
//     offset = append_offset % DEFAULT_BLOCK_SIZE;

//     //Handle writes that extend beyond the current block.
//     //This simple example assumes writing within a single block for simplicity.
//     if (offset + len > DEFAULT_BLOCK_SIZE)
//         remaining_bytes = DEFAULT_BLOCK_SIZE - offset;

//     //Read the block where we need to append.
//     bh = (struct buffer_head *)sb_bread(sb, block_to_write);
//     if (!bh)
//         return -EIO;

//     //Copy data from user buffer to the block buffer.
//     if (copy_from_user(bh->b_data + offset, buf, remaining_bytes)) {
//         brelse(bh); //Release the buffer head.
//         return -EFAULT;
//     }

//     //Mark the buffer dirty so it gets written back to disk.
//     mark_buffer_dirty(bh);
//     sync_dirty_buffer(bh);
//     brelse(bh);

//     //Update the inode size to reflect the appended data.
//     inode->i_size += remaining_bytes;
//     mark_inode_dirty(inode);

//     //The offset parameter is not used for determining where to write,
//     //but it's updated to reflect the new end of the file after appending.
//     *off = inode->i_size;

//     return remaining_bytes;
// }

ssize_t onefilefs_append_write_iter(struct kiocb *iocb, struct iov_iter *from) {
    struct file *file = iocb->ki_filp;
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh;
    int block_to_write;
    loff_t offset;
    size_t len = iov_iter_count(from);
    size_t remaining_bytes = len;
    
    // Use the current file size as the offset for appending (we ignore the ki_pos, as we allow append only).
    loff_t append_offset = i_size_read(inode);

    // Calculate the block where the append operation should start.
    block_to_write = append_offset / DEFAULT_BLOCK_SIZE + 2; // +2 for superblock and inode block.
    offset = append_offset % DEFAULT_BLOCK_SIZE;

    if (offset + len > DEFAULT_BLOCK_SIZE)
        remaining_bytes = DEFAULT_BLOCK_SIZE - offset;

    bh = sb_bread(sb, block_to_write);
    if (!bh)
        return -EIO;

    // Copy data from iov_iter to the block buffer. Notice the change here from copy_from_user.
    size_t copied = copy_from_iter(bh->b_data + offset, remaining_bytes, from);
    if (copied != remaining_bytes) {
        brelse(bh); // Release the buffer head.
        return -EFAULT;
    }

    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    // Update inode size and file position.
    inode->i_size += copied;
    mark_inode_dirty(inode);
    iocb->ki_pos += copied;  // Even if we're appending, it's good practice to update ki_pos.

    return copied;
}


ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    //printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason

    //check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    //printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	    return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    //printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


	//this work is done if the inode was not already cached
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    struct mnt_idmap {
        struct user_namespace *owner;
        refcount_t count;
    };
    inode_init_owner(&nop_mnt_idmap, the_inode, NULL, S_IFREG);
#else
    inode_init_owner(the_inode, NULL, S_IFREG);
#endif
	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    	bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    	if(!bh){
		iput(the_inode);
		return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_append_write_iter, //this is used by kernel_write
};
