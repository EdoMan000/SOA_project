#!/bin/bash

# Script to create and mount or unmount and delete a test image file.

# Temporary file to store the mount directory name
MOUNT_DIR_FILE=".mount_dir_name"

# Function to create and mount the image
create_and_mount() {
    # Create a 1GB test.img file filled with zeros
    dd if=/dev/zero of=test.img bs=1M count=1000

    # Create an ext4 filesystem on the image file
    mkfs.ext4 test.img

    # Initialize the mount directory name
    mount_dir="mountTestFs"
    counter=1

    # Check if the mount directory exists and find a unique name
    while [ -d "$mount_dir" ]; do
        mount_dir="mountTestFs_$counter"
        counter=$((counter + 1))
    done

    # Create the mount directory
    mkdir "$mount_dir"

    # Mount the image file to the mount directory
    sudo mount -o loop test.img "$mount_dir"

    # Save the mount directory name to a file
    echo "$mount_dir" > "$MOUNT_DIR_FILE"

    echo "Mounted test.img to $mount_dir"
}

# Function to unmount and delete the image
unmount_and_delete() {
    # Check if the mount directory file exists
    if [ ! -f "$MOUNT_DIR_FILE" ]; then
        echo "Mount directory information not found. Cannot proceed."
        return
    fi

    # Read the mount directory name from the file
    mount_dir=$(cat "$MOUNT_DIR_FILE")

    # Check if the mount directory exists
    if [ ! -d "$mount_dir" ]; then
        echo "Mount directory $mount_dir does not exist."
    else
        # Unmount the image file
        sudo umount "$mount_dir"
        echo "Unmounted test.img from $mount_dir"

        # Remove the mount directory
        rmdir "$mount_dir"
        echo "Removed mount directory $mount_dir"
    fi

    # Remove the mount directory file
    rm -f "$MOUNT_DIR_FILE"

    # Remove the image file
    rm -f test.img
    echo "Deleted test.img"
}

# Display menu options
echo "Select an option:"
echo "1) Create and mount test.img"
echo "2) Unmount and delete test.img"
echo "3) Exit"
read -p "Enter your choice [1-3]: " choice

case $choice in
    1)
        create_and_mount
        ;;
    2)
        unmount_and_delete
        ;;
    3)
        echo "Exiting."
        ;;
    *)
        echo "Invalid choice. Exiting."
        ;;
esac
