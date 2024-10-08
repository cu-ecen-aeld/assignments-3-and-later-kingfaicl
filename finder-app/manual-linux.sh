#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
#TOOLCHAIN=/home/cloo/toolchain/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/aarch64-none-linux-gnu/libc
# auto-runner can't find home; use finder_app path instead
#TOOLCHAIN=${FINDER_APP_DIR}/libc
# use sysroot from gcc
TOOLCHAIN=$(${CROSS_COMPILE}gcc -print-sysroot)

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
    # config the build
#    echo "Installing ncurses"
#    sudo apt install libncurses5-dev
    echo "Making menuconfig"
    # auto-runner can't find ncurses for making menuconfig; skip
    #make menuconfig

    # config "virt" arm dev board [simulate in QEMU]
    echo "Configuring virt arm dev board"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig

    # build kernel image
    echo "Building kernel image"
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

    # build kernel modules
#    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules

    # build devicetree
    make ARCH=${ARCH} CROSS-COMPILE=${CROSS-COMPILE} dtbs
    
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs
cd ${OUTDIR}/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make distclean
    #make defconfig
    make CROSS_COMPILE=${CROSS_COMPILE} defconfig
else
    cd busybox
fi

# TODO: Make and install busybox
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install


echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
cp -fL ${TOOLCHAIN}/lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib
cp -fL ${TOOLCHAIN}/lib64/libm.so.6 ${OUTDIR}/rootfs/lib64
cp -fL ${TOOLCHAIN}/lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64
cp -fL ${TOOLCHAIN}/lib64/libc.so.6 ${OUTDIR}/rootfs/lib64
#cd ${TOOLCHAIN}
#cp -fL lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib
#cp -fL lib64/libm.so.6 ${OUTDIR}/rootfs/lib64
#cp -fL lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64
#cp -fL lib64/libc.so.6 ${OUTDIR}/rootfs/lib64

# TODO: Make device nodes
sudo mknod -m 666 ${OUTDIR}/rootfs/dev/null c 1 3
sudo mknod -m 666 ${OUTDIR}/rootfs/dev/console c 5 1

# TODO: Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=${CROSS_COMPILE}

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs 
cp -fLr writer finder.sh finder-test.sh autorun-qemu.sh conf ${OUTDIR}/rootfs/home


# TODO: Chown the root directory
sudo chown -hR root:root ${OUTDIR}/rootfs


# TODO: Create initramfs.cpio.gz
cd "$OUTDIR/rootfs"
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ..
gzip -f initramfs.cpio

