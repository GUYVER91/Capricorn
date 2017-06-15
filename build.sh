#
# Custom build script 
#

yellow='\033[0;33m'
white='\033[0m'
red='\033[0;31m'
gre='\e[0;32m'
echo -e ""
echo -e "$yellow=====================\n\n Welcome to GUYVER building program !\n\n=====================\n"
echo -e "$white"
Start=$(date +"%s")
KERNEL_DIR=$PWD
DTBTOOL=$KERNEL_DIR/dtbTool
cd $KERNEL_DIR
export ARCH=arm64
export CROSS_COMPILE="/home/guyver/Desktop/Toolchain/Linaro-v7.1/bin/aarch64-linaro-linux-gnu-"
export LD_LIBRARY_PATH=home/guyver/Desktop/Toolchain/Linaro-v7.1/lib/
STRIP="/home/guyver/Desktop/Toolchain/Linaro-v7.1/bin/aarch64-linaro-linux-gnu-strip"
make clean
make guyver_defconfig
export KBUILD_BUILD_HOST="Ubuntu"
export KBUILD_BUILD_USER="GUYVER"
make -j5
time=$(date +"%d-%m-%y-%T")
$DTBTOOL -2 -o $KERNEL_DIR/arch/arm64/boot/dt.img -s 2048 -p $KERNEL_DIR/scripts/dtc/ $KERNEL_DIR/arch/arm/boot/dts/
mv $KERNEL_DIR/arch/arm64/boot/dt.img $KERNEL_DIR/build/dtb
cp $KERNEL_DIR/arch/arm64/boot/Image.gz $KERNEL_DIR/build/zImage
