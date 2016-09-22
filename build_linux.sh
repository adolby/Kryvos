#!/bin/bash

set -o errexit -o nounset

# Update platform
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libfontconfig1 -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libfontconfig1-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libfreetype6-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libx11-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxext-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxfixes-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxi-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxrender-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxcb1-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libx11-xcb-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libxcb-glx0-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install mesa-common-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
sudo DEBIAN_FRONTEND=noninteractive apt-get install libglu1-mesa-dev -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Capture build directory
project=$(pwd)

# Build Qt
cd /tmp/
wget https://download.qt.io/official_releases/qt/5.7/5.7.0/single/qt-everywhere-opensource-src-5.7.0.tar.gz
gunzip qt-everywhere-opensource-src-5.7.0.tar.gz
tar xf qt-everywhere-opensource-src-5.7.0.tar

cd qt-everywhere-opensource-src-5.7.0
sudo chmod +x configure
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 100
${CXX}
${CC}
./configure -platform linux-g++-64 -opensource -confirm-license -release -c++std c++14 -shared -largefile -no-qml-debug -qt-libpng -qt-libjpeg -qt-doubleconversion -qt-harfbuzz -openssl -qt-pcre -skip qtwebengine -nomake examples

make
make install

# Build
cd ${project}/src/
/usr/local/Qt-5.7.0/bin/qmake -config release
make

# Run tests
cd tests
/usr/local/Qt-5.7.0/bin/qmake -config release
make
cd ../../build/linux/gcc/x86_64/release/test/
sudo chmod +x CryptoTests
./CryptoTests

# Package
cd ..
cp "../../../../../Release Notes" "Release Notes"
cp "../../../../../README.md" "README.md"
cp "../../../../../LICENSE" "LICENSE"
cp "../../../../../Botan License" "Botan License"
cp "../../../../../Qt License" "Qt License"
ls
7z a kryvos_${TRAVIS_TAG}_linux_x86_64.zip "Kryvos" "Release Notes" "README.md" "LICENSE" "Botan License" "Qt License"

exit 0
