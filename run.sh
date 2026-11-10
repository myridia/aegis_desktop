

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -Dnappgui_DIR=/usr/local/nappgui/cmake \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DDEPLOYMENT_TARGET_OSX=13.6

cmake --build build --config Release
open build/AegisDesktop.app
