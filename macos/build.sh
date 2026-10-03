#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")"
xcodebuild -scheme Sentinel -configuration Release -arch arm64 \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="-" ONLY_ACTIVE_ARCH=YES
rm -rf dist/Sentinel.app
mkdir -p dist
cp -R build/Build/Products/Release/Sentinel.app dist/Sentinel.app
echo "Built dist/Sentinel.app"
open dist/Sentinel.app
