FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:9a76c52daea628e55c2c82a3d251b7eca50bc10599f3d8ccd23e75ca16383589

COPY . $SRC/weaver
WORKDIR $SRC/weaver
COPY .clusterfuzzlite/build.sh $SRC/
