FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/chute
WORKDIR $SRC/chute
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
