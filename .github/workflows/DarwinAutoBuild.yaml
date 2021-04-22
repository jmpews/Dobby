name: Darwin Auto Build

on:
  push:
    branches:
      - master

jobs:
  default:
    runs-on: macOS-latest
    steps:
    - name: checkout master
      uses: actions/checkout@master

    - name: auto build
      run: |
        export ANDROID_NDK_DIR=$ANDROID_NDK_18R_PATH
        current_date_time="`date +%Y%m%d`";
        export DOBBY_BUILD_OUTPUT_NAME=dobby_static_${current_date_time}.tar.gz
        ./build-workspace/auto-build.sh
        echo "DOBBY_BUILD_OUTPUT_NAME=$DOBBY_BUILD_OUTPUT_NAME" >> $GITHUB_ENV
      shell: bash

    - name: print output
      run: |
        ls -lha .
        echo "output=$DOBBY_BUILD_OUTPUT_NAME"

    - name: Delete old release assets
      uses: mknejp/delete-release-assets@v1
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        tag: latest
        assets: "*.tar.gz"
        fail-if-no-assets: false
        fail-if-no-release: false

    - name: update tag
      uses: richardsimko/update-tag@master
      with:
        tag_name: latest
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

    - name: Update release
      uses: ncipollo/release-action@v1
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        tag: latest
        name: release ${{ github.ref }}
        body: "dobby static library update for darwin and android"
        artifacts: "./${{ env.DOBBY_BUILD_OUTPUT_NAME }}"
        allowUpdates: true
        replacesArtifacts: true