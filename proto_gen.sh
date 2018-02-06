#!/bin/bash


## Generate both hpp and cpp into proto folder.
protoc -I proto --cpp_out=proto proto/iks.proto
protoc -I proto --grpc_out=proto --plugin=protoc-gen-grpc=$(which grpc_cpp_plugin) proto/iks.proto

## Then, to respect lla convention, we move header to include, and source to src.
## todo: but for now we just move all to include directory and hack cmakefile.

mv proto/*.cc include/logicalaccess/iks/packet
mv proto/*.h include/logicalaccess/iks/packet
#mv proto/*.h include/logicalaccess/iks/packet
