#!/bin/bash
src=./src/lib/*
dst=/usr/include/cbuild/

sudo mkdir -p $dst
sudo cp $src $dst
