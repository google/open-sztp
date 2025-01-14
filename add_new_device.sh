#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <serial_number>"
  exit 1
fi

serial_number="$1"

# Create a new directory under data/ for the new device using data/12345 as a template.
mkdir -p "data/$serial_number"
cp -r data/12345/* "data/$serial_number"
echo "Created new template data dependencies for serial number $serial_number:"
ls "data/$serial_number" | while read file; do
  echo "  data/$serial_number/$file"
done

# If the server is already running, create symlinks in the runfiles directory and update the runfiles manifest.
runfiles_dir="bazel-bin/main_/main.runfiles/_main/data"
if [ -d "$runfiles_dir" ]; then
  echo "Linking new files to the running server's runfiles directory."

  chmod +w $(readlink "$runfiles_dir/../../MANIFEST")
  for file in $(ls "data/$serial_number"); do
    mkdir -p "$runfiles_dir/$serial_number"
    ln -s "data/$serial_number/$file" "$runfiles_dir/$serial_number/$file"
    echo "_main/data/$serial_number/$file $(readlink data/$serial_number/$file)" >> $(readlink "$runfiles_dir/../../MANIFEST")
  done
fi

echo "Done."
echo "Edit the files under data/$serial_number to customize your new device data."

