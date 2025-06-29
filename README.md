# patches
Tool to automate netdev development.

## Installation

```
git clone --recurse-submodules https://github.com/mina/patches.git
# add patches to your $PATH
```

## Workflow:

```
# Do development
git co -b my-branch --track net-next/main
vim ...
git a .
git cm -m "my patch"

# clang-format the patches in `git rebase --interactive`
patches clang_format

# Creates patches under patches.my-branch/
patches create -v 1

# Run all non-build presubmits (faster)
patches presubmit_quick

# Run all the checks including builds (slower)
patches presubmit

# Run an explicit set of nipa tests:
patches patches nipa_test patch/deprecated_api,patch/verify_signedoff

# Send the patches to your target tree based on the upstream branch,
# net-next in this case
patches send -v 1

# Run all the presubmits and send the patches without asking for confirmation
patches send_no_confirm -v 1
```
