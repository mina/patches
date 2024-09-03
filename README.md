# patches
My setup to automate sending netdev patches

Workflow:

```
git co -b my-branch --track net-next/main
vim ...
git a .
git cm -m "my patch"

# Creates patches under my-branch/
patches create -v 1

# clang-format each patch in a git rebase --exec
patches clang_format

# Runs checkpatch
patches checkpatch

# Runs patch-by-patch W=1 C=1 in a git rebase --exec
patches build_patch_by_patch
    # if you run into errors
    vim ...				        # fix the errors
    git cm --amend			    # commit the fixes
    build_patch_with_checks.sh	# check if the errors still happen
    git rebase --continue		# carry on with the patch-by-patch build

# Build patch-by-patch allmodconfig in a git rebase --exec
patches build_allmodconfig_patch_by_patch

# Build all configs in `ls ../<branch name>/*.config`
patches build_configs

# Run all presubmit tests.
patches presubmit

# Send the patches
patches send -v 1

# Also available is send_no_confirm, which presubmits then sends with no prompt
patches send_no_confirm -v 1
```
