# GitHub Release and Hotfix process

This section is for internal usage. It documents the current release and hotfix process to ensure that anyone is able to
run it.

## Release process

The release process is mostly automated through the usage of GitHub Actions.

A release should be initiated through the manually triggered GitHub Action **Bump Version**. When triggering a release,
the reference base that should be chosen is the `dev` branch, with a `release` type, `aptos` light-client and the desired release version. The
specified release version should follow [the Semver standard](https://semver.org/).

This action opens a new PR from a branch named `release/aptos-v<release-version>` with `dev` as its base. A commit is
automatically applied to bump all the `Cargo.toml` version of the relevant crates. The developer in charge of the
release should use this branch to make any necessary updates to the codebase and documentation to have the release
ready.

Once all the changes are done, the PR can be squash and merged in `dev`. This will trigger the **Tag release** action
that is charged with the publication of a release and a tag named `v<release-version>`.

## Hotfix process

The hotfix process is quite similar to the release one.

**Bump Version** should also be triggered, but with the desired `release/aptos-v<release-to-fix>` as reference. A PR will be
opened from a branch named `hotfix/aptos-v<hotfix-version>` with the base `release/aptos-v<release-to-fix>`. A commit is automatically
applied to bump all the `Cargo.toml` version of the relevant crates. The developer in charge of the
hotfix should use this branch to make any necessary updates to the codebase and documentation to have the hotfix
ready.

Once all the changes are done, the PR can be squash and merged in `release/<release-to-fix>`. This will trigger the
**Tag release** action that is charged with the publication of a release and a tag named `v<hotfix-version>`.

Finally, the developer will also need to port the changes made to `dev` so that they are reflected on the latest
development stage of the Light Client.

