# Contributing

This document covers instructions and expectations when contributing to the project.

Questions and feature requests should be discussed in [GitHub Discussions](https://github.com/netbirdio/kubernetes-operator/discussions) while bugs should be reported as an [issue](https://github.com/netbirdio/kubernetes-operator/issues).

## Acceptance Policy

This project is issue first driven. Meaning that any new PR should be linked to either a bug or feature issue. Any PR that has not been discussed first in an issue or with a maintainer can be closed without reason.

All PRs are expected to be tested locally before they are submitted. PRs from non maintainers need approval to run GitHub actions meaning that you cannot submit a PR to run tests. If all steps covered in the development section passes then the CI should also pass.

To keep commit history clean, keep PRs to consist of a single commit. Once the PR is ready to review squash the commit history if there are multiple commits.

## Development

The linter enforces any coding standards that are required.

```bash
make lint
```

Documentation and CRDs need to be generated after making changes to the API structs.

```bash
make generate
```

Unit tests use an in memory Kubernetes cluster to test controller functionality.

```bash
make test-unit
```

The e2e tests cover the installation and upgrade steps, along with testing certain functionality.

```bash
make test-e2e
```

You can run the operator locally against any cluster that you have access to. Running the operator like this means however that webhooks will not work.

```bash
NB_API_KEY=${API_KEY} make run
```

## Releases

This project uses semantic versioning for releases. Each new release with new features should receive a new minor version. Release branches are to be able to backport bug fixes and cut patch releases without including new features. This makes the release process stable as it does not force releasing changes that may depend on other systems. Every new minor release tag should be done in a branch with the name format `release/v0.7.x`, any backported changes should be done to this branch and then the commit in the branch should be tagged with a new patch version.

Follow these steps to release a new version.

1. If this is a new minor release create a new release branch from the last commit to the main branch.
2. Create a [new release](https://github.com/netbirdio/kubernetes-operator/releases/new) in GitHub.
3. Create a new tag with the version of the release and make sure that the target branch is the release branch.
4. Set the title of the release to be the same as the release version.
5. Click the "Generate release notes" button so that release notes are added.
6. Publish the release.

Once this is done a [release action](https://github.com/netbirdio/kubernetes-operator/blob/main/.github/release.yaml) should be started automatically that publishes a new [operator image](https://github.com/netbirdio/kubernetes-operator/pkgs/container/netbird-operator) and [Helm chart](https://github.com/netbirdio/kubernetes-operator/pkgs/container/helm-charts%2Fnetbird-operator).
