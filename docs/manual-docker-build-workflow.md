# Manual Docker Build Workflow Reference

The **Manual Docker Build and Push** workflow (`.github/workflows/manual-docker-build.yml`) lets maintainers build a Docker image from any branch, push it to Amazon ECR with a custom version tag, and optionally tag the image as `latest`.

## Required secrets and variables

Set the following repository secrets before running the workflow:

| Name | Required | Description |
| ---- | -------- | ----------- |
| `AWS_REGION` | ✅ | AWS region where your ECR registry is hosted (for example, `us-east-1`). |
| `AWS_ECR_REPOSITORY` | ✅ | Name of the ECR repository that will store the image. |
| `AWS_ROLE_TO_ASSUME` | ➖ | IAM role ARN to assume. Provide this when you prefer role-based authentication. Leave empty if you use access keys instead. |
| `AWS_ACCESS_KEY_ID` | ➖ | Access key ID for an IAM user or temporary credentials. Required when not using `AWS_ROLE_TO_ASSUME`. |
| `AWS_SECRET_ACCESS_KEY` | ➖ | Secret access key paired with `AWS_ACCESS_KEY_ID`. Required when not using `AWS_ROLE_TO_ASSUME`. |
| `AWS_SESSION_TOKEN` | ➖ | Session token for temporary credentials (leave empty for long-lived user keys). Required when your access key pair is session-based, such as from AWS STS. |

> **Tip:** You may store shared, non-sensitive values such as `AWS_REGION` or `AWS_ECR_REPOSITORY` as repository-level variables instead of secrets if you prefer, but secrets ensure the values are encrypted and access-controlled.

## Workflow inputs

When triggering the workflow manually (`Run workflow` button in GitHub UI), provide the following inputs:

- **version_tag** (required): Docker tag to publish (for example, `v1.2.3`).
- **mark_latest** (optional, default `false`): Set to `true` to also push the `latest` tag.
- **source_branch** (required, default `main`): Branch or ref to check out before building the image.

## Who can run the workflow?

Only collaborators with **write access** (or higher) to the repository can trigger `workflow_dispatch` workflows, even in public repositories. Fork owners can run the workflow in their own forks, but they cannot execute it in your repository unless you grant them the required permissions. For more details, see the [GitHub Actions documentation on triggering workflows manually](https://docs.github.com/actions/using-workflows/manually-running-a-workflow).

