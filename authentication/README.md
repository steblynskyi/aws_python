# Authentication and IAM Permissions

This directory documents the AWS Identity and Access Management (IAM) permissions required to run the AWS security audit toolkit bundled in this repository. The toolkit queries AWS APIs across multiple services to gather configuration and compliance data. To succeed, the IAM identity that executes the audit must be allowed to call read-only "Describe", "List", and "Get" operations for each covered service.

## Services and actions

The toolkit queries the following AWS services and requires the associated IAM actions:

- **Amazon S3** &ndash; `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`
- **AWS Certificate Manager (ACM)** &ndash; `acm:ListCertificates`, `acm:DescribeCertificate`
- **Amazon EC2** &ndash; `ec2:DescribeInstances`, `ec2:DescribeVolumes`
- **Amazon VPC** &ndash; `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeVpnConnections`
- **Amazon RDS** &ndash; `rds:DescribeDBInstances`
- **AWS Key Management Service (KMS)** &ndash; `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:ListAliases`
- **AWS Identity and Access Management (IAM)** &ndash; `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`
- **Amazon Route 53** &ndash; `route53:ListHostedZones`, `route53:GetDNSSEC`
- **AWS Systems Manager (SSM)** &ndash; `ssm:DescribeInstanceInformation`
- **Amazon Elastic Container Service (ECS)** &ndash; `ecs:ListClusters`, `ecs:DescribeClusters`
- **Amazon Elastic Kubernetes Service (EKS)** &ndash; `eks:ListClusters`, `eks:DescribeCluster`

All actions are read-only and scoped to `Resource: "*"`. This allows the audit to inventory resources across the AWS account without changing their state.

## Example IAM policy

Attach the IAM policy defined in [`iam_policy.json`](./iam_policy.json) to the role or user that runs the toolkit. This grants the minimal set of permissions necessary for the audit to succeed while preserving a read-only posture.

You can attach the policy directly to an IAM role used by an automation pipeline, or apply it to a dedicated IAM user if running the audit manually. Consider applying service control policies or session tagging to further restrict access as needed in your environment.
