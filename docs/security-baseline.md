# Security baseline (the 10 guardrails)

Every rule is deterministic, side-effect-free and evaluated against the **normalized** resource model, so one rule
covers Terraform and CloudFormation. A rule returns *evidence* strings; the engine turns them into one finding per
(rule, resource). Values that cannot be determined statically are **never flagged**.

Query the live catalogue any time: `GET /api/v1/rules`.

## Scoring weights

Critical **30** · High **20** · Medium **10**. See [risk-scoring.md](risk-scoring.md).

## AWS

### AWS-S3-001 — S3 bucket is publicly accessible · 🔴 Critical (30)
* **Applies to:** `aws_s3_bucket` (+ `aws_s3_bucket_acl`, `aws_s3_bucket_policy`), `AWS::S3::Bucket` (+ `AWS::S3::BucketPolicy`).
* **Fires when:** an ACL is `public-read`, `public-read-write` or `authenticated-read`; **or** a bucket-policy statement
  with `Effect: Allow` and `Principal: "*"` (or `{AWS: "*"}`) has **no `Condition`**.
* **Does not fire:** private ACL, principals scoped to ARNs, `Deny` statements, statements with a `Condition`
  (a condition may restrict the audience, so the rule does not guess).
* **Evidence:** `ACL is "public-read" (set by aws_s3_bucket_acl.x)` · `Bucket policy statement "PublicRead" allows Principal "*"`.
* **Note:** for Terraform `jsonencode(...)` bodies containing unresolved references, a text heuristic is used and the evidence
  is labelled `[text heuristic]`.
* **Remediation:** private ACL, remove `*` principals, enable Block Public Access, serve public content via CloudFront + OAC.

### AWS-S3-002 — S3 Block Public Access missing or disabled · 🟠 High (20)
* **Fires when:** no public-access-block is linked to the bucket, or any of `block_public_acls`, `block_public_policy`,
  `ignore_public_acls`, `restrict_public_buckets` is false (Terraform: an omitted flag defaults to false).
* **Evidence:** `No public access block is configured for this bucket` / `Public access block setting(s) disabled: …`.
* **Caveat:** account-level Block Public Access is invisible to a file scan, so this may be noisy where it is enforced centrally.

### AWS-S3-003 — S3 bucket has no explicit default encryption · 🟡 Medium (10)
* **Fires when:** no `aws_s3_bucket_server_side_encryption_configuration` / inline block (Terraform) or no `BucketEncryption` (CloudFormation).

### AWS-EC2-001 — SSH (22) open to the internet · 🔴 Critical (30)
* **Fires when:** a **TCP** ingress rule whose port range covers 22 has source `0.0.0.0/0` or `::/0` (any of `cidr_blocks`,
  `ipv6_cidr_blocks`, `cidr_ipv4`, `CidrIp`, `CidrIpv6`). Rules that open *all* ports are reported by AWS-EC2-003 instead (no double counting).
* **Evidence:** `Ingress tcp/22 (covers SSH port 22) is open to 0.0.0.0/0` (one line per offending rule; still **one** finding per group).
* **Resolves:** Terraform `variable` defaults (a `var.admin_cidr` defaulting to `0.0.0.0/0` is flagged).

### AWS-EC2-002 — RDP (3389) open to the internet · 🔴 Critical (30)
Same logic as AWS-EC2-001 for port 3389.

### AWS-EC2-003 — Security group allows all traffic from the internet · 🟠 High (20)
* **Fires when:** protocol `-1`/`all`, or ports 0–65535, from `0.0.0.0/0` or `::/0`.
* Applies to `aws_security_group`, `aws_security_group_rule` (ingress only), `aws_vpc_security_group_ingress_rule`,
  `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`.

### AWS-RDS-001 — Database instance is publicly accessible · 🟠 High (20)
* **Fires when:** `publicly_accessible = true` (`aws_db_instance`) / `PubliclyAccessible: true` (`AWS::RDS::DBInstance`).

### AWS-ENC-001 — Storage is not encrypted at rest · 🟡 Medium (10)
* **Applies to:** `aws_db_instance`, `aws_rds_cluster`, `aws_ebs_volume`, `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::EC2::Volume`.
* **Fires when:** the encryption flag is false **or omitted** (the provider default is unencrypted).
* **Does not fire:** unresolved values, or resources that inherit encryption (snapshot / replica / cluster member).
* **Caveat:** account-level default EBS encryption is not visible to a file scan.

## Azure (Terraform `azurerm_*` only)

### AZ-STOR-001 — Azure storage allows anonymous public access · 🟠 High (20)
* **Fires when:** `azurerm_storage_account` sets `allow_nested_items_to_be_public` (or legacy `allow_blob_public_access`) to **true**,
  or `azurerm_storage_container` has `container_access_type` `blob` or `container`. Only an *explicit* true is flagged (provider defaults differ by version).

### AZ-NSG-001 — NSG exposes SSH/RDP to the internet · 🔴 Critical (30)
* **Applies to:** inline `security_rule` blocks of `azurerm_network_security_group` and standalone `azurerm_network_security_rule`.
* **Fires when:** direction Inbound, access Allow, protocol Tcp or `*`, source `*` / `Internet` / `0.0.0.0/0` / `any`, and the destination
  port(s) (`"22"`, `"20-30"`, `"*"`, lists) cover 22 or 3389.
* **Limitation:** rule **priority is not evaluated** — a higher-priority Deny for the same port is not taken into account.

## Fixtures and how each rule is proven

| Fixture | Findings |
|---|---|
| `samples/terraform/vulnerable.tf` | 10 (S3-001 ×2, S3-002, S3-003, EC2-001, EC2-002, EC2-003, RDS-001, ENC-001 ×2) |
| `samples/cloudformation/vulnerable.json` | 8 |
| `samples/cloudformation/vulnerable.yaml` | 3 (S3-001 via BucketPolicy, EC2-001, ENC-001) |
| `samples/azure/vulnerable.tf` | 4 (AZ-STOR-001 ×2, AZ-NSG-001 ×2) |
| `samples/terraform/safe.tf`, `cloudformation/safe.json`, `cloudformation/safe.yaml`, `azure/safe.tf` | 0 each |

`tests/unit/test_rules.py` asserts the exact `(rule, resource)` multiset for every vulnerable sample, zero findings for every safe sample,
and per-rule edge cases (ranges, IPv6, all-ports, conditions, deny rules, unknown values) using the real parser and engine — nothing mocked.

## Adding a rule

1. Subclass `GuardrailRule` in `rules/aws.py` or `rules/azure.py` with a complete `Rule` metadata block.
2. Add it to `BASELINE` in `rules/registry.py`.
3. Add a vulnerable and a safe fixture and tests. The catalogue test enforces unique IDs and complete metadata.
