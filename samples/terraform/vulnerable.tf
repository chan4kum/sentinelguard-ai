# SentinelGuard AI sample — VULNERABLE Terraform (intentionally insecure; never applied).
# Expected: 10 findings -> AWS-S3-001 x2, AWS-EC2-001, AWS-EC2-002, AWS-S3-002, AWS-EC2-003,
#                          AWS-RDS-001, AWS-S3-003, AWS-ENC-001 x2

variable "admin_cidr" {
  default = "0.0.0.0/0" # resolved by the parser -> world-open
}

# Public ACL, no public-access-block, no encryption -> AWS-S3-001, AWS-S3-002, AWS-S3-003
resource "aws_s3_bucket" "public_assets" {
  bucket = "acme-public-assets"
  acl    = "public-read"
}

# Locked down otherwise, but the policy grants Principal "*" -> AWS-S3-001 (via linked policy)
resource "aws_s3_bucket" "policy_open" {
  bucket = "acme-policy-open"
}

resource "aws_s3_bucket_public_access_block" "policy_open" {
  bucket                  = aws_s3_bucket.policy_open.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "policy_open" {
  bucket = aws_s3_bucket.policy_open.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "policy_open" {
  bucket = aws_s3_bucket.policy_open.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "arn:aws:s3:::acme-policy-open/*"
    }]
  })
}

# SSH via a variable that defaults to the whole internet -> AWS-EC2-001; RDP over IPv6 -> AWS-EC2-002
resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # public HTTPS is acceptable
  }
}

# All protocols, all ports, from anywhere -> AWS-EC2-003
resource "aws_security_group" "wide_open" {
  name = "wide-open"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Public and unencrypted database -> AWS-RDS-001, AWS-ENC-001
resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
}

# Unencrypted volume -> AWS-ENC-001
resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1a"
  size              = 20
}
