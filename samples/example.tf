# samples/example.tf
provider "aws" {
  region = "us-west-2"
}

# TF-001: Public S3 Bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-example"
  acl    = "public-read" # Violates TF-001

  versioning {
    enabled = false # Violates TF-002
  }
}

# TF-003: Security Group Allowing All
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-12345" # Placeholder

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Violates TF-003
  }
}

# TF-004: RDS without Multi-AZ
resource "aws_db_instance" "default" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz123" # Violates TF-REGEX-001
  parameter_group_name = "default.mysql5.7"
  multi_az             = false # Violates TF-004 (if production context)
  skip_final_snapshot  = true
}

# TF-006: IAM Policy with *
resource "aws_iam_policy" "test_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*" # Violates TF-006
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

# TF-005: EC2 Instance using default SG (implicitly, if no vpc_security_group_ids)
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1d0" # Placeholder AMI
  instance_type = "t3.micro"
  # vpc_security_group_ids = [aws_security_group.allow_all.id] # If this line was missing/empty, it might use default SG
  # For this example, let's assume it's missing the explicit SG association check
}
