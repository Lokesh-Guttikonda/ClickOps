# Sample web tier used by the offline demo (scripts/demo_offline.py).
#
# The scenario: during an incident someone opened the AWS Console and edited the
# HTTPS rule of this security group from 443 to 8443 (ModifySecurityGroupRules).
# examples/drifted_plan.json is the `terraform show -json` output of the plan that
# detected it, and examples/cloudtrail_events.json is the CloudTrail history.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC that hosts the web tier."
  type        = string
  default     = "vpc-0a1b2c3d4e5f67890"
}

# Public web tier. HTTPS is the only port meant to be reachable from the internet;
# plain HTTP exists only to redirect to HTTPS.
resource "aws_security_group" "web" {
  name        = "web-tier-sg"
  description = "Ingress for the public web tier"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from the internet (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "web-tier-sg"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t3.micro"
  subnet_id              = "subnet-0123456789abcdef0"
  vpc_security_group_ids = [aws_security_group.web.id]

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name        = "web-01"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
