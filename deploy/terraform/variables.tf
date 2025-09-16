variable "admin_email" {
  description = "Admin email for SNS subscription."
  type        = string
}

variable "sigma_bucket_name" {
  description = "Name for the sigma-signature S3 bucket."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name for the CloudTrail S3 bucket."
  type        = string
}

variable "lambda_name" {
  description = "Name for the Lambda function."
  type        = string
}

variable "aws_region" {
  description = "AWS region to deploy resources."
  type        = string
}
