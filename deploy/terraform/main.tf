// Main Terraform configuration: S3 buckets, SNS topic + subscription, IAM role/policy for Lambda,
// Lambda function packaged from local `lambda/` folder, and S3 -> Lambda notification.

locals {
  lambda_archive = "${path.module}/lambda/index.zip"
}

resource "aws_s3_bucket" "sigma_signature" {
  bucket = var.sigma_bucket_name

  tags = {
    Name = "sigma-signature"
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = var.cloudtrail_bucket_name

  tags = {
    Name = "cloudtrail"
  }
}

resource "aws_sns_topic" "notify_admin" {
  name = "notify-admin-topic"
}

resource "aws_sns_topic_subscription" "admin_email" {
  topic_arn = aws_sns_topic.notify_admin.arn
  protocol  = "email"
  endpoint  = var.admin_email
}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda_exec_role_${replace(var.lambda_name, "-", "_")}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy_${replace(var.lambda_name, "-", "_")}"
  description = "Policy to allow Lambda to read S3 buckets, write logs, and publish to SNS"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "S3Access",
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.sigma_signature.arn,
          "${aws_s3_bucket.sigma_signature.arn}/*",
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
      },
      {
        Sid    = "CloudWatchLogs",
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid      = "SNSPublish",
        Effect   = "Allow",
        Action   = ["sns:Publish"],
        Resource = aws_sns_topic.notify_admin.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = local.lambda_archive
}

resource "aws_lambda_function" "cloudtrail_trigger" {
  filename      = data.archive_file.lambda_zip.output_path
  function_name = var.lambda_name
  role          = aws_iam_role.lambda_exec.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.10"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.notify_admin.arn
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudtrail_trigger.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.cloudtrail.arn
}

resource "aws_s3_bucket_notification" "cloudtrail_lambda" {
  bucket = aws_s3_bucket.cloudtrail.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.cloudtrail_trigger.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}

/*
output "sigma_signature_bucket" {
  value = aws_s3_bucket.sigma_signature.bucket
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail.bucket
}

output "sns_topic_arn" {
  value = aws_sns_topic.notify_admin.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.cloudtrail_trigger.function_name
}
*/