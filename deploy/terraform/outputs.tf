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
