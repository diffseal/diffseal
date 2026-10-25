variable "environment" {
  type = string
}

locals {
  name = "orders-${var.environment}"
}

resource "aws_s3_bucket" "invoices" {
  bucket = "${local.name}-invoice-pdfs"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_sqs_queue" "bookkeeping_dlq" {
  name = "${local.name}-bookkeeping-dlq"
}

resource "aws_sqs_queue" "bookkeeping" {
  name = "${local.name}-bookkeeping"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.bookkeeping_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_dynamodb_table" "payment_audit" {
  name                        = "${local.name}-payment-audit"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.invoices.arn}/*"]
  }
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.bookkeeping.arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.payment_audit.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "invoices" {
  function_name = "${local.name}-invoices"
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"
  image_uri     = "123456789012.dkr.ecr.eu-north-1.amazonaws.com/orders:latest"
  memory_size   = 512

  environment {
    variables = {
      INVOICE_PDF_BUCKET_NAME       = aws_s3_bucket.invoices.id
      INVOICE_BOOKKEEPING_QUEUE_URL = aws_sqs_queue.bookkeeping.url
      PAYMENT_AUDIT_TABLE_NAME      = aws_dynamodb_table.payment_audit.name
    }
  }
}
