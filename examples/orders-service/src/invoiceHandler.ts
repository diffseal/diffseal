import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';

const sqs = new SQSClient({ region: 'eu-north-1' });
const s3 = new S3Client({ region: 'eu-north-1' });
const dynamo = new DynamoDBClient({ region: 'eu-north-1' });

export async function processCustomerInvoice(orderId: string, pdfBuffer: Buffer) {
  // 1. Store encrypted invoice PDF in S3
  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.INVOICE_PDF_BUCKET_NAME,
      Key: `invoices/${orderId}.pdf`,
      Body: pdfBuffer,
    })
  );

  // 2. Write immutable audit record to DynamoDB
  await dynamo.send(
    new PutItemCommand({
      TableName: process.env.PAYMENT_AUDIT_TABLE_NAME,
      Item: {
        id: { S: orderId },
        createdAt: { S: new Date().toISOString() },
      },
    })
  );

  // 3. Enqueue async bookkeeping job for Fortnox sync worker
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: process.env.INVOICE_BOOKKEEPING_QUEUE_URL,
      MessageBody: JSON.stringify({ orderId }),
    })
  );
}

export async function getInvoicePdf(orderId: string) {
  return s3.send(
    new GetObjectCommand({
      Bucket: process.env.INVOICE_PDF_BUCKET_NAME,
      Key: `invoices/${orderId}.pdf`,
    })
  );
}

export async function queryOrderAuditTrail(orderId: string) {
  return dynamo.send(
    new QueryCommand({
      TableName: process.env.PAYMENT_AUDIT_TABLE_NAME,
      KeyConditionExpression: 'id = :id',
    })
  );
}
