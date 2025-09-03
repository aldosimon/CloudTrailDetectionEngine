import boto3
import gzip
import json
import os
import logging

# Configure the logger
logger = logging.getLogger()
logger.setLevel(logging.INFO) # Set to logging.DEBUG to see debug messages as well

# Initialize SNS client (initialized globally for potential re-use across invocations)
sns = boto3.client('sns')
sns_topic_arn = os.environ.get('SnsArn') # Set this environment variable!

def fetch_s3(bucket, key):
    """
    Downloads and decompresses a gzipped file from S3.

    Args:
        bucket (str): The name of the S3 bucket.
        key (str): The key of the file in the S3 bucket.

    Returns:
        bytes: The decompressed content of the file, or None on error.
    """
    s3 = boto3.client('s3')
    logger.debug(f"Attempting to fetch file from bucket '{bucket}' with key '{key}'.")

    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        compressed_content = response['Body'].read()
        logger.debug(f"Successfully downloaded {len(compressed_content)} bytes from S3.")

        try:
            content = gzip.decompress(compressed_content)
            logger.debug(f"Successfully decompressed file. Size: {len(content)} bytes.")
            return content
        except Exception as e:
            logger.warning(f"Error decompressing file '{key}': {e}")
            return None
    except Exception as e:
        logger.error(f"Error fetching file from S3 for '{key}': {e}")
        return None

def matching_rule(record):
    """
    Checks if a CloudTrail event record matches predefined security criteria.

    Args:
        record (dict): A single CloudTrail event record.

    Returns:
        bool: True if the event matches the criteria, False otherwise.
    """
    event_name = record.get('eventName')
    # Hardcoded criteria for matching
    criteria_events = ['StopLogging', 'UpdateTrail', 'ConsoleLogin', 'DeleteTrail']

    if event_name in criteria_events:
        logger.info(f"Found matching CloudTrail event: '{event_name}'.")
        return True
    else:
        return False

def process_s3_records(s3_content):
    """
    Processes the decompressed S3 content (expected to be JSON CloudTrail logs)
    by identifying matching events and returning them.

    Args:
        s3_content (bytes): The decompressed content from S3.

    Returns:
        list: A list of CloudTrail event records that match the predefined rules.
              Returns an empty list if no matches or on error.
    """
    if not s3_content:
        logger.warning("No content provided to process_s3_records.")
        return []

    try:
        # CloudTrail logs are typically UTF-8 encoded JSON
        log_data = json.loads(s3_content.decode('utf-8'))
        records = log_data.get('Records', [])
        logger.debug(f"Successfully loaded JSON data. Found {len(records)} records.")

        matching_events = []
        for record in records:
            if matching_rule(record):
                matching_events.append(record)
        return matching_events
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON content: {e}")
        return []
    except Exception as e:
        logger.error(f"An unexpected error occurred during processing S3 records: {e}")
        return []

def send_sns(record):
    """
    Sends a single CloudTrail event record to an SNS topic.

    Args:
        record (dict): The CloudTrail event record to send.
    """
    global sns_topic_arn
    if not sns_topic_arn:
        logger.critical("SNS_TOPIC_ARN is not set. Cannot send to SNS.")
        return

    try:
        message = json.dumps(record, default=str)
        subject = f"CloudTrail Event: {record.get('eventName', 'Unknown')}"
        logger.debug(f"Attempting to send message to SNS topic '{sns_topic_arn}'. Subject: '{subject}', Message: '{message[:50]}...'")
        response = sns.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject=subject
        )
        logger.info(f"Event sent to SNS. Message ID: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending event to SNS: {e}")

def lambda_handler(event, context):
    """
    AWS Lambda function entry point for processing S3 events containing CloudTrail logs.
    It fetches, processes, and sends matching security events to an SNS topic.
    """
    logger.info(f"Lambda function invoked with event: {event}")
    logger.debug(f"Lambda context: {context}")

    try:
        records_in_event = event.get('Records', [])
        if not records_in_event:
            logger.warning("No S3 records found in the event.")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No S3 records to process.'})
            }

        first_s3_record = records_in_event[0]
        bucket = first_s3_record.get('s3', {}).get('bucket', {}).get('name')
        key = first_s3_record.get('s3', {}).get('object', {}).get('key')

        if not bucket or not key:
            logger.error(f"Could not extract bucket name or key from the S3 event: {event}")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid S3 event format.'})
            }

        logger.info(f"Processing CloudTrail log file: '{key}' from bucket: '{bucket}'")

        # 1. Fetch S3 content
        s3_content = fetch_s3(bucket, key)
        if s3_content is None:
            logger.error(f"Failed to fetch content from S3 for '{key}'. Aborting processing.")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': f'Failed to retrieve S3 content: {key}'})
            }

        # 2. Process S3 content to find matching records
        matching_cloudtrail_records = process_s3_records(s3_content)

        # 3. Send matching records to SNS
        if matching_cloudtrail_records:
            for record in matching_cloudtrail_records:
                logger.info(f"Sending matched event to SNS: {record.get('eventName', 'N/A')} (ID: {record.get('eventID', 'N/A')})")
                send_sns(record)
            logger.info(f"Successfully processed '{key}'. Sent {len(matching_cloudtrail_records)} matching events to SNS.")
        else:
            logger.info(f"No matching events found in '{key}'.")

        return {
            'statusCode': 200,
            'body': json.dumps({'message': f'Successfully processed CloudTrail log: {key}. Sent {len(matching_cloudtrail_records)} matching events to SNS.'})
        }

    except Exception as e:
        logger.critical(f"An unhandled exception occurred during processing: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error processing S3 event: {e}'})
        }