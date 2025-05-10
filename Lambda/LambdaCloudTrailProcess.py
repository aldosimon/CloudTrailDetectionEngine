import boto3
import gzip
import json
import os
import logging

# Configure the logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set to logging.DEBUG to see debug messages as well

# Initialize SNS client
sns = boto3.client('sns')
sns_topic_arn = os.environ.get('SnsArn')  #  Set this environment variable!

def fetch_cloudtrail_log(bucket, key):
    """
    Downloads and decompresses a CloudTrail log file from S3.

    Args:
        bucket (str): The name of the S3 bucket.
        key (str): The key of the CloudTrail log file in the S3 bucket.

    Returns:
        dict: The JSON data of the CloudTrail log file, or None on error.
    """
    s3 = boto3.client('s3')
    logger.debug(f"Attempting to fetch CloudTrail log from bucket '{bucket}' with key '{key}'.")

    try:
        # Download the CloudTrail log file from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        compressed_content = response['Body'].read()
        logger.debug(f"Successfully downloaded {len(compressed_content)} bytes from S3.")

        # Decompress the log file (CloudTrail logs are typically gzipped)
        try:
            content = gzip.decompress(compressed_content).decode('utf-8')
            logger.debug(f"Successfully decompressed log file. Size: {len(content)} bytes.")
        except Exception as e:
            logger.warning(f"Error decompressing log file '{key}': {e}")
            return None  # Indicate failure

        # Load the JSON content of the log file
        try:
            log_data = json.loads(content)
            logger.debug(f"Successfully loaded JSON data. Found {len(log_data.get('Records', []))} records.")
            return log_data
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON for file '{key}': {e}")
            return None  # Indicate failure
    except Exception as e:
        logger.error(f"Error fetching CloudTrail log from S3 for '{key}': {e}")
        return None  # Indicate failure

def process_cloudtrail_event(record):
    """
    Processes a single CloudTrail event record and checks for matching events.

    Args:
        record (dict): A single CloudTrail event record.

    Returns:
        bool: True if the event matches the criteria, False otherwise.
    """
    event_name = record.get('eventName')
    logger.debug(f"Processing event: '{event_name}' with event ID: '{record.get('eventID', 'N/A')}'")
    if event_name in ['StopLogging', 'UpdateTrail', 'ConsoleLogin','DeleteTrail']:
        logger.info(f"Found matching CloudTrail event: '{event_name}'.")
        return True
    else:
        return False

def send_to_sns(record):
    """
    Sends a CloudTrail event record to an SNS topic.

    Args:
        record (dict): The CloudTrail event record to send.
    """
    global sns_topic_arn  # Use the global variable
    if not sns_topic_arn:
        logger.critical("SNS_TOPIC_ARN is not set. Cannot send to SNS.")
        return  # IMPORTANT:  Exit if the environment variable is not set

    try:
        message = json.dumps(record, default=str)
        subject = f"CloudTrail Event: {record.get('eventName', 'Unknown')}"
        logger.debug(f"Attempting to send message to SNS topic '{sns_topic_arn}'. Subject: '{subject}', Message: '{message[:50]}...'") # Log first 50 chars of message
        response = sns.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject=subject
        )
        logger.info(f"Event sent to SNS. Message ID: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending event to SNS: {e}")

def log_error(message):
    """
    Logs an error message.

    Args:
        message (str): The error message to log.
    """
    logger.error(message)



def lambda_handler(event, context):
    """
    This Lambda function processes CloudTrail logs from S3, identifies specific events,
    and sends them to an SNS topic. It logs information, warnings, errors, and critical issues to CloudWatch Logs.

    Args:
        event (dict): The event data passed by the S3 trigger.
        context (object): The Lambda function context.

    Returns:
        dict:  Status code indicating success or failure
    """
    logger.info(f"Lambda function invoked with event: {event}")
    logger.debug(f"Lambda context: {context}")

    try:
        # Get the S3 bucket and object key from the event
        records = event.get('Records', [])
        if not records:
            logger.warning("No S3 records found in the event.")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No S3 records to process.'})
            }

        first_record = records[0]
        s3_info = first_record.get('s3', {})
        bucket_info = s3_info.get('bucket', {})
        object_info = s3_info.get('object', {})

        bucket = bucket_info.get('name')
        key = object_info.get('key')

        if not bucket or not key:
            logger.error(f"Could not extract bucket name or key from the S3 event: {event}")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid S3 event format.'})
            }

        logger.info(f"Processing CloudTrail log file: '{key}' from bucket: '{bucket}'")

        # Fetch the CloudTrail log data from S3
        log_data = fetch_cloudtrail_log(bucket, key)
        if log_data is None:
            logger.error(f"Failed to fetch or process CloudTrail log from S3. Exiting processing for '{key}'.")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': f'Failed to retrieve or process CloudTrail logs: {key}'})
            }  # Return an error response

        # Process each event in the log file
        processed_count = 0
        matching_count = 0
        for record in log_data.get('Records', []):
            processed_count += 1
            if process_cloudtrail_event(record):
                matching_count += 1
                # Send the event to SNS
                logger.info(f"Found matching event: '{record.get('eventName')}' (Event ID: '{record.get('eventID', 'N/A')}'). Sending to SNS.")
                send_to_sns(record)

        logger.info(f"Successfully processed {processed_count} records from '{key}'. Found {matching_count} matching events.")
        return {  #  Successful response
            'statusCode': 200,
            'body': json.dumps({'message': f'Successfully processed CloudTrail log: {key}. Found {matching_count} matching events.'})
        }

    except Exception as e:
        logger.critical(f"An unhandled exception occurred during processing: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Error processing S3 event: {e}'})
        }  # Return an error response
