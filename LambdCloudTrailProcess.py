import boto3
import gzip
import json
import os

def lambda_handler(event, context):
    """
    This Lambda function processes CloudTrail logs from S3, identifies specific events,
    and logs them.

    Args:
        event (dict): The event data passed by the S3 trigger.
        context (object): The Lambda function context.

    Returns:
        None
    """
    s3 = boto3.client('s3')
    log_group_name = os.environ.get('LOG_GROUP_NAME', '/aws/lambda/your-lambda-function-name')  # Default, change if needed
    logs = boto3.client('logs')

    try:
        # Get the S3 bucket and object key from the event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']

        print(f"Processing CloudTrail log file: {key} from bucket: {bucket}") # added print

        # Download the CloudTrail log file from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        compressed_content = response['Body'].read()

        # Decompress the log file (CloudTrail logs are typically gzipped)
        try:
            content = gzip.decompress(compressed_content).decode('utf-8')
        except Exception as e:
            print(f"Error decompressing log file: {e}")
            # Send error log to CloudWatch Logs
            logs.put_log_events(
                logGroupName=log_group_name,
                logEvents=[
                    {
                        'timestamp': int(round(time.time() * 1000)),
                        'message': f"Error decompressing log file: {e}"
                    },
                ]
            )
            return  # Important: Exit if decompression fails

        # Load the JSON content of the log file
        try:
            log_data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
             # Send error log to CloudWatch Logs
            logs.put_log_events(
                logGroupName=log_group_name,
                logEvents=[
                    {
                        'timestamp': int(round(time.time() * 1000)),
                        'message': f"Error decoding JSON: {e}"
                    },
                ]
            )
            return # Exit if json load fails

        # Process each event in the log file
        for record in log_data['Records']:
            event_name = record['eventName']
            if event_name in ['StopLogging', 'UpdateTrail', 'DeleteTrail']:
                # Log the event to CloudWatch Logs
                print(f"Found matching event: {event_name}")
                try:
                    logs.put_log_events(
                        logGroupName=log_group_name,
                        logEvents=[
                            {
                                'timestamp': int(record['eventTime'].timestamp() * 1000),  # Convert datetime to milliseconds
                                'message': json.dumps(record)  # Convert the entire record to a JSON string
                            },
                        ]
                    )
                except Exception as e:
                    print(f"Error sending log to CloudWatch: {e}")

    except Exception as e:
        print(f"Error processing S3 event: {e}")
        # Send error log to CloudWatch Logs
        logs.put_log_events(
                logGroupName=log_group_name,
                logEvents=[
                    {
                        'timestamp': int(round(time.time() * 1000)),
                        'message': f"Error processing S3 event: {e}"
                    },
                ]
            )
        return # Exit
