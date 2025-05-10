import pytest
import json
import gzip
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

# Assuming the function to be tested is in a file named 'LambdaCloudTrailProcess.py'
from Lambda.LambdaCloudTrailProcess import fetch_cloudtrail_log

def create_mock_s3_client(mock_get_object_response=None, should_raise_client_error=False):
    """Creates a mock S3 client."""
    mock_s3 = MagicMock()
    mock_client = MagicMock()
    if should_raise_client_error:
        mock_client.get_object.side_effect = ClientError({'Error': {'Code': 'NoSuchKey', 'Message': 'Not Found'}}, 'GetObject')
    else:
        mock_client.get_object.return_value = mock_get_object_response
    mock_s3.client.return_value = mock_client
    return mock_s3, mock_client

def create_gzipped_json_data(data):
    """Creates gzipped JSON data."""
    json_bytes = json.dumps(data).encode('utf-8')
    gzipped_data = gzip.compress(json_bytes)
    return gzipped_data

def test_fetch_cloudtrail_log_success():
    """Tests successful fetching and processing of a CloudTrail log."""
    mock_log_data = {"Records": [{"eventVersion": "1.0"}]}
    gzipped_data = create_gzipped_json_data(mock_log_data)
    mock_get_object_response = {'Body': MagicMock(read=MagicMock(return_value=gzipped_data))}
    mock_boto3, mock_s3_client = create_mock_s3_client(mock_get_object_response)

    with patch('LambdaCloudTrailProcess.boto3', mock_boto3), patch('LambdaCloudTrailProcess.logger') as mock_logger:
        result = fetch_cloudtrail_log('test-bucket', 'test/log.gz')
        assert result == mock_log_data
        mock_s3_client.get_object.assert_called_once_with(Bucket='test-bucket', Key='test/log.gz')
        mock_logger.debug.assert_any_call("Attempting to fetch CloudTrail log from bucket 'test-bucket' with key 'test/log.gz'.")
        mock_logger.debug.assert_any_call(f"Successfully downloaded {len(gzipped_data)} bytes from S3.")
        mock_logger.debug.assert_any_call(f"Successfully decompressed log file. Size: {len(json.dumps(mock_log_data).encode('utf-8'))} bytes.")
        mock_logger.debug.assert_any_call(f"Successfully loaded JSON data. Found {len(mock_log_data.get('Records', []))} records.")
        mock_logger.warning.assert_not_called()
        mock_logger.error.assert_not_called()

def test_fetch_cloudtrail_log_s3_error():
    """Tests handling of errors during S3 object retrieval."""
    mock_boto3, mock_s3_client = create_mock_s3_client(should_raise_client_error=True)

    with patch('LambdaCloudTrailProcess.boto3', mock_boto3), patch('LambdaCloudTrailProcess.logger') as mock_logger:
        result = fetch_cloudtrail_log('test-bucket', 'nonexistent/log.gz')
        assert result is None
        mock_s3_client.get_object.assert_called_once_with(Bucket='test-bucket', Key='nonexistent/log.gz')
        mock_logger.debug.assert_called_once_with("Attempting to fetch CloudTrail log from bucket 'test-bucket' with key 'nonexistent/log.gz'.")
        mock_logger.error.assert_called_once()
        assert "Error fetching CloudTrail log from S3" in mock_logger.error.call_args[0][0]
        mock_logger.warning.assert_not_called()

def test_fetch_cloudtrail_log_decompression_error():
    """Tests handling of errors during log file decompression."""
    mock_get_object_response = {'Body': MagicMock(read=MagicMock(return_value=b'invalid compressed data'))}
    mock_boto3, mock_s3_client = create_mock_s3_client(mock_get_object_response)

    with patch('LambdaCloudTrailProcess.boto3', mock_boto3), patch('LambdaCloudTrailProcess.logger') as mock_logger:
        result = fetch_cloudtrail_log('test-bucket', 'corrupted/log.gz')
        assert result is None
        mock_s3_client.get_object.assert_called_once_with(Bucket='test-bucket', Key='corrupted/log.gz')
        mock_logger.debug.assert_any_call("Attempting to fetch CloudTrail log from bucket 'test-bucket' with key 'corrupted/log.gz'.")
        mock_logger.debug.assert_any_call(f"Successfully downloaded {len(b'invalid compressed data')} bytes from S3.")
        mock_logger.warning.assert_called_once()
        assert "Error decompressing log file 'corrupted/log.gz'" in mock_logger.warning.call_args[0][0]
        mock_logger.error.assert_not_called()

def test_fetch_cloudtrail_log_json_decode_error():
    """Tests handling of errors during JSON decoding."""
    mock_get_object_response = {'Body': MagicMock(read=MagicMock(return_value=gzip.compress(b'invalid json data')))}
    mock_boto3, mock_s3_client = create_mock_s3_client(mock_get_object_response)

    with patch('LambdaCloudTrailProcess.boto3', mock_boto3), patch('LambdaCloudTrailProcess.logger') as mock_logger:
        result = fetch_cloudtrail_log('test-bucket', 'malformed/log.gz')
        assert result is None
        mock_s3_client.get_object.assert_called_once_with(Bucket='test-bucket', Key='malformed/log.gz')
        mock_logger.debug.assert_any_call("Attempting to fetch CloudTrail log from bucket 'test-bucket' with key 'malformed/log.gz'.")
        mock_logger.debug.assert_any_call(f"Successfully downloaded {len(gzip.compress(b'invalid json data'))} bytes from S3.")
        mock_logger.debug.assert_any_call(f"Successfully decompressed log file. Size: {len(b'invalid json data')} bytes.")
        mock_logger.error.assert_called_once()
        assert "Error decoding JSON for file 'malformed/log.gz'" in mock_logger.error.call_args[0][0]
        mock_logger.warning.assert_not_called()