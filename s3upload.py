#!/usr/bin/env python3
import logging
import sys
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError


def upload_to_aws(local_file, bucket, s3_file):
    s3 = boto3.client('s3' )
    args={}
    if local_file.endswith('.txt'):
        args={'ContentType': "text/plain"}

    try:
        s3.upload_file(local_file, bucket, s3_file,ExtraArgs=args)
        print("Upload Successful")
        return True
    except FileNotFoundError:
        print("The file was not found")
        return False
    except NoCredentialsError:
        print("Credentials not available")
        return False

localfile = sys.argv[1]
bucketname = sys.argv[2]
s3filename = sys.argv[3]
uploaded = upload_to_aws(localfile,bucketname,s3filename)

