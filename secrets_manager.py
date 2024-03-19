import boto3
from botocore.exceptions import ClientError

class SecretsManager:
    def __init__(self, region_name='us-west-2'):
        self.session = boto3.session.Session()
        self.client = self.session.client(
            service_name='secretsmanager',
            region_name=region_name
        )


    def get_secret(self, secret_name):
        try:
            # Retrieve the secret value
            response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print("The requested secret " + secret_name + " was not found")
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                print("The request was invalid due to:", e)
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                print("The request had invalid params:", e)
            else:
                print("An error occurred:", e)
            return None
        else:
            # Depending on whether the secret is a string or binary, one of these fields will be populated
            if 'SecretString' in response:
                return response['SecretString']
            else:
                # In this example, we assume the secret is base64-encoded binary data.
                # Secrets Manager does not return plaintext secrets, only a SecretBinary field containing a
                # base64-encoded binary representation of the secret value.
                return response['SecretBinary']
