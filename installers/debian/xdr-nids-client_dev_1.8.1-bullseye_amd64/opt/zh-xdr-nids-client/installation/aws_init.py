import boto3
import json
import urllib.request

def retrieve_credentials():
    '''
    This function retrieves credentials from the aws secrets manager.
    '''
    instance_data = json.loads(urllib.request.urlopen('http://169.254.169.254/latest/dynamic/instance-identity/document').read().decode())
    secret_manager_client = boto3.client('secretsmanager', region_name = instance_data["region"])

    zerohack_secret = secret_manager_client.get_secret_value(SecretId = "ZerohackAccessKeys")
    zerohack_private_key = secret_manager_client.get_secret_value(SecretId = "ZerohackPrivateKey")
    zerohack_cert_data = secret_manager_client.get_secret_value(SecretId = "ZerohackCertData")

    zerohack_keys = json.loads(zerohack_secret["SecretString"])

    zerohack_access_key_id = zerohack_keys["access_key_id"]
    zerohack_secret_access_key = zerohack_keys["secret_access_key"]
    company_name = zerohack_keys["company_name"]
    aws_default_region = zerohack_keys["default_region"]

    # Writing the certificates.
    with open("/etc/zh-xdr-nids-client/pki/client.cert.pem", "w") as file:
        file.write(zerohack_cert_data['SecretString'])

    with open("/etc/zh-xdr-nids-client/pki/client.key.pem", "w") as file:
        file.write(zerohack_private_key['SecretString'])

    # Writing the init.config file.
    with open("/etc/zh-xdr-nids-client/configs/active/init.config", "w") as file:
        file.write(f"machine_index_name={company_name}\n")
        file.write(f"access_key_id={zerohack_access_key_id}\n")
        file.write(f"secret_access_key={zerohack_secret_access_key}\n")
        file.write(f"aws_default_region={aws_default_region}\n")
        file.write(f"operating_env=aws\n")

    return None

def main():
    retrieve_credentials()

if __name__ == "__main__":
    main()
