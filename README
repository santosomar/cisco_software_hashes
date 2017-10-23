# Cisco Software Hashes
The Bulk Hash file provides a mechanism to re-verify images downloaded from www.cisco.com.
Cisco now provides a Secure Hash Algorithm (SHA) 512 bits (SHA512) checksum to validate downloaded images on www.cisco.com.
This newer SHA512 hash value is generated on all software images, creating a unique output that is more secure than the MD5 algorithm.

Cisco is providing both the MD5 and SHA512 hashes for all the images made available to customers in a ".csv" file. The compressed ".csv" file is digitally signed by Cisco. Cisco provides a X.509 certificate for validating the contents of the Bulk Hash File. This end-entity certificate is chained to Cisco SubCA and Root certificate. Authenticity of X.509 certificate chain is validated prior to ".csv" file signature verification.

Within the Bulk Hash File archive that you can download below, you will find:

* Compressed Bulk Hash File
* X.509 certificate
* Signature file
* Verification script
* Readme

## How Can I Use It?
The SHA512 hash value of each file on Cisco.com is contained in the .csv file that you can download.
Generate a hash value for the Cisco downloaded images that you have in your network.

Make sure that there is an exact match between the hash values you have generated on your network images and a hash value in the ".csv" Bulk Hash file.
You can also download the bulk file at: https://www.cisco.com/c/en/us/about/trust-center/downloads.html

## Zip Content:
1. BulkHash.tar: 
Cisco provided image for which signature is to be verified.

2. BULKHASH-CCO_RELEASE.cer: 
Cisco signed x.509 end-entity certificate containing public key that can be used to 
verify the signature. This certificate is chained to Cisco root posted on 
http://www.cisco.com/security/pki/certs/crcam2.cer

3. BulkHash.tar.signature: 
Signature generated for the image.

4. cisco_x509_verify_release.py : 
Signature verification program. After downloading image, 
its digital signature, and the x.509 certificate, this program can be 
used to verify the 3-tier x.509 certificate chain and signature. Certificate
chain validation is done by verifying the authenticity of end-entity 
certificate using Cisco's SubCA and root CA certificate. Then this authentic
end-entity certificate is used to verify the signature.

## Requirements:

1. Python 2.7.4 or later
2. OpenSSL

## How to run signature verification program:

Example:
```
python cisco_x509_verify_release.py -e BULKHASH-CCO_RELEASE.cer -i BulkHash.tar -s BulkHash.tar.signature -v dgst -sha512
```

### Expected output:
```
Downloading CA certificate from http://www.cisco.com/security/pki/certs/crcam2.cer ...
Successfully downloaded and verified crcam2.cer.
Downloading SubCA certificate from http://www.cisco.com/security/pki/certs/innerspace.cer ...
Successfully downloaded and verified innerspace.cer.
Successfully verified root, subca and end-entity certificate chain.
Successfully verified the signature of BulkHash.tar using BULKHASH-CCO_RELEASE.cer
```
    
