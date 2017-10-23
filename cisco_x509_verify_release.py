#!/router/bin/python
# Author: sto-image-signing-dev@cisco.com
#
# Copyright (c) 2015-2016 by cisco Systems, Inc.
# All rights reserved.
#---------------------------------------------------------------------------

# This script is used to verify three tier certificate
# chain and verify file signature using openssl.

import sys
import os
import argparse
import commands
import urllib
import hashlib

#constants
PROG_NAME = "cisco_x509_verify_release.py"

#menu constants
MENU_MAIN_DESC = "Image signing application. This will verify the certificate chain"\
                 " and image signature using openssl commands."
CISCO_X509_VERIFY_REL_VERSION = "1.0"

#color constants
FAIL = '\033[91m'       #red
WARNING = '\033[93m'    #orange
HEADER = '\033[95m'     #pink

OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'     #using for debugs
OKWHITE = '\033[97m'

ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


rel_root_cert_url = "http://www.cisco.com/security/pki/certs/crcam2.cer"
rel_subca_cert_url = "http://www.cisco.com/security/pki/certs/innerspace.cer"
rel_root_cert_sha256 = "cd85167b3935e27bcc3b0f5fa24c8457882d0bb994f88269a7f72829d957eae9"
rel_subca_cert_sha256 = "f31e6b39dae6996fdf2045a61be8bd3688a86dfd06c46ce71af4af239f411c56"


"""
LOG() function prints string in requested color on terminal
"""
def LOG(color, string):
    if(sys.platform.find("linux") == -1):
        if(color == FAIL):
            print "Error Log: "
            print string
        else:
            print string
    else:
        if(color == FAIL):
            print color + "Error log: " + string + ENDC
        else:
            print color + string + ENDC


"""
cleanup() function deletes any newly created temp files.
"""
def cleanup(args):
    #if root/subcaca cert is provided by user, then dont delete the file.
    #otherwise, its a downloaded file which needs to be cleaned up.
    if(os.path.exists(root_cert)):
        os.remove(root_cert)
    if(os.path.exists(subca_cert)):
        os.remove(subca_cert)
    if os.path.exists("ee_pubkey.pem"):
        os.remove("ee_pubkey.pem")


"""
url_exists() function checks if provided url link is valid or not
"""
def url_exists(url):
    if(urllib.urlopen(url).code >= 400):
        return False
    else:
        return True


"""
verify_cert_sha256() function computes the sha256sum of certificate
and compares with the expected value.
"""
def verify_cert_sha256(cert_name, expected_sha256):
    cert_sha256 = hashlib.sha256(open(cert_name, 'rb').read()).hexdigest()
    if(cert_sha256 == expected_sha256):
        return True
    else:
        LOG(FAIL, "Computed sha256sum of "+cert_name+" = "+cert_sha256)
        LOG(FAIL, "Expected sha256sum of "+cert_name+" = "+expected_sha256)
        return False


"""
convert_cert_to_pem() function converts DER formatted cert
to PEM format.
"""
def convert_cert_to_pem(cert_name):
    with open(cert_name, 'r') as f:
        first_line = f.readline()
        if(first_line.find("-----BEGIN CERTIFICATE-----") == -1):
            cmd = "openssl x509 -inform der -in {} -out {}".format(cert_name, cert_name)
            status, out = commands.getstatusoutput(cmd)

            if(out.find("error") != -1):
                LOG(FAIL, "Failed to convert "+cert_name+"from DER to PEM.")
                LOG(FAIL, out)
                return False

    return True


"""
download_cert() function downloads a certificate from provided
url link if its a valid url.
"""
def download_cert(cert_url):
    cert_name = "N/A"
    if(url_exists(cert_url)):
        cert_name = cert_url.split('/')[-1]
        urllib.urlretrieve(cert_url, cert_name)
    else:
        LOG(FAIL, "Download certificate failed.")
    return cert_name


"""
verify_3tier_cert_chain() function verifies the 3 tier cert chain
"""
def verify_3tier_cert_chain(ee_cert):
    #verify root and subca certificate
    cmd = "openssl verify -CAfile {} {}".format(root_cert, subca_cert)
    status, out = commands.getstatusoutput(cmd)

    if(out.find("error") != -1 or status != 0):
        LOG(FAIL, "Verification of root and subca certificate failed.")
        LOG(FAIL, out)
        return -1

    #verify end-entity certificate chain
    cmd = "openssl verify -CAfile {} -untrusted {} {}".format(root_cert, subca_cert, ee_cert)
    status, out = commands.getstatusoutput(cmd)

    if(out.find("error") != -1 or status != 0):
        LOG(FAIL, "Failed to verify root, subca and end-entity certificate chain.")
        LOG(FAIL, out)
        return -1
    else:
        LOG(OKGREEN, "Successfully verified root, subca and end-entity certificate chain.")
        return status


"""
fetch_pubkey_from_cert() function retrieves public key from x509
PEM certificate.
"""
def fetch_pubkey_from_cert(cert_name):
    cmd = "openssl x509 -pubkey -noout -in {} > ee_pubkey.pem".format(cert_name)
    status, out = commands.getstatusoutput(cmd)

    if(status != 0):
        LOG(FAIL, "Failed to fetch a public key from x509 PEM certificate")
        LOG(FAIL, out)
    else:
        LOG(OKGREEN, "Successfully fetched a public key from "+cert_name+".")
    
    return status


"""
verify_dgst_signature() function verifies the signature of an image.
"""
def verify_dgst_signature(args):
    if(args.sha256):
        sha_version = "sha256"
    else:
        sha_version = "sha512"

    cmd = "openssl dgst -{} -verify ee_pubkey.pem -signature {} {}".format(sha_version, args.signature, args.image_name)
    status, out = commands.getstatusoutput(cmd)
    
    if(status != 0):
        LOG(FAIL, "Failed to verify dgst signature of "+args.image_name+".")
        LOG(FAIL, out)
    
    return status


"""
verify_smime_signature() function verifies the openssl smime signature of an image.
"""
def verify_smime_signature(args):
    cmd = "openssl smime -verify -binary -in {} -inform PEM -content {} -noverify -nointern -certfile {}".format(args.signature, args.image_name, args.ee_cert)
    status, out = commands.getstatusoutput(cmd)
    
    if(status != 0):
        LOG(FAIL, "Failed to verify smime signature of "+args.image_name+".")
        LOG(FAIL, out)
    
    return status


"""
verify_signature() function verifies the image signature using either smime or dgst
openssl command.
"""
def verify_signature(args):
    if(args.verify_type == "smime"):
        status = verify_smime_signature(args)
    else:
        status = fetch_pubkey_from_cert(args.ee_cert)
        if(status != 0):
            return 1
        status = verify_dgst_signature(args)
    return status


"""
command_handler() is a handler function 
"""
def command_handler(args):
    #validate and download root certificate
    global root_cert
    LOG(OKGREEN, "Downloading CA certificate from "+rel_root_cert_url+" ...")
    root_cert = download_cert(rel_root_cert_url)
    if(root_cert != "N/A"):
        if(verify_cert_sha256(root_cert, rel_root_cert_sha256)):
            convert_cert_to_pem(root_cert)
            LOG(OKGREEN, "Successfully downloaded and verified "+root_cert+".")
        else:
            cleanup(args)
            return
    else:
        cleanup(args)
        return

    #validate and download SubCA certificate
    global subca_cert
    LOG(OKGREEN, "Downloading SubCA certificate from "+rel_subca_cert_url+" ...")
    subca_cert = download_cert(rel_subca_cert_url)
    if(subca_cert != "N/A"):
        if(verify_cert_sha256(subca_cert, rel_subca_cert_sha256)):
            convert_cert_to_pem(subca_cert)
            LOG(OKGREEN, "Successfully downloaded and verified "+subca_cert+".")
        else:
            cleanup(args)
            return
    else:
        cleanup(args)
        return
    
    #verify 3 tier certificate chain
    status = verify_3tier_cert_chain(args.ee_cert)

    if(status != 0):
        cleanup(args)
        return

    #verify signature
    status = verify_signature(args)
    if(status == 0):
        LOG(OKGREEN, "Successfully verified the signature of "+args.image_name+" using "+args.ee_cert)

    cleanup(args)
    return


"""
verify_parser_options() is used to verify input arguments.
It returns error if any required argument is missing.
"""
def verify_parser_options(args):
    if(args.image_name != None):
        if(not os.path.exists(args.image_name)):
            LOG(FAIL, "'"+args.image_name+"' does not exist")
            return 1
    if(args.signature != None):
        if(not os.path.exists(args.signature)):
            LOG(FAIL, "'"+args.signature+"' does not exist")
            return 1
    if(args.ee_cert != None):
        if(not os.path.exists(args.ee_cert)):
            LOG(FAIL, "'"+args.ee_cert+"' does not exist")
            return 1

    return 0


"""
arg_parser() is used to setup command line options.
"""
def arg_parser():
    #setup main parser
    pmain = argparse.ArgumentParser(prog=PROG_NAME, description=MENU_MAIN_DESC)
    
    #verion arguemnt
    pmain.add_argument("-V", "--version", action='version', version='%(prog)s (version ' + CISCO_X509_VERIFY_REL_VERSION + ')')

    #certificate argument
    pmain.add_argument("-e", "--ee_cert", metavar = "<ee_cert_name>", dest = "ee_cert", required = True, help = "Local path to End-entity certificate in PEM format")

    #signature file argument
    pmain.add_argument("-s", "--signature", metavar = "<signature_file>", dest = "signature", required = True, help = "Filename containing image signature")

    #input image argument
    pmain.add_argument("-i", "--image_name", metavar = "<image_name>", dest = "image_name", required = True, help = "Image name")
    
    #openssl verify type argument
    pmain.add_argument("-v", "--verify_type", choices = ['dgst', 'smime'], default = ['dgst'], dest = "verify_type", required = False, help = "Verify type: dgst|smime")

    #hashing algorithm argument
    group_input = pmain.add_mutually_exclusive_group(required=False)
    group_input.add_argument("-sha256", action = "store_true", dest = "sha256", help = "Using sha256 hashing algorithm (required only for 'dgst')")
    group_input.add_argument("-sha512", action = "store_true", dest = "sha512", help = "Using sha512 hashing algorithm (required only for 'dgst')")
    
    pmain.set_defaults(func=command_handler)

    return pmain


"""
main function for STO image signing script
to verify cert chain and bulk hash signatures.
"""
def main():
    #setup console menu parsers
    pmain = arg_parser()

    #parse args
    args = pmain.parse_args()

    #manually verify the input arguments
    if(verify_parser_options(args) != 0):
        return 1

    #invoke appropriate handler function
    args.func(args)

    return 0


"""
Starting point
"""
if __name__ == "__main__":
    sys.exit(main())

