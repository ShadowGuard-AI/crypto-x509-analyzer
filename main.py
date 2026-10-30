import argparse
import logging
import sys
import time
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="X.509 Certificate Analyzer")
    parser.add_argument("certificate_path", help="Path to the X.509 certificate file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    return parser


def analyze_certificate(cert_path):
    """
    Analyzes an X.509 certificate file for potential vulnerabilities.

    Args:
        cert_path (str): The path to the certificate file.

    Returns:
        True if the certificate was read and analyzed, False if it could
        not be read or parsed. Analysis results go to the log.
    """
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
    except FileNotFoundError:
        logging.error(f"Error: Certificate file not found at {cert_path}")
        return False
    except Exception as e:
        logging.error(f"Error reading certificate file: {e}")
        return False

    try:
        # PEM only. DER input fails here with a clear message rather than
        # being guessed at, because the file gives no reliable signal for
        # which encoding it carries.
        cert = x509.load_pem_x509_certificate(cert_data)
    except ValueError as e:
        logging.error(f"Error loading certificate: {e}.  Ensure it is in PEM format.")
        return False
    except Exception as e:
         logging.error(f"General error loading certificate: {e}")
         return False

    logging.info(f"Analyzing certificate: {cert.subject}")

    # Check certificate validity period
    if cert.not_valid_before_utc > cert.not_valid_after_utc:
        logging.warning("Certificate validity start date is after the end date. This is invalid.")

    if cert.not_valid_before_utc.timestamp() > time.time():
        logging.warning("Certificate is not yet valid.")

    if cert.not_valid_after_utc.timestamp() < time.time():
        logging.warning("Certificate is expired.")

    # Current cryptography releases no longer expose a signature_algorithm
    # object with a name. The OID is the stable identifier, so the weak
    # algorithm check keys off the OIDs for md5WithRSAEncryption,
    # sha1WithRSAEncryption and dsaWithSHA1.
    sig_oid = cert.signature_algorithm_oid.dotted_string
    weak_sig_oids = {"1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.10040.4.3"}
    logging.info(f"Signature Algorithm OID: {sig_oid}")
    if sig_oid in weak_sig_oids:
        logging.warning(f"Weak signature algorithm detected: {sig_oid}")

    # Check key usage extensions
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        logging.info(f"Key Usage: {key_usage}")

    except x509.ExtensionNotFound:
        logging.warning("Key Usage extension is missing. This can be a security risk.")
    except Exception as e:
        logging.error(f"Error reading Key Usage extension: {e}")

    # Check Basic Constraints extension
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        logging.info(f"Basic Constraints: {basic_constraints}")
        if basic_constraints.ca:
            logging.info("Certificate is a CA certificate.")
        else:
            logging.info("Certificate is an end-entity certificate.")
    except x509.ExtensionNotFound:
        logging.info("Basic Constraints extension not found.") # It's not necessarily an error
    except Exception as e:
        logging.error(f"Error reading Basic Constraints extension: {e}")


    # Check Subject Alternative Name (SAN)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        logging.info(f"Subject Alternative Name: {san}")
    except x509.ExtensionNotFound:
        logging.info("Subject Alternative Name extension not found.")  # Not necessarily an error.
    except Exception as e:
        logging.error(f"Error reading Subject Alternative Name extension: {e}")

    # Verify certificate signature. The old verifier() context manager was
    # removed from cryptography, and verify() takes a different argument
    # shape per key family, so dispatch on the public key type. A
    # self-signed certificate verifies against its own key; for a CA issued
    # certificate this checks the signature against the subject key, which
    # is a consistency check, not chain validation.
    try:
        public_key = cert.public_key()
        hash_alg = cert.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hash_alg))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, hash_alg)
        else:
            raise TypeError(f"Unsupported public key type: {type(public_key).__name__}")
        logging.info("Certificate signature is valid.")

    except InvalidSignature:
        logging.error("Certificate signature is invalid.")
    except Exception as e:
        logging.error(f"Error verifying certificate signature: {e}")

    # Check if CA flag is consistent with usage.
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if basic_constraints.ca and not key_usage.key_cert_sign:
            logging.warning("CA certificate missing keyCertSign in KeyUsage extension")

    except x509.ExtensionNotFound:
        pass  # Ignore, some certs don't have these.
    except Exception as e:
        logging.error(f"Error in CA flag consistency check: {e}")

    # Print issuer
    logging.info(f"Issuer: {cert.issuer}")

    #Print subject
    logging.info(f"Subject: {cert.subject}")
    return True



def main():
    """
    Main function to execute the certificate analysis tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    if not analyze_certificate(args.certificate_path):
        sys.exit(1)


if __name__ == "__main__":
    main()