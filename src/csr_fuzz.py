#!/usr/bin/env python3
# coding: utf-8

import sys, os, argparse, subprocess, random, copy, shutil, binascii

# openSSL lib used to generate CSRs
from OpenSSL import crypto

# ASN1 lib used for modifcating CSRs with illegal values
import asn1
import hashlib

# debug
import code
import base64
from utilities import *
from der import *

VERSION = "1.0"

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

# configuration
DESTINATION_FOLDER = "./fuzzed_csrs"
NB_TO_GENERATE = 1
CA_PEM = None
CA_KEY = None

# default, non fuzzed values
COUNTRY  = "FR"
STATE    = "IDF"
LOCALITY = "Montigny"
ORG      = "Oppida"
UNIT 	 = "CESTI"
CN       = "Oppida!"
EMAIL    = "cesti@oppida.fr"
PASSWORD = "oppida"
COMPANY  = "Oppida"

# openssl prompts
OPENSSL_COUNTRY  = "Country Name .*:"
OPENSSL_STATE    = "State or Province Name .*:"
OPENSSL_LOCALITY = "Locality Name .*:"
OPENSSL_ORG      = "Organization Name .*:"
OPENSSL_UNIT     = "Organizational Unit Name .*:"
OPENSSL_CN       = "Common Name .*:"
OPENSSL_EMAIL    = "Email Address .*:"
OPENSSL_PASSWORD = "A challenge password .*:"
OPENSSL_COMPANY  = "An optional company name .*:"

DEFAULT_FIELDS = {
	"C" : COUNTRY,
	"ST": STATE,
	"L" : LOCALITY,
	"O" : ORG,
	"OU": UNIT,
	"CN": CN,
	"emailAddress": EMAIL
}

ASN1_OID_C  = "2.5.4.6"
ASN1_OID_ST = "2.5.4.8"
ASN1_OID_L  = "2.5.4.7"
ASN1_OID_O  = "2.5.4.10"
ASN1_OID_OU = "2.5.4.11"
ASN1_OID_CN = "2.5.4.3"
ASN1_OID_EMAIL = "1.2.840.113549.1.9.1"


ASN1_OIDs = {
	"C" : ASN1_OID_C,
	"ST": ASN1_OID_ST,
	"L" : ASN1_OID_L,
	"O" : ASN1_OID_O,
	"OU": ASN1_OID_OU,
	"CN": ASN1_OID_CN,
	"emailAddress": ASN1_OID_EMAIL
}

MUTATION_RANDOMIZE_VALUE 	= "rand_value"
MUTATION_RANDOMIZE_OID   	= "rand_oid"
MUTATION_DUPLICATE_OBJECT 	= "duplicate_object"
MUTATION_DELETE_OBJECT    	= "delete_object"

MUTATIONS = [
	MUTATION_RANDOMIZE_VALUE, 
	MUTATION_RANDOMIZE_OID,
	MUTATION_DUPLICATE_OBJECT, 
	MUTATION_DELETE_OBJECT
]

def print_config():
	print("===========================================")
	print("Configuration:                   ")
	print("[+] Output directory: %s         " % DESTINATION_FOLDER)
	print("[+] Number of mutations for <randomize value> and <randomize OID> : %d         " % NB_TO_GENERATE)
	print("===========================================")

def init(args):
	global DESTINATION_FOLDER, NB_TO_GENERATE, CA_PEM, CA_KEY
	if args.o is not None:
		DESTINATION_FOLDER = args.o
	if args.n is not None:
		NB_TO_GENERATE = int(args.n)
	if args.pem is not None:
		CA_PEM = args.pem
	if args.key is not None:
		CA_KEY = args.key
	print_config()

#------------------------------------------
#
#  Wrappers around python OpenSSL
#
#------------------------------------------

# key_type: TYPE_RSA or TYPE_DSA
# key_bits: 2048 or 3072
def openssl_create_keypair(key_type, key_bits):
	pkey = crypto.PKey()
	pkey.generate_key(key_type, key_bits)
	f = open('CA.key','wb')
	f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
	f.close()
	return pkey

def openssl_gen_csr(public_key, digest="sha256", fields=DEFAULT_FIELDS):
	csr = crypto.X509Req()
	subj = csr.get_subject()	
	for (key, value) in fields.items():
		setattr(subj, key, value)
	csr.set_pubkey(public_key)
	csr.sign(public_key, digest)
	return csr

def openssl_load_csr(buffer):
	return crypto.load_certificate_request(crypto.FILETYPE_ASN1, buffer)

def openssl_export_csr(csr, name):
	f = open(name, 'w')
	f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode('utf-8'))
	f.close()

# create a ca from which the cetificates will be signed
# key_type: TYPE_RSA or TYPE_DSA
# key_bits: 2048 or 3072
def create_ca(key_type, key_bits, serial, notBefore, notAfter):
	CAkey = openssl_create_keypair(key_type, key_bits)
	CAreq = openssl_gen_csr(CAkey)
	CAcert = create_certificate(CAreq, CAreq, CAkey, serial, notBefore, notAfter) # self-signed 10 years
	# open('CA.key', 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, CAkey))
	open('CA.pem', 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, CAcert))

	return CAcert, CAkey

# create a certificate from a csr req
def create_certificate(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="sha256"):
	"""
	Generate a certificate given a certificate request.

	Arguments: req        - Certificate reqeust to use
	         issuerCert - The certificate of the issuer
	         issuerKey  - The private key of the issuer
	         serial     - Serial number for the certificate
	         notBefore  - Timestamp (relative to now) when the certificate
	                      starts being valid
	         notAfter   - Timestamp (relative to now) when the certificate
	                      stops being valid
	         digest     - Digest method to use for signing, default is sha256
	Returns:   The signed certificate in an X509 object
	"""
	cert = crypto.X509()
	cert.set_serial_number(serial)
	cert.gmtime_adj_notBefore(notBefore)
	cert.gmtime_adj_notAfter(notAfter)
	cert.set_issuer(issuerCert.get_subject())
	cert.set_subject(req.get_subject())
	cert.set_pubkey(req.get_pubkey())
	cert.sign(issuerKey, digest)
	return cert

#------------------------------------------
#
#  Raw CSR parsing and manipulation
#
#------------------------------------------

# export without using openSSL - allows to bypass some verifications performed by openSSL
def export_csr(csr, name):
	f = open(name, 'w')
	f.write('-----BEGIN CERTIFICATE REQUEST-----\n')
	f.write(base64.b64encode(csr.encode()).decode('utf-8'))
	f.write('\n-----END CERTIFICATE REQUEST-----\n')	
	f.close()

# manually sign CSR body and update signature - allows to bypass some verifications performed by openSSL
def sign_csr(csr, pk, digest="sha256"):
	# retrieve the DER encoding of the CSR body
	csr_body = csr.children[0]
	der_encoding = csr_body.encode()
	# compute the signature of the (hash of the) body
	sig = crypto.sign(pk, der_encoding, digest)
	csr.children[2].value = b'\x00' + sig

def decode_csr(decoder):
	result = []
	while not decoder.eof():
		tag = decoder.peek()
		if tag.typ == asn1.Types.Primitive:
			# leaf
			tag, value = decoder.read()
			result.append(DER_Tag(tag, value))
		elif tag.typ == asn1.Types.Constructed:
			# list of nodes
			node = DER_Tag(tag)
			decoder.enter()
			node.children += decode_csr(decoder)
			decoder.leave()
			# update parent
			for child in node.children: child.parent = node
			result.append(node)
	return result

def read_csr(path):
	b = open(path, 'r').read()
	b = b.replace('-----BEGIN CERTIFICATE REQUEST-----\n','')
	b = b.replace('\n-----END CERTIFICATE REQUEST-----\n','')
	decoder = asn1.Decoder()
	decoder.start(base64.b64decode(b))
	return decode_csr(decoder)[0]

# we want to change a value based on the OID
# the structure is as follows
# SEQUENCE:
#   OBJECT_node: OID
#   VALUE_node : value
# we parse until we find a sequence with the correct OID, then we change [value]
def change_value(csr, oid, new_value):
	if len(csr.children) > 0:
		if csr.tag.nr == asn1.Numbers.Sequence:
			oid_found = False
			for child in csr.children:
				if oid_found:
					child.value = new_value
					child.fuzzed = True
					return True
				if child.value == oid:
					oid_found = True
					continue
				if change_value(child, oid, new_value): return True
			return False
		else:
			for child in csr.children:
				if change_value(child, oid, new_value): return True
			return False
	return False

# browse the structure until we find a node corresponding to the OID, then replace it by new_oid
def change_oid(csr, oid, new_oid):
	if len(csr.children) > 0:
		if csr.tag.nr == asn1.Numbers.Sequence:
			for child in csr.children:
				if child.value == oid:
					child.fuzzed = True
					child.value = new_oid
					return True
				if change_oid(child, oid, new_oid): return True
			return False
		else:
			for child in csr.children:
				if change_oid(child, oid, new_oid): return True
			return False
	return False

# browse the structure until we find a node corresponding to the OID, then duplicate it
def duplicate_csr_object(csr, oid):
	if len(csr.children) > 0:
		if csr.tag.nr == asn1.Numbers.Sequence:
			for child in csr.children:
				if child.value == oid:
					csr.parent.children.append(copy.copy(csr))
					return True
				if duplicate_csr_object(child, oid): return True
			return False
		else:
			for child in csr.children:
				if duplicate_csr_object(child, oid): return True
			return False
	return False

# browse the structure until we find a node corresponding to the OID, then delete it
# CSR format: 
# SET 			<--- (2) we remove this node
#	SEQUENCE
#		OID     <--- (1) we find this OID
#		VALUE
def delete_csr_object(csr, oid):
	if len(csr.children) > 0:
		if csr.tag.nr == asn1.Numbers.Sequence:
			delete_child = False
			for child in csr.children:
				if child.value == oid:
					delete_child = True
					break
				if delete_csr_object(child, oid): return True
			if delete_child:
				csr.parent.parent.children.remove(csr.parent)
			return False
		else:
			for child in csr.children:
				if delete_csr_object(child, oid): return True
			return False
	return False

#------------------------------------------
#
#  Generation of malicious CSRs
#
#------------------------------------------

def generate_malicious_csr(reference_name, name, pk, modifs, digest="sha256", sign=True):
	info("Generating %s" % name)
	csr = read_csr(reference_name)
	for (oid, new_value) in modifs:
		change_value(csr, oid, new_value)
	modified_csr = openssl_load_csr(csr.encode())
	if sign: modified_csr.sign(pk, digest)
	openssl_export_csr(modified_csr, name)

	return modified_csr


def generate_malicious_cert_from_csr(modified_csr, name, CAcert, CAkey):
	cert_from_csr = create_certificate(modified_csr, CAcert, CAkey, 1, 0, 60*60*24*365*10)
	f = open(name, 'wb')
	f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_from_csr))
	info('Generating ' + name)
	f.close()


def generate_empty_csr(reference_name, name, pk, digest="sha256", sign=True):
	info("Generating %s" % name)
	csr = read_csr(reference_name)
	for oid in ASN1_OIDs.values():
		delete_csr_object(csr, oid)
	modified_csr = openssl_load_csr(csr.encode())
	if sign: modified_csr.sign(pk, digest)
	openssl_export_csr(modified_csr, name)

	return modified_csr

# generate malicious CSRs by setting the CN field to malicious values
def generate_malicious_csrs(pk, CAcert, CAkey):
	# check output directory
	info("Generating malicious CSRs ...")
	dest = DESTINATION_FOLDER + "/malicious_csrs"
	if not os.path.exists(dest):
		info("Destination folder does not exist: create it.")
		os.mkdir(dest)
	else:
		warning("Destination folder exists, CSRs will be stored in existing folder.")

	# generate a default, valid CSR that will then be modified for each test case
	csr = openssl_gen_csr(pk)
	reference_name = dest+"/reference.csr"
	info("Exporting reference CSR to %s" % reference_name)
	openssl_export_csr(csr, reference_name)
	
	# generate malicious CSRs
	try:
		# long string
		name = "long_string"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, (1024*"A").encode("utf-8"))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# command injection*
		cmd_inj = "Hello`ls`World".encode("utf-8")
		name = "cmd_inj"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, cmd_inj)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# command injection*
		cmd_inj2 = "`whoami`".encode("utf-8")
		name = "cmd_inj2"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, cmd_inj2)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# command injection*
		cmd_inj3 = "$(id)".encode("utf-8")
		name = "cmd_inj3"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, cmd_inj3)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# command injection*
		cmd_inj4 = "|whoami|".encode("utf-8")
		name = "cmd_inj4"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, cmd_inj4)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# command injection*
		cmd_inj5 = "&&id;".encode("utf-8")
		name = "cmd_inj5"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, cmd_inj5)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)


		# null byte
		name = "nullbyte"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, bytes([0x4f, 0x70, 0x70, 0x00, 0x69, 0x64, 0x61]))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# visibility
		visibility = "<font size=0>invisible</font>".encode("utf-8")
		name = "visibility"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, visibility)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# format string 1
		name = "format_string1"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, "Oppida%s%s%s%s%s%s%s%s%s%s%s%s".encode('utf-8'))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# format string 2
		name = "format_string2"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, "Oppida%x.%x".encode('utf-8'))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# crlf
		name = "crlf"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, "Oppida\r\nUser".encode('utf-8'))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# XSS
		xss = "<script>alert('XSS')</script>".encode("utf-8")
		name ="xss"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, xss)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# XSS 2
		name = "xss2"
		xss2 = "<body onload=alert('XSS')>".encode("utf-8")
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, xss2)])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# invalid signature
		name = "invalid_signature"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, "Invalid Signature".encode('utf-8'))], sign=False)
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)
		
		# emoji
		name = "emoji"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, [(ASN1_OID_CN, "🚂🚃🚃💨🐱‍🏍".encode('utf-8'))])
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)
		
		# all subject fields empty
		empty_value  = "".encode('utf-8')
		empty_fields = [
			(ASN1_OID_C  , empty_value),
			(ASN1_OID_ST , empty_value),
			(ASN1_OID_L  , empty_value),
			(ASN1_OID_O  , empty_value),
			(ASN1_OID_OU , empty_value),
			(ASN1_OID_CN , empty_value),
			(ASN1_OID_EMAIL, empty_value)
		]
		name = "empty_fields"
		modified_csr = generate_malicious_csr(reference_name, dest+"/"+name+".csr", pk, empty_fields)
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)

		# all subject fields deleted
		name = "empty_subject"
		modified_csr = generate_empty_csr(reference_name, dest+"/"+name+".csr", pk)
		generate_malicious_cert_from_csr(modified_csr, dest+"/"+name+".crt", CAcert, CAkey)


	except Exception as e:
		error(str(e))
		return False

	success("Generated all malicious CSRs")
	return True


#------------------------------------------
#
#  Generation of fuzzed CSRs
#
#------------------------------------------

def randomize_value(csr, oid):
	new_value = os.urandom(random.randrange(0, 256))
	info("... mutation: randomize value with byte array of size %d" % len(new_value))
	change_value(csr, oid, new_value)

def randomize_oid(csr, oid):
	new_oid = os.urandom(random.randrange(0, 32))
	info("... mutation: randomize OID %s with byte array of size %d" % (str(oid), len(new_oid)))
	change_oid(csr, oid, new_oid)

def duplicate_object(csr, oid):
	info("... mutation: duplicate OID %s" % str(oid))
	duplicate_csr_object(csr, oid)

def delete_object(csr, oid):
	info("... mutation: delete OID %s" % str(oid))
	delete_csr_object(csr, oid)

def apply_mutation(csr, oid, mutation):
	if mutation == MUTATION_RANDOMIZE_VALUE:
		randomize_value(csr, oid)
	elif mutation == MUTATION_RANDOMIZE_OID:
		randomize_oid(csr, oid)
	elif mutation == MUTATION_DUPLICATE_OBJECT:
		duplicate_object(csr, oid)
	elif mutation == MUTATION_DELETE_OBJECT:
		delete_object(csr, oid)	
	else:
		error("Invalid mutation type")
	
def fuzz_csr_field(ref_csr_name, field_to_fuzz, mutation, pk, digest="sha256"):
	csr = read_csr(ref_csr_name)
	oid = ASN1_OIDs[field_to_fuzz]
	apply_mutation(csr, oid, mutation)
	sign_csr(csr, pk, digest)
	return csr

def generate_fuzzed_csrs(pk, CAcert, CAkey):
	info("Generating with %d mutations ..." % NB_TO_GENERATE)

	if not os.path.exists(DESTINATION_FOLDER):
		info("Destination folder does not exist: create it.")
	else:
		warning("Destination folder exists: it will be overwritten")
		shutil.rmtree(DESTINATION_FOLDER)

	os.mkdir(DESTINATION_FOLDER)

	# generate a default, valid CSR that will be mutated for each test case
	csr = openssl_gen_csr(pk)
	reference_name = DESTINATION_FOLDER+"/fuzzing_ref.csr"
	info("Exporting reference CSR to %s" % reference_name)
	openssl_export_csr(csr, reference_name)

	try: 
		# generate the required number of fuzzed CSRs
		nb = 1
		for field_to_fuzz in ASN1_OIDs.keys():
			for mutation in MUTATIONS:
				to_generate = NB_TO_GENERATE if mutation in [MUTATION_RANDOMIZE_OID, MUTATION_RANDOMIZE_VALUE] else 1
				for i in range(to_generate):
					name = DESTINATION_FOLDER+"/%03d_%s_%s" % (nb, field_to_fuzz, mutation)
					info("Generating %s" % name)
					digest="sha256"
					fuzzed = fuzz_csr_field(reference_name, field_to_fuzz, mutation, pk, digest)
					# Pour raison étrange, certains certificats renvoient une erreur sur le openssl_load_csr(fuzzed.encode()). 
					# J'ai rajouté un try except pour que ce ne soit pas bloquant, mais quelques .crt ne sont pas créés (les "delete_object" par exemple).
					try:
						modified_csr = openssl_load_csr(fuzzed.encode())
						generate_malicious_cert_from_csr(modified_csr, name+".crt", CAcert, CAkey)
					except:
						warning('Could not generate %s.crt. Skipping this ".crt".' % name)

					export_csr(fuzzed, name + '.csr')
					success("Generated fuzzed CSR in %s" % name)
					nb += 1

	except Exception as e:
		error(str(e))
		return False

	return True


def main():
	parser = argparse.ArgumentParser(description='CSR fuzzer v%s: generation of malicious/fuzzed Certificate Signing Requests and their associated CRT files.' % VERSION)
	parser.add_argument('-o', action='store', metavar='output', help='Generation path (defaults to %s).' % DESTINATION_FOLDER)
	parser.add_argument('-n', action='store', metavar='number', help='Number of mutations for <randomize value> and <randomize OID> (defaults to %d)' % NB_TO_GENERATE)
	parser.add_argument('-pem', action='store', metavar='CA pem', help='Path to CA certificate (.pem)')
	parser.add_argument('-key', action='store', metavar='CA key', help='Path to CA private key (.key)')
	args = parser.parse_args()
	init(args)

	# generate a new RSA 3072 key pair to sign all malicious csrs
	info("Generating key pair")
	pk = openssl_create_keypair(TYPE_RSA, 3072)
	info("Generated key pair: %s" % str(pk))
	
	if CA_PEM is None or CA_KEY is None:
		# generate a new CA 
		CAcert,CAkey = create_ca(TYPE_RSA, 3072, 1, 0, 60*60*24*365*10)	# self-signed 10 years
	else:
		CAcert = crypto.load_certificate(crypto.FILETYPE_PEM, open(CA_PEM, 'rb').read())
		CAkey  = crypto.load_privatekey(crypto.FILETYPE_PEM, open(CA_KEY, 'rb').read())

	ok  = generate_fuzzed_csrs(pk, CAcert, CAkey)	
	ok &= generate_malicious_csrs(pk, CAcert, CAkey)
	if ok:
		success("Generation complete without error.")
	else:
		warning("Generation complete with error(s).")

if __name__ == '__main__':
	main()