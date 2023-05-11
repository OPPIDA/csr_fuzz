# fuzzer for DER encoded data, such as CSRs
import sys, argparse, base64

# ASN1 lib used for modifcating CSRs with illegal values
import asn1

#------------------------------------------
#
#  DER structure
#
#------------------------------------------

encoder = asn1.Encoder()

class DER_Tag():
	def __init__(self, tag=None, value=None):
		self.tag = tag
		self.value = value
		self.length = 0
		self.parent = None
		self.children = []
		self.fuzzed = False

	def pretty(self, indent=0):
		print("%s%s%s" % (indent*" ", self.tag, "" if self.value is None else self.value))
		for child in self.children:
			child.pretty(indent+2)

	def encode_length(self, value):
		l = self.length if self.length != 0 else 0 if value == None else len(value)
		if l < 128:
			return bytes([l])
		else:
			# number of bytes necessary to encode the length
			following_bytes = len(hex(l)[2:])
			if following_bytes % 2 != 0: following_bytes = int(following_bytes/2) + 1
			else: following_bytes = int(following_bytes/2)
			first_byte = 1 << 7 | following_bytes
			# convert length in a sequence of bytes
			next_bytes = [(l & (0xff << pos*8)) >> pos*8 for pos in reversed(range(following_bytes))]
			return bytes([first_byte]) + bytes(next_bytes)			

	def encode_value(self):
		if self.tag.typ == asn1.Types.Constructed:
			v = bytes([])
			for c in self.children:
				v += c.encode()
			return v
		# primitive
		# for fuzzed fields, return the raw bytes
		if self.fuzzed: return self.value 
		if self.tag.nr == asn1.Numbers.IA5String: # not handled by the lib
			return self.value.encode('ascii')
		v = encoder._encode_value(self.tag.nr, self.value)
		return v

	'''
	Encodes the DER structure as bytes

	Note: in case self.length is not 0, the self.length field is used. Otherwise, it is recomputed from value/children
	'''
	def encode(self):
		res = bytes([])
		# first byte 
		# 8 7         6   5 4 3 2 1
		# tag class  P/C  tag number(0-30)
		if self.tag == None:
			return bytes([])
		C = 1 if self.tag.typ == asn1.Types.Constructed else 0
		if self.tag.nr < 32:
			# single byte header, otherwise header has to fit on two bytes 			
			header = [self.tag.cls | C << 5 | self.tag.nr]
		else:
			first_byte = self.tag.cls | C << 5 | 31
			second_byte = 1 << 7 | self.tag.nr
			header = [first_byte, second_byte]
		value  = self.encode_value()
		length = self.encode_length(value)
		return bytes(header) + length + value

def pretty_der_bytes(array, indent=0):
	offset = 0
	while offset < len(array):
		# we have 2 header bytes, then length
		if array[offset] & 0b11111 == 0b11111:
			header = array[offset:offset+2]
			rest = array[offset+2:]
		else:
			header = array[offset:offset+1]
			rest = array[offset+1:]
		len_first_byte = rest[0]	
		if len_first_byte < 0x80: # single length byte
			length = len_first_byte
			length_length = 1
			lb = rest[0:1]
			value = rest[1:1+length]
		else:
			length_bytes = len_first_byte & 0x7f
			length = 0
			lb = rest[0:length_bytes+1]
			for i in range(length_bytes):
				length = length << 8 | rest[1+i]
			length_length = 1 + length_bytes
			value = rest[length_length:length_length+length]
		# we have offsets for header, length, and value
		# we decide if we recurse into value or not
		print("%s" % "."*indent, end="")
		print("".join(["%02X" % b for b in header]), end=" ")					
		print("".join(["%02X" % b for b in lb]), end="")
		print(" (%d)" % length, end="")
		if header[0] & 0x20 == 0x20: # constructed
			print("")
			pretty_der_bytes(value, indent+1)
		else: # primitive
			print(" : "+"".join(["%02X" % b for b in value]))
		offset += len(header) + length_length + len(value)

def print_csr(path):
	b = open(path, 'r').read()
	b = b.replace('-----BEGIN CERTIFICATE REQUEST-----\n','')
	b = b.replace('\n-----END CERTIFICATE REQUEST-----\n','')
	pretty_der_bytes(base64.b64decode(b))

def main():
	parser = argparse.ArgumentParser(description='ASN.1/DER encoding/decoding tool. Uses lib asn1.')
	parser.add_argument('-i', action='store', metavar='raw', help='Prints decoded raw value of the given CSR')
	args = parser.parse_args()
	if args.i is None:
		print("Required: -i <csr_path>")
		sys.exit(0)
	path = args.i
	print_csr(path)

if __name__ == '__main__':
	main()