import coba

class baseDES(object):
	def __init__(self, pad=None):
		if pad:
			pad = self.guardAgainstUnicode(pad)
		self.blockSize = 8

	def setKey(self, key):
		key = self.guardAgainstUnicode(key)
		self.key = key

	def getKey(self):
		return self.key

	def handlePadding(self, data):
		if len(data) % self.blockSize == 0:
			return data
		else:
			add_padding = len(data) % self.blockSize

			for x in range(add_padding, 8):
				data += chr(0)
		return data

	def guardAgainstUnicode(self, data):
		if isinstance(data,unicode):
			raise ValueError("Harus Byte bukan lainnya")
		
		return data

class DES_Chiper(baseDES):

	ENCRYPT =	0x00
	DECRYPT =	0x01
	
	def __init__(self, key, pad=None):
		if len(key) != 8:
			raise ValueError("Ukuran Key DES harus 8 bytes!")
		baseDES.__init__(self, pad)
		self.keySize = 8
		self.L = []
		self.R = []
		self.Kn = [[0]*48]*16
		self.final = []

		self.setKey(key)

	def setKey(self, key):
		baseDES.setKey(self, key)
		self.createSubKeys()

	def Permutasi(self, table, block):
		return list(map(lambda x:block[x], table))

	def createSubKeys(self):
		key = self.Permutasi(coba.PC1, coba.toBit(self.getKey()))
		i = 0

		self.L = key[:28]
		self.R = key[28:]

		while i<16:
			j = 0

			while j<coba.leftRotate[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]

				j+=1

			self.Kn[i] = self.Permutasi(coba.PC2, self.L+self.R)
			i+=1

	def desCrypt(self, block, crypt_type):
		block = self.Permutasi(coba.IP, block)
		self.L = block[:32]
		self.R = block[32:]

		#ini salah des.ENCRYPT
		if crypt_type == DES_Chiper.ENCRYPT:
			iterasi = 0
			adjustment = 1
		else:
			iterasi = 15
			adjustment = -1

		i = 0

		while i<16:
			#copy R[i-1] nanti akan jadi L[i]
			tempR = self.R[:]

			#Permutasi R[i-1] jadi R[i]
			self.R = self.Permutasi(coba.Expansion, self.R)

			#Exclusive OR R[i-1] dengan K[i]
			self.R = list(map(lambda x, y: x^y, self.R, self.Kn[iterasi]))
			B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]

			#Permutasi B[1] - B[8] pakek SBox
			j = 0
			Bn = [0]*32
			pos = 0

			while j<8:
				m = (B[j][0] *2) + B[j][5]
				n = (B[j][1] *8) + (B[j][2] *4) + (B[j][3] *2) + B[j][4]

				v = coba.sBox[j][(m << 4) + n]

				Bn[pos] = (v&8) >> 3
				Bn[pos+1] = (v&4) >> 2
				Bn[pos+2] = (v&2) >> 1
				Bn[pos+3] = v&1

				pos+=4
				j+=1

			#Permutasi dengan PBox
			self.R = self.Permutasi(coba.PBox, Bn)

			self.R = list(map(lambda x, y: x^y, self.R, self.L))
			self.L = tempR

			i+=1
			iterasi+=adjustment

		self.final = self.Permutasi(coba.InversIP, self.R+self.L)

		return self.final

	def crypt(self, data, crypt_type):
		if not data:
			 return ''

		i = 0
		dict = {}
		result = []

		while i < len(data):
			block = coba.toBit(data[i:i+8])
			process_block = self.desCrypt(block, crypt_type)

			result.append(coba.toString(process_block))
			i+=8
		return ''.join(result)

	def encrypt(self, data):
		data = self.guardAgainstUnicode(data)
		data = self.handlePadding(data)
		return self.crypt(data, DES_Chiper.ENCRYPT)

	def decrypt(self, data):
		data = self.guardAgainstUnicode(data)
		return self.crypt(data, DES_Chiper.DECRYPT)
		#return data

"""def des_jalan():
	k = DES_Chiper("desCrypt")
	data = "DES encryption algorithm coba"
	print "key: ", k.getKey()
	print "Data: ", data
	d = k.encrypt(data)
	print "Encryption data: ", d
	print 

if __name__ == '__main__':
	des_jalan()"""







