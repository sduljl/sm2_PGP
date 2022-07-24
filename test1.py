from random import SystemRandom
from gmssl import sm2
from base64 import b64encode, b64decode


#定义椭圆曲线
class elliptic_curve:
	def __init__(self, A, B, P, N, Gx, Gy, name):
		self.A = A
		self.B = B
		self.P = P
		self.N = N
		self.Gx = Gx
		self.Gy = Gy
		self.name = name

#初始化类,设置为国密推荐椭圆曲线参数
sm2_class = elliptic_curve(
	name="sm2_class",
	A=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
	B=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
	P=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
	N=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
	Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
	Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
)



def multiply(a, n, N, A, P):
	return curve_exchange(curve_mul(curve_one(a), n, N, A, P), P)


def add(a, b, A, P):
	return curve_exchange(curve_add(curve_one(a), curve_one(b), A, P), P)


def curve_inv(a, n):
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n


def curve_one(Xp_Yp):
	Xp, Yp = Xp_Yp
	return (Xp, Yp, 1)


def curve_exchange(Xp_Yp_Zp, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	z = curve_inv(Zp, P)
	return ((Xp * z**2) % P, (Yp * z**3) % P)


def curve_math(Xp_Yp_Zp, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	if not Yp:
		return (0, 0, 0)
	ysq = (Yp ** 2) % P
	S = (4 * Xp * ysq) % P
	M = (3 * Xp ** 2 + A * Zp ** 4) % P
	nx = (M**2 - 2 * S) % P
	ny = (M * (S - nx) - 8 * ysq ** 2) % P
	nz = (2 * Yp * Zp) % P
	return (nx, ny, nz)


def curve_add(Xp_Yp_Zp, Xq_Yq_Zq, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	Xq, Yq, Zq = Xq_Yq_Zq
	if not Yp:
		return (Xq, Yq, Zq)
	if not Yq:
		return (Xp, Yp, Zp)
	U1 = (Xp * Zq ** 2) % P
	U2 = (Xq * Zp ** 2) % P
	S1 = (Yp * Zq ** 3) % P
	S2 = (Yq * Zp ** 3) % P
	if U1 == U2:
		if S1 != S2:
			return (0, 0, 1)
		return curve_math((Xp, Yp, Zp), A, P)
	H = U2 - U1
	R = S2 - S1
	H2 = (H * H) % P
	H3 = (H * H2) % P
	U1H2 = (U1 * H2) % P
	nx = (R ** 2 - H3 - 2 * U1H2) % P
	ny = (R * (U1H2 - nx) - S1 * H3) % P
	nz = (H * Zp * Zq) % P
	return (nx, ny, nz)


def curve_mul(Xp_Yp_Zp, n, N, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	if Yp == 0 or n == 0:
		return (0, 0, 1)
	if n == 1:
		return (Xp, Yp, Zp)
	if n < 0 or n >= N:
		return curve_mul((Xp, Yp, Zp), n % N, N, A, P)
	if (n % 2) == 0:
		return curve_math(curve_mul((Xp, Yp, Zp), n // 2, N, A, P), A, P)
	if (n % 2) == 1:
		return curve_add(curve_math(curve_mul((Xp, Yp, Zp), n // 2, N, A, P), A, P), (Xp, Yp, Zp), A, P)


class SK:
	def __init__(self, curve=sm2_class, secret=None):
		self.curve = curve
		self.secret = secret or SystemRandom().randrange(1, curve.N)

	def publicKey(self):
		curve = self.curve
		xPublicKey, yPublicKey = multiply((curve.Gx, curve.Gy), self.secret, A=curve.A, P=curve.P, N=curve.N)
		return PK(xPublicKey, yPublicKey, curve)

	def tostring(self):
		return "{}".format(str(hex(self.secret))[2:].zfill(64))


class PK:
	def __init__(self, x, y, curve):
		self.x = x
		self.y = y
		self.curve = curve

	def tostring(self, compressed=True):
		return {
			True:  str(hex(self.x))[2:],
			False: "{}{}".format(str(hex(self.x))[2:].zfill(64), str(hex(self.y))[2:].zfill(64))
		}.get(compressed)


class sm2_1:
    # 加密
    def encrypt(self, info):
        encode_info = sm2_crypt.encrypt(info.encode(encoding="utf-8"))
        encode_info = b64encode(encode_info).decode()  # 将二进制bytes通过base64编码
        return encode_info

    # 解密
    def decrypt(self, info):
        decode_info = b64decode(info.encode())  # 通过base64解码成二进制bytes
        decode_info = sm2_crypt.decrypt(decode_info).decode(encoding="utf-8")
        return decode_info

priKey = SK()
pubKey = priKey.publicKey()

print("使用的私钥：")
print(priKey.tostring())
print("使用的公钥：")
print(pubKey.tostring(compressed = False))
sm2_crypt = sm2.CryptSM2(public_key=pubKey.tostring(compressed = False), private_key=priKey.tostring())
print("原明文：")
m = 'welcome to sdu'
print(m)
sm2 = sm2_1()
# 加密的密码
c = sm2.encrypt(m)
print("加密后得到的密文：")
print(c)
# 解密的密码
m1 = sm2.decrypt(c)
print("解密后得到的明文：")
print(m1)


