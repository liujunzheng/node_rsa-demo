import Rsa from './Rsa'
// 从对象获取公钥和私钥
const client = new Rsa()
const clientKeys = client.getKeys()
console.log('clientKeys,', clientKeys)

const server = new Rsa()
const serverKeys = server.getKeys()
console.log('serverKeys', serverKeys)


const data = 'this is rsa data'
const code = '159357'

// 客户端使用服务端的公钥加密
const encryptData = server.encryptByPubKey(data)
// 客户端使用自己的私钥签名
const encryptSign = client.signature(code)

// 服务端使用自己的私钥解密
const decryptData = server.decryptByPriKey(encryptData)
// 服务端使用客户端的公钥验签
const decryptSign = client.verify(code, encryptSign)

console.log('decryptData： \n', decryptData); // this is rsa data
console.log('decryptSign： \n', decryptSign); // true

// const keys = rsa.getKeys()
// console.log(keys)

// const res_en_by_pub = rsa.encryptByPubKey('hello')
// const res_de_by_pri = rsa.decryptByPriKey(res_en_by_pub)
// const res_sign_by_pri = rsa.signature('123456')
// const res_verify_by_pub = rsa.verify('123456', res_sign_by_pri)
// console.log('公钥加密：' + res_en_by_pub)
// console.log('私钥解密：' + res_de_by_pri)
// console.log('私钥签名：' + res_sign_by_pri)
// console.log('公钥验证：' + res_verify_by_pub)



// 从已有文件加载私钥和公钥
// const rsa = new Rsa()
// const pubKey = Rsa.getKey(process.cwd() + '\\' + 'rsa_pub')
// const priKey = Rsa.getKey(process.cwd() + '\\' + 'rsa_pri')
// const res_en_by_pub = rsa.encryptByPubKey('123456', pubKey)
// const res_de_by_pri = rsa.decryptByPriKey(res_en_by_pub, priKey)
// const res_sign_by_pri = rsa.signature('123456', priKey)
// const res_verify_by_pub = rsa.verify('123456', res_sign_by_pri, pubKey)
// console.log('公钥加密：' + res_en_by_pub)
// console.log('私钥解密：' + res_de_by_pri)
// console.log('私钥签名：' + res_sign_by_pri)
// console.log('公钥验证：' + res_verify_by_pub)


