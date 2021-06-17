import * as NodeRsa from 'node-rsa'
import * as path from 'path'
import * as fs from 'fs'

export default class Rsa {
    private pubKey: string | null = null
    private priKey: string | null = null

    /**
     * 获取密钥对
     * @returns 返回 公钥和私钥
     */
    public getKeys(): {
        pubKey: string,
        priKey: string
    } {
        const key = new NodeRsa({
            b: 512
        })
        this.pubKey = key.exportKey('pkcs8-public')
        this.priKey = key.exportKey('pkcs8-private')
        return {
            pubKey: this.pubKey as string,
            priKey: this.priKey as string
        }
    }

    /**
     * 将密钥对写到文件
     * @param filepath 文件输出目录 [默认为程序运行目录]
     * @returns true: 写出成功 | false: 写出失败
     */
    public output(filepath?: string): boolean {
        if (!filepath) filepath = process.cwd() + path.sep
        filepath = filepath + path.sep
        try {
            fs.writeFileSync(
                filepath + 'rsa_pub',
                this.pubKey as string
            )
            fs.writeFileSync(
                filepath + 'rsa_pri',
                this.priKey as string
            )
            fs.writeFileSync(
                filepath + 'rsa_key',
                this.pubKey as string + '\n' + this.priKey as string
            )
            return true
        } catch (error) {
            return false
        }
    }

    /**
     * 使用公钥对消息加密
     * @param data 消息数据
     * @param publicKey 公钥 [默认为当前 rsa 对象公钥]
     * @returns 公钥加密后的数据 [base64加密的]
     */
    public encryptByPubKey(data: string, publicKey?: string): any {
        if (!publicKey) publicKey = this.pubKey as string
        if (!publicKey) return null
        try {
            const pubKey = new NodeRsa(publicKey, 'pkcs8-public')
            return pubKey.encrypt(Buffer.from(data), 'base64')
        } catch (error) {
            return null
        }
    }

    /**
     * 使用私钥解密
     * @param data 加密数据 [base64加密的]
     * @param privateKey 私钥 [默认为当前 rsa 对象私钥]
     * @returns 私钥解密后的数据
     */
    public decryptByPriKey(data: string, privateKey?: string): any {
        if (!privateKey) privateKey = this.priKey as string
        if (!privateKey) return null
        try {
            const priKey = new NodeRsa(privateKey, 'pkcs8-private')
            return priKey.decrypt(Buffer.from(data, 'base64'), 'utf8')
        } catch (error) {
            return null
        }
    }

    /**
     * 使用私钥对消息签名
     * @param data 消息数据
     * @param privateKey 私钥 [默认为当前 rsa 对象私钥]
     * @returns 签名数据 [base64加密的]
     */
    public signature(data: string, privateKey?: string): any {
        if (!privateKey) privateKey = this.priKey as string
        if (!privateKey) return null
        try {
            const priKey = new NodeRsa(privateKey, 'pkcs8-private')
            return priKey.sign(Buffer.from(data)).toString('base64')
        } catch (error) {
            return null
        }
    }

    /**
     * 使用公钥验签
     * @param data 消息数据
     * @param signature 签名数据 [base64加密的]
     * @param publicKey 公钥 [默认为当前 rsa 对象公钥]
     * @returns true: 验签成功 | false: 验签失败
     */
    public verify(data: string, signature: string, publicKey?: string): boolean {
        if (!publicKey) publicKey = this.pubKey as string
        if (!publicKey) return false
        try {
            const pubKey = new NodeRsa(publicKey, 'pkcs8-public')
            return pubKey.verify(data, Buffer.from(signature, 'base64'))
        } catch (error) {
            console.log(error)
            return false
        }
    }

    /**
     * 装载密钥对
     * @param pubKey 公钥
     * @param priKey 私钥
     * @returns true: 装载成功 | false: 装载失败
     */
    public setKeys(pubKey: string, priKey: string): boolean {
        if (!pubKey || !priKey) return false
        this.pubKey = pubKey
        this.priKey = priKey
        return true
    }

    /**
     * 从文件获取密钥(或私钥)
     * @param filepath 文件路径
     * @returns '': 获取失败 | 密钥(或私钥)
     */
    public static getKey(filepath: string): string {
        if (!filepath) return ''
        try {
            const key = fs.readFileSync(filepath, {
                encoding: 'utf-8'
            })
            return key
        } catch (error) {
            return ''
        }
    }

}

