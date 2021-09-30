package chenxi.shangguan.messagecipher

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import chenxi.shangguan.messagecipher.databinding.ActivityMainBinding
import java.lang.Byte
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import kotlin.collections.HashMap
import kotlin.experimental.and

val AES_PWD_PASS : String = ""

class MainActivity : AppCompatActivity() {

    private lateinit var ui : ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //setContentView(R.layout.activity_main)
        ui = ActivityMainBinding.inflate(layoutInflater)
        setContentView(ui.root)

        if (getSupportActionBar() != null){
            getSupportActionBar()?.hide();
        }

        var keys: Map<String, Any>?
        var v1: String?
        var v2: String?

        // 初始化PSA密钥对
        ui.btnGenKeys.setOnClickListener {
            // 生成rsa密钥对
            keys = initKey()
            v1 = getPublicKey(keys as Map<String?, Any?>)
            v2 = getPrivateKey(keys as Map<String?, Any?>)

            // 清空数字签名和密文文本框
            ui.txtEncryptedTxt.text.clear()
            ui.txtSignature.text.clear()

            // 显示到文本框
            ui.txtPublicKey.setText(v1)
            ui.txtPrivateKey.setText(v2)
        }

        // 公钥加密AES pwd
        ui.btnPublicKeyEncrypt.setOnClickListener {
            // 获取并判断AES pwd长度是否合规
            var aes_pwd = ui.txtAESPwd.text.toString()
            var public_key = ui.txtPublicKey.text.toString()

            if (aes_pwd.length != 16 && aes_pwd.length != 24 && aes_pwd.length != 32){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("密码应为16/24/32字符长度").setPositiveButton("好" , null ).create().show()
            }else{
                if (public_key != ""){
                    ui.txtEncryptedTxt.setText(encryptByPublicKey(aes_pwd, public_key))
                }else{
                    AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供公钥").setPositiveButton("好" , null ).create().show()
                }
            }
        }

        // 公钥解密 encrpyed text
        ui.btnPublicKeyDecrypt.setOnClickListener {
            var encrpyed_text = ui.txtEncryptedTxt.text.toString()
            var public_key = ui.txtPublicKey.text.toString()

            if (encrpyed_text == "") {
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供密文").setPositiveButton("好" , null ).create().show()
            }else{
                if (public_key != ""){
                    ui.txtAESPwd.setText(decryptByPublicKey(encrpyed_text, public_key))
                }else{
                    AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供公钥").setPositiveButton("好" , null ).create().show()
                }
            }
        }

        // 私钥加密 AES pwd
        ui.btnPrivateKeyEncrypt.setOnClickListener {
            var aes_pwd = ui.txtAESPwd.text.toString()
            var private_key = ui.txtPrivateKey.text.toString()

            if (aes_pwd.length != 16 && aes_pwd.length != 24 && aes_pwd.length != 32){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("密码应为16/24/32字符长度").setPositiveButton("好" , null ).create().show()
            }else{
                if (private_key != ""){
                    ui.txtEncryptedTxt.setText(encryptByPrivateKey(aes_pwd, private_key))
                }else{
                    AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供私钥").setPositiveButton("好" , null ).create().show()
                }
            }
        }

        // 私钥解密 encrpyed text
        ui.btnPrivateKeyDecrypt.setOnClickListener {
            // 获取已加密的文本和私钥
            var encrypted_text = ui.txtEncryptedTxt.text.toString()
            var private_key = ui.txtPrivateKey.text.toString()

            if(encrypted_text == ""){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供密文").setPositiveButton("好" , null ).create().show()
            }else if (private_key == ""){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供私钥").setPositiveButton("好" , null ).create().show()
            }else{
                ui.txtAESPwd.setText(decryptByPrivateKey(encrypted_text, private_key))
            }
        }

        // 私钥对加密后的数据签名
        ui.btnGenSignature.setOnClickListener {
            var encrpyed_text = ui.txtEncryptedTxt.text.toString()
            var private_key = ui.txtPrivateKey.text.toString()
            var aes_pwd = ui.txtAESPwd.text.toString()

            if (private_key != "") {
                if (encrpyed_text == "") {
                    if (aes_pwd.length != 16 && aes_pwd.length != 24 && aes_pwd.length != 32) {
                        AlertDialog.Builder(this@MainActivity).setTitle("错误")
                                .setMessage("密码应为16/24/32字符长度").setPositiveButton("好" , null ).create().show()
                    } else {
                        ui.txtEncryptedTxt.setText(encryptByPrivateKey(aes_pwd, private_key))
                        ui.txtSignature.setText(
                                sign(
                                        ui.txtEncryptedTxt.text.toString(),
                                        private_key
                                )
                        )

                        // 将内容复制到剪贴板
                        try {
                            //获取剪贴板管理器
                            val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                            // 创建普通字符型ClipData
                            val mClipData = ClipData.newPlainText("Label", ui.txtSignature.text)
                            // 将ClipData内容放到系统剪贴板里。
                            cm.setPrimaryClip(mClipData);
                            AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("已完成加密和签名并已复制到剪贴板").setPositiveButton("好" , null ).create().show()
                        } catch (e: Exception) {

                        }
                    }
                }else{
                    ui.txtSignature.setText(sign(ui.txtEncryptedTxt.text.toString(), private_key))
                    AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("已完成签名并已复制到剪贴板").setPositiveButton("好" , null ).create().show()
                }
            }else{
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供私钥").setPositiveButton("好" , null ).create().show()
            }
        }

        // 用公钥和加密数据验证签名
        ui.btnVerifySignature.setOnClickListener {
            var encrpyed_text = ui.txtEncryptedTxt.text.toString()
            var public_key = ui.txtPublicKey.text.toString()
            var signature_text = ui.txtSignature.text.toString()

            if (encrpyed_text == "") {
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供密文").setPositiveButton("好" , null ).create().show()
            }else if (public_key == ""){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供公钥").setPositiveButton("好" , null ).create().show()
            }else if (signature_text == ""){
                AlertDialog.Builder(this@MainActivity).setTitle("错误").setMessage("需要提供数字签名").setPositiveButton("好" , null ).create().show()
            }else{
                if (verify(encrpyed_text, public_key, signature_text)){
                    ui.txtAESPwd.setText(decryptByPublicKey(encrpyed_text, public_key))
                    AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("合法签名，验证成功").setPositiveButton("好" , null ).create().show()
                }else{
                    AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("签名不合法，验证失败").setPositiveButton("好" , null ).create().show()
                }
            }
        }


        // 清空AES密码文本框
        ui.btnClearAesPwdTxt.setOnClickListener {
            ui.txtAESPwd.text.clear()
        }

        // 清空公钥文本框
        ui.btnClearPublicKeyTxt.setOnClickListener{
            ui.txtPublicKey.text.clear()
        }

        // 清空私钥文本框
        ui.btnClearPrivateKeyTxt.setOnClickListener {
            ui.txtPrivateKey.text.clear()
        }

        // 清空数字签名文本框
        ui.btnClearSignatureTxt.setOnClickListener {
            ui.txtSignature.text.clear()
        }

        // 清空密文文本框
        ui.btnClearEncryptedTxt.setOnClickListener {
            ui.txtEncryptedTxt.text.clear()
        }

        // 复制公钥到剪贴板
        ui.btnCopyPublicKey.setOnClickListener {
            // 将内容复制到剪贴板
            try {
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                // 创建普通字符型ClipData
                val mClipData = ClipData.newPlainText("Label", ui.txtPublicKey.text)
                // 将ClipData内容放到系统剪贴板里。
                cm.setPrimaryClip(mClipData);
                AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("公钥已复制到剪贴板").setPositiveButton("好" , null ).create().show()
            } catch (e: Exception) {

            }
        }

        // 从剪贴板粘贴公钥
        ui.btnPastePublicKey.setOnClickListener {
            // 从剪贴板获取内容
            try{
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                //获取文本
                val clipData: ClipData? = cm.primaryClip
                if (clipData != null && clipData.itemCount > 0) {
                    val text = clipData.getItemAt(0).text
                    val pasteString = text.toString()

                    ui.txtPublicKey.text.clear()
                    ui.txtPublicKey.setText(pasteString)
                }
            }catch (e: Exception){

            }
        }

        // 复制私钥到剪贴板
        ui.btnCopyPrivateKey.setOnClickListener {
            // 将内容复制到剪贴板
            try {
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                // 创建普通字符型ClipData
                val mClipData = ClipData.newPlainText("Label", ui.txtPrivateKey.text)
                // 将ClipData内容放到系统剪贴板里。
                cm.setPrimaryClip(mClipData);
                AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("私钥已复制到剪贴板").setPositiveButton("好" , null ).create().show()
            } catch (e: Exception) {

            }
        }

        // 从剪贴板粘贴私钥
        ui.btnPastePrivateKey.setOnClickListener {
            // 从剪贴板获取内容
            try{
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                //获取文本
                val clipData: ClipData? = cm.primaryClip
                if (clipData != null && clipData.itemCount > 0) {
                    val text = clipData.getItemAt(0).text
                    val pasteString = text.toString()

                    ui.txtPrivateKey.text.clear()
                    ui.txtPrivateKey.setText(pasteString)
                }
            }catch (e: Exception){

            }
        }

        // 从剪贴板粘贴签名
        ui.btnPasteSignature.setOnClickListener {
            // 从剪贴板获取内容
            try{
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                //获取文本
                val clipData: ClipData? = cm.primaryClip
                if (clipData != null && clipData.itemCount > 0) {
                    val text = clipData.getItemAt(0).text
                    val pasteString = text.toString()

                    ui.txtSignature.text.clear()
                    ui.txtSignature.setText(pasteString)
                }
            }catch (e: Exception){

            }
        }

        // 复制加密后的内容到剪贴板
        ui.btnCopyEncryptedTxt.setOnClickListener {
            // 将内容复制到剪贴板
            try {
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                // 创建普通字符型ClipData
                val mClipData = ClipData.newPlainText("Label", ui.txtEncryptedTxt.text)
                // 将ClipData内容放到系统剪贴板里。
                cm.setPrimaryClip(mClipData);
                AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("密文已复制到剪贴板").setPositiveButton("好" , null ).create().show()
            } catch (e: Exception) {

            }
        }

        // 从剪贴板粘贴加密后的内容
        ui.btnPasteEncryptedTxt.setOnClickListener {
            // 从剪贴板获取内容
            try{
                //获取剪贴板管理器
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                //获取文本
                val clipData: ClipData? = cm.primaryClip
                if (clipData != null && clipData.itemCount > 0) {
                    val text = clipData.getItemAt(0).text
                    val pasteString = text.toString()

                    ui.txtEncryptedTxt.text.clear()
                    ui.txtEncryptedTxt.setText(pasteString)
                }
            }catch (e: Exception){

            }
        }

        // 跳转到AES加解密：带上AES密码
        ui.btnGoToAES.setOnClickListener {
            val send_aes_pwd = ui.txtAESPwd.text.toString()
            ui.btnClearAesPwdTxt.callOnClick()
            ui.btnClearEncryptedTxt.callOnClick()
            val i = Intent(this, AesCipher::class.java)
            i.putExtra(AES_PWD_PASS, send_aes_pwd)
            startActivity(i)
        }

        // 清空所有文本框和剪贴板
        ui.btnPurgeAll.setOnClickListener {
            // 清空所有文本框
            ui.btnClearAesPwdTxt.callOnClick()
            ui.btnClearPublicKeyTxt.callOnClick()
            ui.btnClearPrivateKeyTxt.callOnClick()
            ui.btnClearSignatureTxt.callOnClick()
            ui.btnClearEncryptedTxt.callOnClick()

            // 清空密钥
            keys = HashMap(0)
            v1 = ""
            v2 = ""

            //清空剪贴板
            try{
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                val mClipData = ClipData.newPlainText("", "")
                cm.setPrimaryClip(mClipData)
            }catch (e: Exception){

            }
            AlertDialog.Builder(this@MainActivity).setTitle("提示").setMessage("重置成功").setPositiveButton("好" , null ).create().show()
        }

        // 随机生成AES密码
        ui.btnGenRandAesPwd.setOnClickListener {
            // 清空数字签名和密文文本框
            ui.txtEncryptedTxt.text.clear()
            ui.txtSignature.text.clear()
            ui.txtAESPwd.setText(createRandom(false, 32))
        }

    }

    /**
     * 随机生成指定长度的16进制字符串
     *
     * @param numberFlag  是否纯数字 true/false
     * @param length       字符串长度
     * @return String
     * @throws
     */
    fun createRandom(numberFlag: Boolean, length: Int): String? {
        var retStr = ""
        val strTable = if (numberFlag) "1234567890" else "`1234567890-=abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+[]{}ABCDEFGHIJKLMNOPQRSTUVWXYZ;:,./<>?\\"
        val len = strTable.length
        var bDone = true
        do {
            retStr = ""
            var count = 0
            for (i in 0 until length) {
                val dblR = Math.random() * len
                val intR = Math.floor(dblR).toInt()
                val c = strTable[intR]
                if (c in '0'..'9') {
                    count++
                }
                retStr += strTable[intR]
            }
            if (count >= 2) {
                bDone = false
            }
        } while (bDone)
        return retStr
    }


    // RSA配置和函数库部分
    //android系统的RSA实现是"RSA/None/NoPadding"，而标准JDK实现是"RSA/None/PKCS1Padding"
    val KEY_ALGORITHM = "RSA"
    val ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding" // "RSA/ECB/PKCS1Padding"
    val SIGNATURE_ALGORITHM = "MD5withRSA"

    private val PUBLIC_KEY = "RSAPublicKey"
    private val PRIVATE_KEY = "RSAPrivateKey"

    @Throws(Exception::class)
    fun decryptBASE64(key: String?): ByteArray? {
        // base64
        //return Base64.decode(key, Base64.DEFAULT)

        //HEX to ByteArray
        return hexToByte(key!!)
    }

    @Throws(Exception::class)
    fun encryptBASE64(key: ByteArray?): String? {
        // base64
        //return Base64.encodeToString(key, Base64.DEFAULT)

        // ByteArray to HEX
        return byteToHex(key!!)
    }


    /**
     * byte数组转hex
     * @param bytes
     * @return
     */
    private val hexArray = "0123456789ABCDEF".toCharArray()
    /*
    private fun byteToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }
     */
    private fun byteToHex(bytes: ByteArray?): String? {
        val hexChars = CharArray(bytes!!.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    /**
     * hex转byte数组
     * @param hex
     * @return
     */
    private fun hexToByte(hex: String?): ByteArray? {
        var m = 0
        var n = 0
        val byteLen = hex!!.length / 2 // 每两个字符描述一个字节
        val ret = ByteArray(byteLen)
        for (i in 0 until byteLen) {
            m = i * 2 + 1
            n = m + 1
            val intVal = Integer.decode("0x" + hex.substring(i * 2, m) + hex.substring(m, n))
            ret[i] = Byte.valueOf(intVal.toByte())
        }
        return ret
    }



    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun sign(data: String?, privateKey: String?): String? {
        // 解密由base64编码的私钥
        val keyBytes = decryptBASE64(privateKey)
        try {
            // 构造PKCS8EncodedKeySpec对象
            val pkcs8KeySpec = PKCS8EncodedKeySpec(keyBytes)

            // KEY_ALGORITHM 指定的加密算法
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)

            // 取私钥匙对象
            val priKey = keyFactory.generatePrivate(pkcs8KeySpec)

            // 用私钥对信息生成数字签名
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(priKey)
            //signature.update(Base64.encode(data?.toByteArray(), Base64.DEFAULT))
            signature.update(data?.toByteArray(charset("utf-8")))
            return encryptBASE64(signature.sign())
        }catch (e: Exception){
            return ""
        }
    }

    /**
     * 校验数字签名
     *
     * @param data      加密数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    @Throws(Exception::class)
    fun verify(data: String?, publicKey: String?, sign: String?): Boolean {
        try {
            // 解密由base64编码的公钥
            val keyBytes = decryptBASE64(publicKey)

            // 构造X509EncodedKeySpec对象
            val keySpec = X509EncodedKeySpec(keyBytes)

            // KEY_ALGORITHM 指定的加密算法
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)

            // 取公钥匙对象
            val pubKey = keyFactory.generatePublic(keySpec)
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(pubKey)
            //signature.update(Base64.decode(data?.toByteArray(), Base64.DEFAULT))
            signature.update(data?.toByteArray(charset("utf-8")))
            // 验证签名是否正常
            return signature.verify(decryptBASE64(sign))
        }catch (e: Exception){
            return false
        }
    }

    /**
     * 解密<br></br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun decryptByPrivateKey(data: String?, key: String?): String? {
        try {
            // 对密钥解密
            val keyBytes = decryptBASE64(key)

            // 取得私钥
            val pkcs8KeySpec = PKCS8EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val privateKey: Key = keyFactory.generatePrivate(pkcs8KeySpec)

            // 对数据解密
            //val cipher = Cipher.getInstance(keyFactory.algorithm)
            val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            //val original = cipher.doFinal(Base64.decode(data?.toByteArray(), Base64.DEFAULT)) // Base64
            val original = cipher.doFinal(decryptBASE64(data))  // HEX
            return String(original, charset("UTF-8"))
        }catch (e: Exception){
            return ""
        }
    }

    /**
     * 解密<br></br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun decryptByPublicKey(data: String?, key: String?): String? {
        try {
            // 对密钥解密
            val keyBytes = decryptBASE64(key)

            // 取得公钥
            val x509KeySpec = X509EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val publicKey: Key = keyFactory.generatePublic(x509KeySpec)

            // 对数据解密
            //val cipher = Cipher.getInstance(keyFactory.algorithm)
            val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
            cipher.init(Cipher.DECRYPT_MODE, publicKey)
            //val original = cipher.doFinal(Base64.decode(data?.toByteArray(), Base64.DEFAULT)) // Base64
            val original = cipher.doFinal(decryptBASE64(data))
            return String(original, charset("UTF-8"))
        }catch (e: Exception){
            return ""
        }
    }

    /**
     * 加密<br></br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun encryptByPublicKey(data: String?, key: String?): String? {
        try {
            // 对公钥解密
            val keyBytes = decryptBASE64(key)
            // 取得公钥
            val x509KeySpec = X509EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val publicKey: Key = keyFactory.generatePublic(x509KeySpec)

            // 对数据加密
            //val cipher = Cipher.getInstance(keyFactory.algorithm)
            val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val original = cipher.doFinal(data?.toByteArray())
            //return Base64.encodeToString(original, Base64.DEFAULT) // Base64
            return encryptBASE64(original) // HEX
        }catch (e: Exception){
            return ""
        }
    }

    /**
     * 加密<br></br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun encryptByPrivateKey(data: String?, key: String?): String? {
        try {
            // 对密钥解密
            val keyBytes = decryptBASE64(key)

            // 取得私钥
            val pkcs8KeySpec = PKCS8EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val privateKey: Key = keyFactory.generatePrivate(pkcs8KeySpec)

            // 对数据加密
            //val cipher = Cipher.getInstance(keyFactory.algorithm)
            val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
            cipher.init(Cipher.ENCRYPT_MODE, privateKey)
            val original = cipher.doFinal(data?.toByteArray())
            //return Base64.encodeToString(original, Base64.DEFAULT) // Base64
            return encryptBASE64(original) // HEX
        }catch (e: Exception){
            return ""
        }
    }

    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun getPrivateKey(keyMap: Map<String?, Any?>): String? {
        val key = keyMap[PRIVATE_KEY] as Key?
        return encryptBASE64(key!!.encoded)
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun getPublicKey(keyMap: Map<String?, Any?>): String? {
        val key = keyMap[PUBLIC_KEY] as Key?
        return encryptBASE64(key!!.encoded)
    }

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun initKey(): Map<String, Any>? {
        val keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        // RSA算法要求有一个可信任的随机数源
        val secureRandom = SecureRandom()

        //keyPairGen.initialize(2048)
        keyPairGen.initialize(2048, secureRandom)

        val keyPair = keyPairGen.generateKeyPair()
        // 公钥
        val publicKey = keyPair.public as RSAPublicKey
        // 私钥
        val privateKey = keyPair.private as RSAPrivateKey
        val keyMap: MutableMap<String, Any> = HashMap(2)
        keyMap[PUBLIC_KEY] = publicKey
        keyMap[PRIVATE_KEY] = privateKey
        return keyMap
    }

}