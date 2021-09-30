package chenxi.shangguan.messagecipher

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import chenxi.shangguan.messagecipher.databinding.ActivityAesCipherBinding
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.util.Base64
import androidx.appcompat.app.AlertDialog
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesCipher : AppCompatActivity() {

    private lateinit var ui : ActivityAesCipherBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //setContentView(R.layout.activity_aes_cipher)
        ui = ActivityAesCipherBinding.inflate(layoutInflater)
        setContentView(ui.root)

        if (getSupportActionBar() != null){
            getSupportActionBar()?.hide();
        }

        ui.aesPwd.setText(intent.getStringExtra(AES_PWD_PASS))

        ui.btnEncrypt.setOnClickListener {
            val plainText = ui.plainText.text.toString()
            val pwd = ui.aesPwd.text.toString()

            if (plainText == ""){
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("需要提供密文").setPositiveButton("好" , null ).create().show()
            }else if(pwd == ""){
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("需要提供密码").setPositiveButton("好" , null ).create().show()
            }else if (pwd.length == 16 || pwd.length == 24 || pwd.length == 32){
                val encryptedText = encrypt(plainText, pwd)
                if (encryptedText == null) {
                    AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("发生未知错误").setPositiveButton("好" , null ).create().show()
                }else{
                    ui.plainText.text.clear()
                    ui.encryptedText.text.clear()
                    ui.encryptedText.setText(encryptedText)

                    // 将内容复制到剪贴板
                    try {
                        //获取剪贴板管理器
                        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                        // 创建普通字符型ClipData
                        val mClipData = ClipData.newPlainText("Label", ui.encryptedText.text)
                        // 将ClipData内容放到系统剪贴板里。
                        cm.setPrimaryClip(mClipData);

                    } catch (e: Exception) {

                    }
                }
            }else{
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("密码应为16/24/32字符长度").setPositiveButton("好" , null ).create().show()
            }
        }

        ui.btnDecrypt.setOnClickListener {
            val encryptedText = ui.encryptedText.text.toString()
            val pwd = ui.aesPwd.text.toString()

            if (encryptedText == ""){
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("需要提供密文").setPositiveButton("好" , null ).create().show()
            }else if(pwd == ""){
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("需要提供密码").setPositiveButton("好" , null ).create().show()
            }else if (pwd.length == 16 || pwd.length == 24 || pwd.length == 32){
                val decryptedText = decrypt(encryptedText, pwd)
                if (decryptedText == null){
                    AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("发生未知错误").setPositiveButton("好" , null ).create().show()
                }else{
                    ui.plainText.text.clear()
                    ui.plainText.setText(decryptedText)
                }
            }else{
                AlertDialog.Builder(this@AesCipher).setTitle("错误").setMessage("密码应为16/24/32字符长度").setPositiveButton("好" , null ).create().show()
            }
        }

        ui.btnDelPlainTxt.setOnClickListener {
            ui.plainText.text.clear()
        }

        ui.btnPurgeAll.setOnClickListener {
            ui.plainText.text.clear()
            ui.aesPwd.text.clear()
            ui.encryptedText.text.clear()

            // 清空剪贴板
            try{
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                val mClipData = ClipData.newPlainText("", "")
                cm.setPrimaryClip(mClipData)
            }catch (e: Exception){

            }

            AlertDialog.Builder(this@AesCipher).setTitle("提示").setMessage("重置成功").setPositiveButton("好" , null ).create().show()
        }

        ui.butDelEncryptedTxt.setOnClickListener {
            ui.encryptedText.text.clear()
        }

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

                    ui.encryptedText.text.clear()
                    ui.encryptedText.setText(pasteString)

                    ui.btnDecrypt.callOnClick()
                }
            }catch (e: Exception){

            }
        }

    }


    //private static final String CipherMode = "AES/ECB/PKCS5Padding";使用ECB加密，不需要设置IV，但是不安全
    private val CipherMode = "AES/CFB/NoPadding" //使用CFB加密，需要设置IV


    /**
     * 对字符串加密
     *
     * @param key  密钥
     * @param data 源字符串
     * @return 加密后的字符串
     */
    @Throws(Exception::class)
    fun encrypt(data: String, key: String): String? {
        return try {
            val cipher = Cipher.getInstance(CipherMode)
            val keyspec = SecretKeySpec(key.toByteArray(), "AES")
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, IvParameterSpec(ByteArray(cipher.blockSize)))
            val encrypted = cipher.doFinal(data.toByteArray())
            //Base64.encodeToString(encrypted, Base64.DEFAULT) //Base64
            byteToHex(encrypted) // HEX
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 对字符串解密
     *
     * @param key  密钥
     * @param data 已被加密的字符串
     * @return 解密得到的字符串
     */
    @Throws(Exception::class)
    fun decrypt(data: String, key: String): String? {
        return try {
            //val encrypted1 = Base64.decode(data.toByteArray(), Base64.DEFAULT) // Base64
            val encrypted1 = hexToByte(data) // HEX
            val cipher = Cipher.getInstance(CipherMode)
            val keyspec = SecretKeySpec(key.toByteArray(), "AES")
            cipher.init(Cipher.DECRYPT_MODE, keyspec, IvParameterSpec(ByteArray(cipher.blockSize)))
            val original = cipher.doFinal(encrypted1)
            String(original, charset("UTF-8"))
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * byte数组转hex
     * @param bytes
     * @return
     */
    private val hexArray = "0123456789ABCDEF".toCharArray()
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
            ret[i] = java.lang.Byte.valueOf(intVal.toByte())
        }
        return ret
    }

}