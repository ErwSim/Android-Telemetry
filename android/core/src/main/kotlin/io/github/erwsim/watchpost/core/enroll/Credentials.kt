package io.github.erwsim.watchpost.core.enroll

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager

/** Holds the TLS client key. The Android implementation keeps it in the Keystore (non-exportable). */
interface ClientCredentialStore {
    fun import(privateKey: PrivateKey, chain: List<X509Certificate>)
    fun keyManager(): X509KeyManager?
    fun chain(): List<X509Certificate>
    fun delete()
}

/** Authenticated encryption of small secrets at rest (the device token). */
interface SecretBox {
    fun seal(plain: ByteArray): ByteArray
    fun open(sealed: ByteArray): ByteArray
    fun destroy()
}

/** KeyManager that always presents the single enrolled client certificate. */
class SingleKeyManager(
    private val alias: String,
    private val keyProvider: () -> PrivateKey?,
    private val chainProvider: () -> List<X509Certificate>,
) : X509ExtendedKeyManager() {
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(alias)
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = alias
    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = alias
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias == this.alias) chainProvider().toTypedArray() else null
    override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == this.alias) keyProvider() else null
}

/** Android Keystore implementation: the key is imported once and can never be read back. */
class AndroidKeystoreCredentials(private val alias: String = ALIAS) : ClientCredentialStore {
    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun import(privateKey: PrivateKey, chain: List<X509Certificate>) {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            // TLS stacks may sign pre-hashed data (NONE) or let the key hash (SHA-2).
            .setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512,
            )
            .build()
        ks.setEntry(alias, KeyStore.PrivateKeyEntry(privateKey, chain.toTypedArray()), protection)
    }

    override fun keyManager(): X509KeyManager? {
        if (!keyStore().containsAlias(alias)) return null
        return SingleKeyManager(
            alias,
            keyProvider = { keyStore().getKey(alias, null) as? PrivateKey },
            chainProvider = ::chain,
        )
    }

    override fun chain(): List<X509Certificate> =
        keyStore().getCertificateChain(alias)?.map { it as X509Certificate } ?: emptyList()

    override fun delete() {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "watchpost_client"
    }
}

/** AES-256-GCM with a non-exportable Keystore key. Output: 12-byte IV followed by the ciphertext. */
class AndroidKeystoreSecretBox(private val alias: String = ALIAS) : SecretBox {
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(AndroidKeystoreCredentials.PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeystoreCredentials.PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    override fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        return cipher.iv + cipher.doFinal(plain)
    }

    override fun open(sealed: ByteArray): ByteArray {
        require(sealed.size > IV_LEN) { "sealed value too short" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, IV_LEN))
        return cipher.doFinal(sealed, IV_LEN, sealed.size - IV_LEN)
    }

    override fun destroy() {
        val ks = KeyStore.getInstance(AndroidKeystoreCredentials.PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private companion object {
        const val ALIAS = "watchpost_token_key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
