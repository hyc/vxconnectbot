/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sk.vx.connectbot.util;

import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.crypto.keys.Ed25519Provider;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sk.vx.connectbot.bean.PubkeyBean;
import android.util.Log;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.SSHSignature;


public class PubkeyUtils {
	static {
		Ed25519Provider.insertIfNeeded();
	}
	private static final String TAG = "ConnectBot.PubkeyUtils";
	public static final String PKCS8_START = "-----BEGIN PRIVATE KEY-----";
	public static final String PKCS8_END = "-----END PRIVATE KEY-----";

	// Size in bytes of salt to use.
	private static final int SALT_SIZE = 8;

	// Number of iterations for password hashing. PKCS#5 recommends 1000
	private static final int ITERATIONS = 1000;

	public static String formatKey(Key key){
		String algo = key.getAlgorithm();
		String fmt = key.getFormat();
		byte[] encoded = key.getEncoded();
		return "Key[algorithm=" + algo + ", format=" + fmt +
			", bytes=" + encoded.length + "]";
	}

	public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("SHA-256").digest(data);
	}

	public static byte[] cipher(int mode, byte[] data, byte[] secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec secretKeySpec = new SecretKeySpec(sha256(secret), "AES");
		Cipher c = Cipher.getInstance("AES");
		c.init(mode, secretKeySpec);
		return c.doFinal(data);
	}

	public static byte[] encrypt(byte[] cleartext, String secret) throws Exception {
		byte[] salt = new byte[SALT_SIZE];

		byte[] ciphertext = Encryptor.encrypt(salt, ITERATIONS, secret, cleartext);

		byte[] complete = new byte[salt.length + ciphertext.length];

		System.arraycopy(salt, 0, complete, 0, salt.length);
		System.arraycopy(ciphertext, 0, complete, salt.length, ciphertext.length);

		Arrays.fill(salt, (byte) 0x00);
		Arrays.fill(ciphertext, (byte) 0x00);

		return complete;
	}

	public static byte[] decrypt(byte[] complete, String secret) throws Exception {
		try {
			byte[] salt = new byte[SALT_SIZE];
			byte[] ciphertext = new byte[complete.length - salt.length];

			System.arraycopy(complete, 0, salt, 0, salt.length);
			System.arraycopy(complete, salt.length, ciphertext, 0, ciphertext.length);

			return Encryptor.decrypt(salt, ITERATIONS, secret, ciphertext);
		} catch (Exception e) {
			Log.d("decrypt", "Could not decrypt with new method", e);
			// We might be using the old encryption method.
			return cipher(Cipher.DECRYPT_MODE, complete, secret.getBytes());
		}
	}

	public static byte[] getEncodedPublic(PublicKey pk) {
		return new X509EncodedKeySpec(pk.getEncoded()).getEncoded();
	}

	public static byte[] getEncodedPrivate(PrivateKey pk) {
		return new PKCS8EncodedKeySpec(pk.getEncoded()).getEncoded();
	}

	public static byte[] getEncodedPrivate(PrivateKey pk, String secret) throws Exception {
		if (secret.length() > 0)
			return encrypt(getEncodedPrivate(pk), secret);
		else
			return getEncodedPrivate(pk);
	}

	public static PrivateKey decodePrivate(byte[] encoded, String keyType) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encoded);
		KeyFactory kf = KeyFactory.getInstance(keyType);
		return kf.generatePrivate(privKeySpec);
	}

	public static PrivateKey decodePrivate(byte[] encoded, String keyType, String secret) throws Exception {
		if (secret != null && secret.length() > 0)
			return decodePrivate(decrypt(encoded, secret), keyType);
		else
			return decodePrivate(encoded, keyType);
	}

	public static int getBitStrength(byte[] encoded, String keyType) throws InvalidKeySpecException,
			NoSuchAlgorithmException {
		final PublicKey pubKey = PubkeyUtils.decodePublic(encoded, keyType);
		if (PubkeyDatabase.KEY_TYPE_RSA.equals(keyType)) {
			return ((RSAPublicKey) pubKey).getModulus().bitLength();
		} else if (PubkeyDatabase.KEY_TYPE_DSA.equals(keyType)) {
			return 1024;
		} else if (PubkeyDatabase.KEY_TYPE_EC.equals(keyType)) {
			return ((ECPublicKey) pubKey).getParams().getCurve().getField()
					.getFieldSize();
		} else if (PubkeyDatabase.KEY_TYPE_ED25519.equals(keyType)) {
			return 256;
		} else {
			return 0;
		}
	}

	public static PublicKey decodePublic(byte[] encoded, String keyType) throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
		KeyFactory kf = KeyFactory.getInstance(keyType);
		return kf.generatePublic(pubKeySpec);
	}

	public static KeyPair convertToKeyPair(PubkeyBean keybean, String password) throws BadPasswordException {
		if (PubkeyDatabase.KEY_TYPE_IMPORTED.equals(keybean.getType())) {
			// load specific key using pem format
			try {
				return PEMDecoder.decode(new String(keybean.getPrivateKey(), "UTF-8").toCharArray(), password);
			} catch (Exception e) {
				Log.e(TAG, "Cannot decode imported key", e);
				throw new BadPasswordException();
			}
		} else {
			// load using internal generated format
			try {
				PrivateKey privKey = PubkeyUtils.decodePrivate(keybean.getPrivateKey(), keybean.getType(), password);
				PublicKey pubKey = PubkeyUtils.decodePublic(keybean.getPublicKey(), keybean.getType());
				Log.d(TAG, "Unlocked key " + PubkeyUtils.formatKey(pubKey));

				return new KeyPair(pubKey, privKey);
			} catch (Exception e) {
				Log.e(TAG, "Cannot decode pubkey from database", e);
				throw new BadPasswordException();
			}
		}
	}
	public static KeyPair recoverKeyPair(byte[] encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec privKeySpec = new PKCS8EncodedKeySpec(encoded);
		KeySpec pubKeySpec;

		PrivateKey priv;
		PublicKey pub;
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(PubkeyDatabase.KEY_TYPE_RSA);
			priv = kf.generatePrivate(privKeySpec);

			pubKeySpec = new RSAPublicKeySpec(((RSAPrivateCrtKey) priv)
					.getModulus(), ((RSAPrivateCrtKey) priv)
					.getPublicExponent());

			pub = kf.generatePublic(pubKeySpec);
		} catch (ClassCastException e) {
			kf = KeyFactory.getInstance(PubkeyDatabase.KEY_TYPE_DSA);
			priv = kf.generatePrivate(privKeySpec);

			DSAParams params = ((DSAPrivateKey) priv).getParams();

			// Calculate public key Y
			BigInteger y = params.getG().modPow(((DSAPrivateKey) priv).getX(),
					params.getP());

			pubKeySpec = new DSAPublicKeySpec(y, params.getP(), params.getQ(),
					params.getG());

			pub = kf.generatePublic(pubKeySpec);
		}

		return new KeyPair(pub, priv);
	}

	/*
	 * OpenSSH compatibility methods
	 */

	public static String convertToOpenSSHFormat(PublicKey pk, String origNickname) throws IOException, InvalidKeyException {
		String nickname = origNickname;
		if (nickname == null)
			nickname = "connectbot@android";

		if (pk instanceof RSAPublicKey) {
			String data = "ssh-rsa ";
			data += String.valueOf(Base64.encode(RSASHA1Verify.get().encodePublicKey((RSAPublicKey) pk)));
			return data + " " + nickname;
		} else if (pk instanceof DSAPublicKey) {
			String data = "ssh-dss ";
			data += String.valueOf(Base64.encode(DSASHA1Verify.get().encodePublicKey((DSAPublicKey) pk)));
			return data + " " + nickname;
		} else if (pk instanceof ECPublicKey) {
			ECPublicKey ecPub = (ECPublicKey) pk;
			String keyType = ECDSASHA2Verify.getSshKeyType(ecPub);
			SSHSignature verifier = ECDSASHA2Verify.getVerifierForKey(ecPub);
			String keyData = String.valueOf(Base64.encode(verifier.encodePublicKey(ecPub)));
			return keyType + " " + keyData + " " + nickname;
		} else if (pk instanceof Ed25519PublicKey) {
			Ed25519PublicKey edPub = (Ed25519PublicKey) pk;
			return Ed25519Verify.ED25519_ID + " " +
					String.valueOf(Base64.encode(Ed25519Verify.get().encodePublicKey(edPub))) +
					" " + nickname;
		}

		throw new InvalidKeyException("Unknown key type");
	}

	/*
	 * OpenSSH compatibility methods
	 */

	/**
	 * @param trileadKey
	 * @return OpenSSH-encoded pubkey
	 */
	public static byte[] extractOpenSSHPublic(KeyPair pair) {
		try {
			PublicKey pubKey = pair.getPublic();
			if (pubKey instanceof RSAPublicKey) {
				return RSASHA1Verify.get().encodePublicKey(pubKey);
			} else if (pubKey instanceof DSAPublicKey) {
				return DSASHA1Verify.get().encodePublicKey(pubKey);
			} else if (pubKey instanceof ECPublicKey) {
				return ECDSASHA2Verify.getVerifierForKey((ECPublicKey) pubKey).encodePublicKey(pubKey);
			} else if (pubKey instanceof Ed25519PublicKey) {
				return Ed25519Verify.get().encodePublicKey(pubKey);
			} else {
				return null;
			}
		} catch (IOException e) {
			return null;
		}
	}

	public static String exportPEM(PrivateKey key, String secret) throws NoSuchAlgorithmException, InvalidParameterSpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, IOException {
		StringBuilder sb = new StringBuilder();

		byte[] data = key.getEncoded();

		sb.append(PKCS8_START);
		sb.append('\n');

		if (secret != null) {
			byte[] salt = new byte[8];
			SecureRandom random = new SecureRandom();
			random.nextBytes(salt);

			PBEParameterSpec defParams = new PBEParameterSpec(salt, 1);
			AlgorithmParameters params = AlgorithmParameters.getInstance(key.getAlgorithm());

			params.init(defParams);

			PBEKeySpec pbeSpec = new PBEKeySpec(secret.toCharArray());

			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(key.getAlgorithm());
			Cipher cipher = Cipher.getInstance(key.getAlgorithm());
			cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);

			byte[] wrappedKey = cipher.wrap(key);

			EncryptedPrivateKeyInfo pinfo = new EncryptedPrivateKeyInfo(params, wrappedKey);

			data = pinfo.getEncoded();

			sb.append("Proc-Type: 4,ENCRYPTED\n");
			sb.append("DEK-Info: DES-EDE3-CBC,");
			sb.append(encodeHex(salt));
			sb.append("\n\n");
		}

		int i = sb.length();
		sb.append(Base64.encode(data));
		for (i += 63; i < sb.length(); i += 64) {
			sb.insert(i, "\n");
		}

		sb.append('\n');
		sb.append(PKCS8_END);
		sb.append('\n');

		return sb.toString();
	}

	private static final char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	protected static String encodeHex(byte[] bytes) {
		final char[] hex = new char[bytes.length * 2];

		int i = 0;
		for (byte b : bytes) {
			hex[i++] = HEX_DIGITS[(b >> 4) & 0x0f];
			hex[i++] = HEX_DIGITS[b & 0x0f];
		}

		return String.valueOf(hex);
	}

	public static String getPubkeyString(PubkeyBean pubkey) {
		try {
			PublicKey pk = PubkeyUtils.decodePublic(pubkey.getPublicKey(), pubkey.getType());
			return convertToOpenSSHFormat(pk, pubkey.getNickname());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String getPrivkeyString(PubkeyBean pubkey, String passphrase) {
		String data = null;
		boolean imported = PubkeyDatabase.KEY_TYPE_IMPORTED.equals(pubkey.getType());
		if (imported)
			try {
				data = new String(pubkey.getPrivateKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
		else {
			try {
				PrivateKey pk = null;
				if (passphrase == null)
					pk = decodePrivate(pubkey.getPrivateKey(), pubkey.getType());
				else
					pk = decodePrivate(pubkey.getPrivateKey(), pubkey.getType(), passphrase);
				data = exportPEM(pk, passphrase);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return data;
	}

	public static class BadPasswordException extends Exception {
	}

}
