package sk.vx.connectbot.service;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import sk.vx.connectbot.service.TerminalManager;
import sk.vx.connectbot.service.TerminalManager.KeyHolder;
import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.SSHSignature;

import com.madgag.ssh.android.authagent.AndroidAuthAgent;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class AuthAgentService extends Service {
	private static final String TAG = "ConnectBot.AuthAgentService";
	protected TerminalManager manager;
	final Lock lock = new ReentrantLock();
	final Condition managerReady = lock.newCondition();

	private ServiceConnection connection = new ServiceConnection() {
		public void onServiceConnected(ComponentName className, IBinder service) {
			Log.d(TAG, "Terminal manager available! Hurrah");
			manager = ((TerminalManager.TerminalBinder) service).getService();
			lock.lock();
			try {
				managerReady.signal();
			} finally {
				lock.unlock();
			}
		}

		public void onServiceDisconnected(ComponentName className) {
			manager = null;
			Log.d(TAG, "Terminal manager gone...");
		}
	};

	@Override
	public IBinder onBind(Intent intent) {
		Log.d(TAG, "onBind() called");
		bindService(new Intent(this, TerminalManager.class), connection, BIND_AUTO_CREATE);
		return mBinder;
	}

	private final AndroidAuthAgent.Stub mBinder = new AndroidAuthAgent.Stub() {

		public Map getIdentities() throws RemoteException {
			Log.d(TAG, "getIdentities() called");
			waitForTerminalManager();
			Log.d(TAG, "getIdentities() manager.loadedKeypairs : " + manager.loadedKeypairs);

			return sshEncodedPubKeysFrom(manager.loadedKeypairs);
		}

		public byte[] sign(byte[] publicKey, byte[] data) throws RemoteException {
			Log.d(TAG, "sign() called");
			waitForTerminalManager();
			KeyPair pair = keyPairFor(publicKey);
			Log.d(TAG, "sign() - signing keypair found : "+pair);

			if (pair == null) {
				return null;
			}

			PrivateKey privKey = pair.getPrivate();
			if (privKey instanceof RSAPrivateKey) {
				return sshEncodedSignatureFor(data, (RSAPrivateKey) privKey);
			} else if (privKey instanceof DSAPrivateKey) {
				return sshEncodedSignatureFor(data, (DSAPrivateKey) privKey);
			} else if (privKey instanceof ECPrivateKey) {
				return sshEncodedSignatureFor(data, (ECPrivateKey) privKey);
			} else if (privKey instanceof Ed25519PrivateKey) {
				return sshEncodedSignatureFor(data, (Ed25519PrivateKey) privKey);
			}
			return null;
		}

		private void waitForTerminalManager() throws RemoteException {
			lock.lock();
			try {
				while (manager == null) {
					Log.d(TAG, "Waiting for TerminalManager...");
					managerReady.await();
				}
			} catch (InterruptedException e) {
				throw new RemoteException();
			} finally {
				lock.unlock();
			}
			Log.d(TAG, "Got TerminalManager : "+manager);
		}

		private Map<String, byte[]> sshEncodedPubKeysFrom(Map<String, KeyHolder> keypairs) {
			Map<String, byte[]> encodedPubKeysByName = new HashMap<String, byte[]>(keypairs.size());

			for (Entry<String, KeyHolder> entry : keypairs.entrySet()) {
				byte[] encodedKey = sshEncodedPubKeyFrom(entry.getValue().pair);
				if (encodedKey != null) {
					encodedPubKeysByName.put(entry.getKey(), encodedKey);
				}
			}
			return encodedPubKeysByName;
		}

		private byte[] sshEncodedPubKeyFrom(KeyPair pair) {
			try {
				PrivateKey privKey = pair.getPrivate();
				if (privKey instanceof RSAPrivateKey) {
					RSAPublicKey pubkey = (RSAPublicKey) pair.getPublic();
					return RSASHA1Verify.get().encodePublicKey(pubkey);
				} else if (privKey instanceof DSAPrivateKey) {
					DSAPublicKey pubkey = (DSAPublicKey) pair.getPublic();
					return DSASHA1Verify.get().encodePublicKey(pubkey);
				} else if (privKey instanceof ECPrivateKey) {
					ECPublicKey pubkey = (ECPublicKey) pair.getPublic();
					return ECDSASHA2Verify.getVerifierForKey(pubkey).encodePublicKey(pubkey);
				} else if (privKey instanceof Ed25519PrivateKey) {
					Ed25519PublicKey pubkey = (Ed25519PublicKey) pair.getPublic();
					return Ed25519Verify.get().encodePublicKey(pubkey);
				}
			} catch (IOException e) {
				Log.e(TAG, "Couldn't encode " + pair, e);
			}
			return null;
		}

		private byte[] sshEncodedSignatureFor(byte[] data, RSAPrivateKey privKey) {
			try {
				return RSASHA1Verify.get().generateSignature(data, privKey, new SecureRandom());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private byte[] sshEncodedSignatureFor(byte[] data, DSAPrivateKey privKey) {
			try {
				return DSASHA1Verify.get().generateSignature(data, privKey, new SecureRandom());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private byte[] sshEncodedSignatureFor(byte[] data, ECPrivateKey privKey) {
			try {
				return ECDSASHA2Verify.getVerifierForKey(privKey).generateSignature(data, privKey, new SecureRandom());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private byte[] sshEncodedSignatureFor(byte[] data, Ed25519PrivateKey privKey) {
			try {
				return Ed25519Verify.get().generateSignature(data, privKey, new SecureRandom());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private KeyPair keyPairFor(byte[] publicKey) {
			String nickname = manager.getKeyNickname(publicKey);

			if (nickname == null) {
				Log.w(TAG, "No key-pair found for public-key.");
				return null;
			}

			// check manager.loadedKeypairs.get(nickname).bean.isConfirmUse() and promptForPubkeyUse(nickname) ?
			return manager.getKey(nickname);
		}

	};
}
