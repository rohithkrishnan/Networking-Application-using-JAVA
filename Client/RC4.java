package client;

public class RC4 {

	private static byte[] stateVector = new byte[256];
	private static byte[] tempVector = new byte[256];
	private static int keyLength;

	public static void streamGenerationRC4(byte[] key) {
		if (key.length < 1 || key.length > 256) {
			throw new IllegalArgumentException("key must be between 1 and 256 bytes");
		} else {
			keyLength = key.length;
			for (int i = 0; i < 256; i++) {
				stateVector[i] = (byte) i;
				tempVector[i] = key[i % keyLength];
			}
			int j = 0;
			byte temp;
			for (int i = 0; i < 256; i++) {
				j = (j + stateVector[i] & 0xFF + tempVector[i] & 0xFF) % 256;
				// Swapping values
				temp = stateVector[j];
				stateVector[j] = stateVector[i];
				stateVector[i] = temp;
			}
		}

	}

	public static byte[] encrypt(byte[] plainText) {
		byte[] ciphertext = new byte[plainText.length];
		int i = 0, j = 0, k, t;
		byte temp;

		for (int counter = 0; counter < plainText.length; counter++) {
			i = (i + 1) % 256;
			j = (j + stateVector[i] & 0xFF) % 256;
			temp = stateVector[j];
			stateVector[j] = stateVector[i];
			stateVector[i] = temp;
			t = (stateVector[i] & 0xFF + stateVector[j] & 0xFF) % 256;
			k = stateVector[t];
			ciphertext[counter] = (byte) (plainText[counter] ^ k);

		}
		return ciphertext;
	}

}
