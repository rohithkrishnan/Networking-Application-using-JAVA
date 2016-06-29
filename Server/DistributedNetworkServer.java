package server;

import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/*Distributed Networking Program
 * ENTS640 Project
 * Authors: Rohith Krishnan (114203274), Purnankh Dhankhar
 * Server Side Script*/
public class DistributedNetworkServer {

	public static void main(String[] args) throws Exception {
		byte[] rawData = new byte[500]; /*
										 * Byte Array that will contain the data
										 * to be sent
										 */
		byte[] data = new byte[30]; /*
									 * Buffer to hold individual chunks of data
									 */
		byte[] integrityCheck = new byte[4];
		byte[] key = { 0x11, 0x7F, -0x00, -0x7F, -0x2A, 0x1A, 0x11, 0x19, 0x6E, 0x5C, 0x4B, 0x1F, 0x56, 0x37, 0x29,
				0x18 }; // 128 bit key for RC4 Encryption Algorithm
		byte[] seqNum = { 0x00, 0x1F, 0x4A,
				0x2A }; /*
						 * Initial Sequence Number agreed by Server and Client
						 */
		byte packetType1 = 0x55;
		byte packetType2 = (byte) 0xAA;
		byte[] prependArray = new byte[6];
		byte[] ackData = new byte[9];
		int serverTimeout = 2000, mul = 1; /*
											 * Server Timeout value(Initialised
											 * with value of 2 seconds)
											 */
		int i;
		int icflag = 0; // Flag to indicate Integrity Check Mismatch
		int resend = 0; // Flag to indicate if packet resending is required
		RC4 rc4ObjectS = null; /*
								 * Object of class RC4 for accessing the
								 * corresponding class methods
								 */

		rc4ObjectS.streamGenerationRC4(
				key); /*
						 * Creating State Vector with the hardcoded Key
						 */

		DatagramSocket serverSocket = new DatagramSocket(
				5000); /*
						 * Server Socket initialised with port# 5000
						 */

		InetAddress IPcheck;
		IPcheck = InetAddress.getLocalHost(); // Get the address of the
												// LocalHost
		DatagramPacket receivedPacket = new DatagramPacket(ackData, ackData.length);

		// Create 500 bytes of random data
		System.out.println("Creating random bytes of Data");
		new Random().nextBytes(rawData);
		// 500 bytes of data
		System.out.println(Arrays.toString(rawData));
		// System.out.println("\n");

		int dataSize = 30; // chunk size
		int messageSize = rawData.length;
		// int counter = 0;

		/* Sending the packets in chunks of 30-- */
		for (i = 0; i < messageSize - dataSize + 1; i += dataSize) {
			data = Arrays.copyOfRange(rawData, i, i + dataSize);
			prependArray[0] = packetType1;
			for (int k = 1; k <= 4; k++) {
				prependArray[k] = seqNum[k - 1];
			}
			prependArray[5] = 30;
			byte[] dataPacket = new byte[40];
			byte[] temp = new byte[36];
			System.arraycopy(prependArray, 0, temp, 0, prependArray.length);
			System.arraycopy(data, 0, temp, prependArray.length, data.length);
			// System.out.println("Running RC4 encryption");
			// System.out.println(Arrays.toString(temp));
			byte[] cipherText = rc4ObjectS.encrypt(temp);

			integrityCheck = integrityCheck(cipherText);
			// System.out.println("Data being processed for secure
			// transmission");
			// System.out.println(Arrays.toString(integrityCheck));
			System.arraycopy(prependArray, 0, dataPacket, 0, prependArray.length);
			System.arraycopy(data, 0, dataPacket, prependArray.length, data.length);
			System.arraycopy(integrityCheck, 0, dataPacket, prependArray.length + data.length, integrityCheck.length);
			// System.out.println(Arrays.toString(dataPacket));

			DatagramPacket toSendPacket = new DatagramPacket(dataPacket, dataPacket.length, IPcheck, 1000);
			do {
				/* Send the data packet */
				serverSocket.send(toSendPacket);

				{
					/*
					 * Set a timeout in the case of not receiving an ACK packet
					 */
					serverSocket.setSoTimeout(serverTimeout * mul);
					try {
						// System.out.println("Waiting for reply from
						// client...");
						serverSocket.receive(receivedPacket);
						// System.out.println("\nRecieved ACK Packet");
						resend = 0;
					} catch (InterruptedIOException error) {
						/*
						 * If ACK packet not received in time, increase the
						 * timeout and resend the Packet
						 */
						System.err.println("Error encountered:\nACK packet not received --" + error.getMessage()
								+ "\nPacket sent with increased timeout of " + (serverTimeout / 1000) * mul + " (s)");
						resend = 1;
						mul *= 2;
						;
					}

				}
			} while (resend == 1 && mul < 8);
			/*
			 * If ACK packet is not received even after 3 timeouts, delcare
			 * communication failure and exit the program
			 */
			if (mul == 8) {
				System.err.println("!!!Communication Failure!!!\nAborting transmission and exiting program");
				System.exit(0);
			}

			ackData = receivedPacket
					.getData(); /*
								 * Extract the data from the Datagram Packet
								 */

			byte[] ackICRcvd = new byte[4]; // IC value of ACK Packet (received)
			System.arraycopy(ackData, 5, ackICRcvd, 0, 4);
			byte[] ackICData = new byte[5];
			System.arraycopy(ackData, 0, ackICData, 0, 5);

			byte[] ackDataRC4 = rc4ObjectS.encrypt(ackICData);
			byte[] ackIClocal = integrityCheck(
					ackDataRC4); /*
									 * IC value of ACK Packet (locally
									 * calculated)
									 */

			for (int z = 0; z < 4; z++) {/* Checking for IC Match */
				if (ackIClocal[z] != ackICRcvd[z]) {
					icflag++; // Increment the Flag if any of the bytes do not
								// match
				}
			}
			if (icflag != 0) {
				System.out.println("Integrity Check Failed..Sending last Packet");
			}

			byte[] seqNumRcvd = new byte[4];
			System.arraycopy(ackData, 1, seqNumRcvd, 0, 4);
			// System.out.println("Seq Num Recvd:" +
			// Arrays.toString(seqNumRcvd));
			int byteToIntR = java.nio.ByteBuffer.wrap(seqNumRcvd)
					.getInt(); /*
								 * Converting 4 byte sequence number to an
								 * integer
								 */
			int byteToInt = java.nio.ByteBuffer.wrap(seqNum)
					.getInt(); /*
								 * Converting 4 byte sequence number to an
								 * integer
								 */

			/*
			 * Condition to check for sequence number. If the received sequence
			 * number matches the sequence number of last sent packet, increment
			 * sequence number. If not resend the packet with same sequence number
			 */

			if (byteToIntR == (byteToInt + 1)) {
				byteToInt++;
				seqNum = intToBytes(byteToInt);
				// System.out.println("Packet delivered successfully, sending
				// next packet..");
			} else {
				System.out.println("Seq Num mismatch...sending again");
				i -= 30;
			}
		}
		/* For the last packet */
		if (messageSize % dataSize != 0) {
			data = Arrays.copyOfRange(rawData, messageSize - messageSize % dataSize, messageSize);
			// System.out.println(Arrays.toString(data));
			prependArray[0] = packetType2;
			for (int k = 1; k <= 4; k++) {
				prependArray[k] = seqNum[k - 1];
			}

			prependArray[5] = (byte) (rawData.length % 30);

			byte[] dataPacket = new byte[30];
			byte[] temp = new byte[26];
			System.arraycopy(prependArray, 0, temp, 0, prependArray.length);
			System.arraycopy(data, 0, temp, prependArray.length, data.length);

			// System.out.println(Arrays.toString(temp));
			byte[] cipherText = rc4ObjectS.encrypt(temp);

			integrityCheck = integrityCheck(cipherText);

			// System.out.println(Arrays.toString(integrityCheck));
			System.arraycopy(prependArray, 0, dataPacket, 0, prependArray.length);
			System.arraycopy(data, 0, dataPacket, prependArray.length, data.length);
			System.arraycopy(integrityCheck, 0, dataPacket, prependArray.length + data.length, integrityCheck.length);
			// System.out.println(Arrays.toString(dataPacket));

			DatagramPacket toSendPacket = new DatagramPacket(dataPacket, dataPacket.length, IPcheck, 1000);
			serverSocket.send(toSendPacket);
			// System.out.println("!!!Sending last DATA PACKET!!!");

			{ /* ACK packet not received handling */
				mul = 1;
				resend = 0;
				do {
					serverSocket.setSoTimeout(serverTimeout * mul);
					try {
						serverSocket.receive(receivedPacket);
						// System.out.println("\nReceived last ACK data
						// Packet");
						resend = 0;
					} catch (InterruptedIOException error) {
						System.err.println("Error encountered:\nACK packet not received" + error.getMessage());
						mul++;
						resend = 1;
					}

				} while (resend == 1 && mul < 8);
			}
			ackData = receivedPacket.getData();

			// System.out.println(Arrays.toString(ackData));
			byte[] ackICRcvd = new byte[4];
			System.arraycopy(ackData, 5, ackICRcvd, 0, ackICRcvd.length);
			// System.out.println("Received ACK IC value is:" +
			// Arrays.toString(ackICRcvd));
			byte[] ackICData = new byte[5];
			System.arraycopy(ackData, 0, ackICData, 0, ackICData.length);
			byte[] ackDataRC4 = rc4ObjectS.encrypt(ackICData);
			byte[] ackICLocal = integrityCheck(ackDataRC4);

			for (int z = 0; z < 4; z++) {
				if (ackICLocal[z] != ackICRcvd[z]) {
					icflag++;
				}
			}
			if (icflag == 0) {
				// System.out.println("Integrity Check Passed");
				System.out.print("Last packet delivered successfully, ending transmission");
			} else {
				System.out.println("Ack packet IC Failed");
			}
		}
		/* End of main() */
	}

	public static byte[] integrityCheck(byte[] encryptedArray) {
		/* fucntion for calculating the Integrity Check */
		byte[] ic = new byte[4];
		int remainder = encryptedArray.length % 4;

		// Check if padding required
		if (remainder == 0) {
			for (int i = 0; i < encryptedArray.length; i += 4) {
				ic[0] = (byte) (ic[0] ^ encryptedArray[i]);
				ic[1] = (byte) (ic[1] ^ encryptedArray[i + 1]);
				ic[2] = (byte) (ic[2] ^ encryptedArray[i + 2]);
				ic[3] = (byte) (ic[3] ^ encryptedArray[i + 3]);

			}

			return ic;
		} else {
			encryptedArray = Arrays.copyOf(encryptedArray, encryptedArray.length + (4 - remainder));
			for (int i = 0; i < encryptedArray.length; i += 4) {
				ic[0] = (byte) (ic[0] ^ encryptedArray[i]);
				ic[1] = (byte) (ic[1] ^ encryptedArray[i + 1]);
				ic[2] = (byte) (ic[2] ^ encryptedArray[i + 2]);
				ic[3] = (byte) (ic[3] ^ encryptedArray[i + 3]);

			}
			return ic;
		}
	}

	/* Function to Convert integer value to bytes */
	public static byte[] intToBytes(final int i) {
		ByteBuffer bufferObject = ByteBuffer.allocate(4);
		bufferObject.putInt(i);
		return bufferObject.array();
	}

	/* End of Class DistributedNetworkServer */
}
