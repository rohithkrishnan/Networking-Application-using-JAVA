package client;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
/*Distributed Networking Program
* ENTS640 Project
* Authors: Rohith Krishnan (114203274), Purnankh Dhankhar
* Client Side Script*/
public class DistributedNetworkClient {

	public static void main(String[] args) throws IOException {
		byte[] packetType = new byte[1];
		byte[] receivedData = new byte[500]; /*
												 * Byte array to hold received
												 * message
												 */
		byte[] integrityCheckReceived = new byte[4]; /*
														 * Byte array to hold
														 * the received IC value
														 */
		byte[] reply = new byte[9]; /* ACK packet byte array */
		byte[] key = { 0x11, 0x7F, -0x00, -0x7F, -0x2A, 0x1A, 0x11, 0x19, 0x6E, 0x5C, 0x4B, 0x1F, 0x56, 0x37, 0x29,
				0x18 }; /* RC4 key (Same as in Server) */
		byte[] seqNum = { 0x00, 0x1F, 0x4A, 0x2A }; // (0,31,74,42)
		byte[] packetData = new byte[40]; /*
											 * Byte array to hold the received
											 * packet's data content
											 */

		int icflag = 0, h = 0;
		int waitLoop = 0;

		RC4 rc4ObjectC = null;
		rc4ObjectC.streamGenerationRC4(key);
		InetAddress IPcheck = InetAddress.getLocalHost();

		DatagramSocket clientSocket = new DatagramSocket(
				1000); /*
						 * Initialise client socket with port# 1000
						 */

		DatagramPacket toSendPacket = new DatagramPacket(reply, reply.length, IPcheck,
				5000); /*
						 * Datagram packet which would be sent to the server
						 */
		DatagramPacket receivedPacket = new DatagramPacket(packetData, packetData.length);

		do {
			// clientSocket.setSoTimeout(3000);

			/* Keep waiting for a packet from server */
			try {
				System.out.println("Waiting for packet from Server");
				clientSocket.receive(receivedPacket);
				System.out.println("\nReceived data Packet");
			} catch (InterruptedIOException error) {
				System.err
						.println("Error encountered:\nData packet not received." + error.getMessage() + " " + waitLoop);
			}

			packetData = receivedPacket.getData();

			if (packetData[0] == 0x55) {
				System.out.println(Arrays.toString(packetData));
				byte[] temp = new byte[36];
				System.arraycopy(packetData, 36, integrityCheckReceived, 0, 4);

				System.arraycopy(packetData, 0, temp, 0, packetData.length - 4);

				byte[] encryptedArray = rc4ObjectC.encrypt(temp);
				System.out.println("Processing the Data for security");
				byte[] integrityCheckCalculated = integrityCheck(encryptedArray);

				{
					for (int i = 0; i < 4; i++) {
						if (integrityCheckCalculated[i] != integrityCheckReceived[i]) {
							icflag++;
						}
					}
				}

			} else if (packetData[0] == (byte) 0xAA) {
				byte[] newArray = new byte[30];
				System.arraycopy(packetData, 0, newArray, 0, 30);
				System.out.println("Data Packet Received" + Arrays.toString(newArray));
				byte[] temp = new byte[26];
				System.arraycopy(packetData, 26, integrityCheckReceived, 0, 4);
				System.out.println("IC received:" + Arrays.toString(integrityCheckReceived));
				System.arraycopy(packetData, 0, temp, 0, packetData.length - 14);
				byte[] encryptedArray = rc4ObjectC.encrypt(temp);

				System.out.println("Processing the Data for security");
				byte[] integrityCheckCalculated = integrityCheck(encryptedArray);
				{
					for (int i = 0; i < 4; i++) {
						if (integrityCheckCalculated[i] != integrityCheckReceived[i]) {
							icflag++;
						}

					}
				}

			} else {
				System.err.println("\nPacket Type not recognised: Discarding");
				icflag = 0;
			}

			/*
			 * If icflag is set it means the packet has failed the Integrity
			 * Check and if it is 0, it means the packet passed the integrity
			 * check
			 */

			if (icflag != 0) {
				System.out.println("Integrity Check Failed\nSending same seq num");
				// send the same sequence number as ACK
				reply[0] = (byte) 0xff;
				byte[] ackData = new byte[5];
				ackData[0] = (byte) 0xFF;
				System.arraycopy(seqNum, 0, ackData, 1, 4);

				byte[] ackDataRC4 = rc4ObjectC.encrypt(ackData);
				byte[] ackDataIC = integrityCheck(ackDataRC4);

				for (int i = 1; i < 5; i++) {
					reply[i] = seqNum[i - 1];
				}
				for (int j = 5; j < 9; j++) {
					reply[j] = ackDataIC[j - 5];
				}

				clientSocket.send(toSendPacket);
			} else {
				System.out.println("Integrity Check Passed...");
				byte[] seqNumRcvd = new byte[4];
				System.arraycopy(packetData, 1, seqNumRcvd, 0, 4);

				int byteToIntR = java.nio.ByteBuffer.wrap(seqNumRcvd).getInt();
				int byteToInt = java.nio.ByteBuffer.wrap(seqNum).getInt();

				if (byteToIntR == byteToInt) {
					byteToInt++;
					seqNum = intToBytes(byteToInt);
					System.out.println("Incremented Sequence Number:" + Arrays.toString(seqNum));
					System.arraycopy(packetData, 6, receivedData, h, packetData[5]);
					h += packetData[5];
					System.out.println("Received Array Buffer" + Arrays.toString(receivedData));
				} else {
					System.out.println("Sequence Number Mismatch");
				}

				reply[0] = (byte) 0xff;
				byte[] ackData = new byte[5];
				ackData[0] = (byte) 0xff;
				System.arraycopy(seqNum, 0, ackData, 1, 4);

				byte[] ackDataRC4 = rc4ObjectC.encrypt(ackData);
				byte[] ackDataIC = integrityCheck(ackDataRC4);

				for (int i = 1; i < 5; i++) {
					reply[i] = seqNum[i - 1];
				}
				for (int l = 5; l < 9; l++) {
					reply[l] = ackDataIC[l - 5];
				}

				clientSocket.send(toSendPacket);
				System.out.println("Sending ACK packet:" + Arrays.toString(reply) + "\n");
			}

		} while (packetData[0] != (byte) 0xAA); /*
												 * Keep repeating the above code
												 * until last packet has been
												 * received
												 */
		System.out.println("The received message is:\n" + Arrays.toString(receivedData));
		System.out.println("!!!End of Transmission!!!");

		/* end of void main */
	}

	public static byte[] integrityCheck(byte[] encryptedArray) {

		byte[] ic = new byte[4];
		int remainder = encryptedArray.length % 4;

		if (remainder == 0) {
			for (int i = 0; i < encryptedArray.length; i += 4) {
				ic[0] = (byte) (ic[0] ^ encryptedArray[i]);
				ic[1] = (byte) (ic[1] ^ encryptedArray[i + 1]);
				ic[2] = (byte) (ic[2] ^ encryptedArray[i + 2]);
				ic[3] = (byte) (ic[3] ^ encryptedArray[i + 3]);
			}

			return ic;
		} else {

			/*
			 * If the array whose integrity check to be calculated is not a
			 * multiple of 4 pad additional zeroes to make it a multiple of 4
			 */
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

	public static byte[] intToBytes(final int i) {
		// Function to convert integer seq num into 4 byte array
		ByteBuffer bufferObject = ByteBuffer.allocate(4);
		bufferObject.putInt(i);
		return bufferObject.array();
	}
}
