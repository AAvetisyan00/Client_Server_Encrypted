/*
	UDP Server
*/

#include <stdio.h>
#include "UDPServer.h"
#include <iostream>
#include <cstdlib>
#include <string.h>
#include <string>
#include <cmath>

#ifndef _WIN32
using SOCKET = int
#define WSAGetLastError() 1
#else
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib") //Winsock Library
#endif

//#define SERVER "127.0.0.1"	//ip address of udp server
#define BUFLEN 	1024		    //Max length of buffer
#define PORT    8888			//The port on which to listen for incoming data

std::string dCoder(std::string s)
{
	char a[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	std::string result = "";
	for (int i = 0; i < s.length(); i++) {
		int k = 1;
		while (s[i] == s[i + 1] && i < s.length() - 1) {
			k++;
			i++;
		}
		//cout << s[i] << k;
		char c = a[k];
		result = result + s[i];
		result = result + c;
	}
	return result;
}

std::string nCoder(std::string d)
{
	char a[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	std::string result = "";
	int k, l = 0;
	for (int i = 0; i < d.length(); i = i + 2) {
		k = 0;
		while (a) {
			if (d[i + 1] == a[k]) {
				l = k;
				break;
			}
			k++;
		}
		while (l) {
			result = result + d[i];
			l--;
		}
	}
	return result;
}

// function to compute greatest common divisor
int gcd(int a, int b) {
	if (a == 0) {
		return b;
	}
	return gcd(b % a, a);
}

// function to compute modular inverse
int modInv(int a, int m) {
	int m0 = m, t, q;
	int x0 = 0, x1 = 1;

	if (m == 1)
		return 0;

	while (a > 1) {
		q = a / m;
		t = m;

		m = a % m;
		a = t;

		t = x0;
		x0 = x1 - q * x0;
		x1 = t;
	}

	if (x1 < 0)
		x1 += m0;

	return x1;
}

// function to compute modular exponentiation
int modExp(int base, int exponent, int modulus) {
	int result = 1;
	base = base % modulus;
	while (exponent > 0) {
		if (exponent % 2 == 1) {
			result = (result * base) % modulus;
		}
		exponent = exponent / 2;
		base = (base * base) % modulus;
	}
	return result;
}

// function to generate public and private key pairs
void generateKeys(int p, int q, int& n, int& e, int& d) {
	n = p * q;
	int phi = (p - 1) * (q - 1);
	e = 2;
	while (e < phi) {
		if (gcd(e, phi) == 1) {
			break;
		}
		e++;
	}
	d = modInv(e, phi);
}

// function to encrypt a string using RSA
std::string encrypt(std::string message, int n, int e) {
	std::string ciphertext = "";
	for (int i = 0; i < message.length(); i++) {
		int asciiValue = (int)message[i];
		int cipherValue = modExp(asciiValue, e, n);
		ciphertext += std::to_string(cipherValue) + " ";
	}
	return ciphertext;
}

// function to decrypt a string using RSA
std::string decrypt(std::string ciphertext, int n, int d) {
	std::string message = "";
	int startIndex = 0;
	while (startIndex < ciphertext.length()) {
		int endIndex = ciphertext.find(" ", startIndex);
		if (endIndex == -1) {
			endIndex = ciphertext.length();
		}
		std::string cipherValueString = ciphertext.substr(startIndex, endIndex - startIndex);
		int cipherValue = std::stoi(cipherValueString);
		int asciiValue = modExp(cipherValue, d, n);
		message += (char)asciiValue;
		startIndex = endIndex + 1;
	}
	return message;
}

int main(int argc, char* argv[])
{
	struct sockaddr_in si_other;
	//struct sockaddr_in si_other1;
	unsigned short srvport;
	int slen;
	char buf[BUFLEN];
	char msg[BUFLEN];
	int i, k = 0;

	std::string decod_string, ncode_string;

	int p = 13; // choose two prime numbers for p and q
	int q = 11;
	int n, e, d;
	generateKeys(p, q, n, e, d);

	srvport = (1 == argc) ? PORT : atoi(argv[1]);

	UDPServer server(srvport);
	slen = sizeof(si_other);

	while (1)
	{
		memset(msg, '\0', BUFLEN);
		memset(buf, '\0', BUFLEN);

		printf("Waiting for data...   ");
		server.RecvDatagram(buf, BUFLEN, (struct sockaddr*)&si_other, &slen);
		std::string ncode_string(buf);
		ncode_string = decrypt(ncode_string, n, d);
		ncode_string = nCoder(ncode_string);
		strcpy_s(buf, ncode_string.c_str());
		printf("%s ", buf);
		memset(buf, '\0', BUFLEN);

		printf("\nAnswer : ");
		gets_s(msg, BUFLEN);
		std::string decod_string(msg);
		decod_string = dCoder(decod_string);
		decod_string = encrypt(decod_string, n, e);
		strcpy_s(msg, decod_string.c_str());
		server.SendDatagram(msg, (int)strlen(msg), (struct sockaddr*)&si_other, slen);
		memset(msg, '\0', BUFLEN);
	}
	return 0;
}
