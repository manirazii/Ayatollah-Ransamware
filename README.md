# Ayatollah Ransomware

This is a simple ransomware implementation written in C for educational purposes. The program demonstrates how files in a directory can be encrypted using AES encryption, with the AES key itself being encrypted using RSA. The code also includes functionality to decrypt the files, simulating a ransomware attack and recovery process.

## **Disclaimer**
This code is for **educational purposes only**. Creating, distributing, or using ransomware is illegal and unethical. This project is intended to help security researchers and developers understand how ransomware works in order to better defend against it. Do not use this code for malicious purposes.

## **How It Works**
1. **Encryption**:
   - The program generates an RSA key pair.
   - For each file in the specified directory, it generates a random AES key.
   - The file is encrypted using the AES key.
   - The AES key is then encrypted using the RSA public key and saved in a separate `.key` file.

2. **Decryption**:
   - The program reads the encrypted AES key from the `.key` file.
   - The AES key is decrypted using the RSA private key.
   - The file is then decrypted using the AES key.

3. **Ransom Message**:
   - After encryption, a ransom message is displayed, simulating a typical ransomware demand.

## **Usage**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Ayatollah-Ransomware.git
   ```
2. Compile the code using a C compiler (e.g., GCC):
   ```bash
   gcc Ayatollah_Ransomware.c -o ransomware -lcrypt32
   ```
3. Run the program:
   ```bash
   ./ransomware
   ```

## **Important Notes**
- The code is designed to work on Windows due to its use of the Windows CryptoAPI.
- The program targets the `C:\test` directory by default. Modify the code to change the target directory.
- **Do not run this code on important files or systems.** Use a controlled environment for testing.

## **Ethical Use**
This project is intended to raise awareness about ransomware and help developers understand how to protect against such attacks. Always use this knowledge responsibly and ethically.
