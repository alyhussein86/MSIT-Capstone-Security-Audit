# MSIT-Capstone-Security-Audit

This is a readme file for documentation purposes only

# Documentation

All the below instructions were run on an isolated OS particularly KaliLinux on VM loader like Oracle VirtalBox

# Download VirtualBox: 
https://www.virtualbox.org/wiki/Downloads.

# Download KaliLinux OS: 
https://www.kali.org/get-kali/#kali-platforms

# KaliLinux Documenation: 
https://www.kali.org/docs/introduction/download-official-kali-linux-images/

Quick setup with docker or run Dockerfile in the Docker Image folder

docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest


Default username and password: mobsf/mobsf

Using browser accessing local network (http://localhost:80000)

click in Static Analyser so that you can analyse your mobile app (android apk, or iOS ipa file)

Extract and download the JSON file of the analysed data as (mobsf_scan.json).

Run WireShark to capture the network behaviour.

Capture a network packet (traffic_capture.pcap) and save it on the same path as the JSON file.

then run the correlation.py to identify the vulnerabilites on the app and matches it with the Network.

Run Test_Correlation_engine.py identify the vulnerabilites on your app and help you to close any incoming cyberattack on your app or pakage specifically on HTTP and TLS connection.
