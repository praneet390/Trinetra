compilation command:

g++ -o security_svc.exe malware.cpp -mwindows -static-libgcc -static-libstdc++ -s -O2 -lwininet -lgdiplus -lole32 -lshell32 -lntdll
