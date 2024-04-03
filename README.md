# Network_programming

## 1. PCAP Programming

### PCAP API를 활용해 Packet의 정보를 출력하는 프로그램 작성

#### Packet 정보는 다음과 같다.

##### Ethernet Header : src mac / dst mac
##### IP Header : src ip / dst ip
##### TCP Header : src port / dst port
##### Message : nc 명령어를 통한 message 수신
##### 하나의 PC에서 $ nc <수신자 IP> <Port> 명령어를 통해 message를 보내고 그 메세지와 함깨 위의 패킷 정보들을 출력하는 프로그램이다.
##### 두 개의 PC로 테스트를 해보았으며, Listen 상태인 Port는 $ lsof -i | grep LISTEN로 확인 하였다. (Mac M1 환경 기준)
##### 아래와 1번 그림과 같이 hi라는 메세지를 보내면 수신 PC에서 해당 프로그램을 통해 결과 값이 2번 그림처럼 출력 되는 것을 볼 수 있다.
1. ![image](https://github.com/jeongahn/Network_programming/assets/54920329/f79c38ca-3d40-43f0-8fe0-1d159589fde1)
2. ![image](https://github.com/jeongahn/Network_programming/assets/54920329/c2a3f746-d53f-44b8-9e17-41de2d418914)

##### 코드 컴파일 명령어 : gcc -o Packet_info Packet_info.c -lpcap
