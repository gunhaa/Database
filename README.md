
- https://dev.mysql.com/doc/dev/mysql-server/8.4.4/page_protocol_connection_phase.html
  - https://dev.mysql.com/doc/dev/mysql-server/8.4.4/page_caching_sha2_authentication_exchanges.html
- https://dev.mysql.com/doc/dev/mysql-server/8.4.4/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
```plaintext
Debugger attached.
Connected to MySQL server on port 3306
응답 도착: <Buffer 4a 00 00 00 0a 38 2e 30 2e 34 32 00 33 00 00 00 5d 2e 75 4d 7f 1e 42 0f 00 ff ff ff 02 00 ff df 15 00 00 00 00 00 00 00 00 00 00 56 6c 16 15 7b 48 18 ... 28 more bytes>
응답 전문: 4a0000000a382e302e343200330000005d2e754d7f1e420f00ffffff0200ffdf1500000000000000000000566c16157b481844482f4c050063616368696e675f736861325f70617373776f726400
Parsed Handshake:
- Server Version: 8.0.42
- Connection ID: 51
- Character Set: 255
- Status Flags: 0x2
- Capability Flags: 0x-20000001
- Auth Plugin Name: caching_sha2_password
- Salt: 5d2e754d7f1e420f566c16157b481844482f4c0500

557569
557569
전송 패킷(hex): 630000010182080000000001210000000000000000000000000000000000000000000000726f6f7400205fc1ba9c311e3211568106d0cbeccba236e9126c001a2ff79e7984f65fa59547707269736d610063616368696e675f736861325f70617373776f726400login packet 전송
응답 도착: <Buffer 2c 00 00 02 fe 63 61 63 68 69 6e 67 5f 73 68 61 32 5f 70 61 73 73 77 6f 72 64 00 5d 2e 75 4d 7f 1e 42 0f 56 6c 16 15 7b 48 18 44 48 2f 4c 05 00>
응답 전문: 2c000002fe63616368696e675f736861325f70617373776f7264005d2e754d7f1e420f566c16157b481844482f4c0500
추가 인증 전송
parseAuthSwitch의 Data:  <Buffer 2c 00 00 02 fe 63 61 63 68 69 6e 67 5f 73 68 61 32 5f 70 61 73 73 77 6f 72 64 00 5d 2e 75 4d 7f 1e 42 0f 56 6c 16 15 7b 48 18 44 48 2f 4c 05 00>
현재 offset은 5여야 한다: 5
salt:  <Buffer 5d 2e 75 4d 7f 1e 42 0f 56 6c 16 15 7b 48 18 44 48 2f 4c 05>
전송 패킷 2단계 인증 결과 MySQL에 전송:  2100000320dffd71e045e35f0cf0f928fc037be9667cf38f77caa0541997fa39bcdac77aef
추가 인증 전송 완료
```

- 흐름
  - Scramble - XOR(SHA256(password), SHA256(SHA256(SHA256(password)), salt))

```plaintext
[서버] Handshake  (salt1) , sequenceId: 00
   ↓
[클라이언트] LoginPacket (임시 scramble, salt1로 계산, 캐시용, 맞든 틀리든 의미X) ,sequenceId: 01
   ↓
[서버] AuthSwitchRequest (salt2 제공), sequenceId: 02
   ↓
[클라이언트] AuthSwitchResponse (scramble2: salt2로 계산), sequenceId: 03
   ↓
[서버] 인증결과 판단, sequenceId: 04
```

- handshake 프로토콜은
  - [전체길이]:3byte
  - [상태]:1byte
  - 
