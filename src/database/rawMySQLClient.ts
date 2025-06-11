import database from "./database.interface";
import net from "net";
import crypto from "crypto";

export default class RawMySQLClient implements database {
  getConnection(): void {
    const client = new net.Socket();
    client.connect(3306, "127.0.0.1", () => {
      console.log("Connected to MySQL server on port 3306");
    });

    /*
        MySQL Handshake Initialization Packet 
        null character로 끝나는 위치를 찾아야함(0x00)

        전체 len (3byte) + sequenceId(1byte)
        1              protocol version
        n              server version (null-terminated string)
        4              connection ID
        8              auth-plugin-data-part-1
        1              filler (0x00)
        2              capability flags (lower 2 bytes)
        1              character set
        2              status flags
        2              capability flags (upper 2 bytes)
        1              length of auth-plugin-data
        10             reserved (all 0x00)
        n              auth-plugin-data-part-2
        n              auth plugin name (null-terminated string)
        */

    client.on("data", (data) => {
      console.log("응답 도착:", data);
      // 0~3: 패킷 헤더
      const payloadLength = data.readUIntLE(0, 3); // 보통 0x4a
      const sequenceId = data.readUInt8(3);

      // 맨 앞 3바이트 length, 1바이트 시퀀스 번호 스킵
      // [패킷 길이 + 시퀀스 번호]
      let offset = 4;

      // 1. Protocol version (1 byte): 10
      const protocolVersion = data.readUInt8(offset);
      offset += 1;

      // 0x0a = 10, 시작시에만 보냄
      if (sequenceId === 0 && protocolVersion === 0x0a) {
        // do handshakeLogic
        const parsedHandshake = this.parseHandshake(data, offset); // 추출
        const loginPacket = this.constructLoginPacket(parsedHandshake); // 로그인 요청
        client.write(loginPacket);
        console.log("login packet 전송");
      }

      if (sequenceId === 2 && protocolVersion === 0xfe) {
        console.log("추가 인증 전송");
        const parsedAuthSwitchRequest = this.parseAuthSwitchRequest(
          data,
          offset
        );

        const password = "1234";
        const loginPacket = this.constructAuthSwitchRequest(
          parsedAuthSwitchRequest,
          password,
          sequenceId
        );
        client.write(loginPacket);
        console.log("추가 인증 전송 완료");
      }

      if (protocolVersion === 0x00) {
        // query 로직 전송가능 상태
        console.log(`login success`);
      }
    });

    client.on("close", () => {
      console.log("Connection closed");
    });
  }

  private constructAuthSwitchRequest(
    parsedAuthSwitchRequest: any,
    password: string,
    sequenceId: number
  ) {
    // console.log("salt length:", parsedAuthSwitchRequest.salt.length); // 반드시 20
    // console.log("salt (hex):", parsedAuthSwitchRequest.salt.toString("hex"));

    // console.log("password type:", typeof password); // 반드시 string
    // console.log("password:", password); // 실제 입력된 값
    // console.log(
    //   "sha1 (hex):",
    //   this.sha256(Buffer.from(String(password), "utf8")).toString("hex")
    // );

    const passwordSha1 = this.sha256(Buffer.from(password));
    const passwordSha2 = this.sha256(passwordSha1);
    const passwordSha3 = this.sha256(
      Buffer.concat([passwordSha2, parsedAuthSwitchRequest.salt])
    );

    const scrambled = Buffer.alloc(passwordSha1.length);
    for (let i = 0; i < passwordSha1.length; i++) {
      scrambled[i] = passwordSha1[i] ^ passwordSha3[i];
    }

    const payload = Buffer.concat([Buffer.from([scrambled.length]), scrambled]);

    const header = Buffer.alloc(4);
    // 0,1,2 length
    header.writeUIntLE(payload.length, 0, 3);
    // 3 sequenceId
    header.writeUInt8(sequenceId + 1, 3);

    console.log(
      "전송 패킷 2단계 인증(hex):",
      Buffer.concat([header, payload]).toString("hex")
    );

    return Buffer.concat([header, payload]);
  }

  private parseAuthSwitchRequest(
    data: Buffer<ArrayBufferLike>,
    offset: number
  ) {
    let pluginEnd = offset;
    while (data[pluginEnd] !== 0x00) {
      pluginEnd++;
    }
    const authPluginName = data.toString("utf8", offset, pluginEnd);
    offset = pluginEnd + 1;

    const salt = data.slice(offset, offset + 20); // 남은 전체는 salt (20 bytes), 널문자 짤라야함

    return { authPluginName, salt };
  }

  query() {
    throw new Error("Method not implemented.");
  }

  private parseHandshake(data: any, offset: any) {
    // 2. Server version (null end)
    let serverEnd = offset;
    while (data[serverEnd] !== 0x00) {
      serverEnd++;
    }

    const serverVersion = data.toString("utf8", offset, serverEnd);
    offset = serverEnd + 1;

    // 3. Connection ID (4 bytes)
    const connectionId = data.readUInt32LE(offset);
    offset += 4;

    // 4. Auth plugin data part 1 (8 bytes)
    const salt1 = data.slice(offset, offset + 8);
    offset += 8;

    // 5. Filler (1 byte)
    offset += 1;

    // 6. Capability flags (lower 2 bytes)
    const capabilityFlagsLower = data.readUInt16LE(offset);
    offset += 2;

    // 7. Character set (1 byte)
    const characterSet = data.readUInt8(offset);
    offset += 1;

    // 8. Status flags (2 bytes)
    const statusFlags = data.readUInt16LE(offset);
    offset += 2;

    // 9. Capability flags (upper 2 bytes)
    const capabilityFlagsUpper = data.readUInt16LE(offset);
    offset += 2;

    const capabilityFlags = capabilityFlagsLower | (capabilityFlagsUpper << 16);

    // 10. Length of auth-plugin-data (1 byte)
    const authPluginDataLength = data.readUInt8(offset);
    offset += 1;

    // 11. Reserved (10 bytes)
    offset += 10;

    // 12. Auth plugin data part 2 (~12 bytes, length can vary)
    const salt2 = data.slice(
      offset,
      offset + Math.max(13, authPluginDataLength - 8)
    );
    offset += salt2.length;

    // 13. Auth plugin name (null end)
    let pluginEnd = offset;
    while (data[pluginEnd] !== 0x00 && pluginEnd < data.length) {
      pluginEnd++;
    }
    const authPluginName = data.toString("utf8", offset, pluginEnd);

    // Combine salt1 + salt2
    const fullSalt = Buffer.concat([salt1, salt2]);

    console.log(`Parsed Handshake:
- Server Version: ${serverVersion}
- Connection ID: ${connectionId}
- Character Set: ${characterSet}
- Status Flags: 0x${statusFlags.toString(16)}
- Capability Flags: 0x${capabilityFlags.toString(16)}
- Auth Plugin Name: ${authPluginName}
- Salt: ${fullSalt.toString("hex")}
`);
    return {
      username: "root",
      password: "1234",
      database: "prisma",
      salt: fullSalt,
      capabilityFlags: capabilityFlags,
      authPluginName: authPluginName,
    };
  }

  private constructLoginPacket(parsedHandshake: any) {
    const CLIENT_LONG_PASSWORD = 0x00000001;
    const CLIENT_PROTOCOL_41 = 0x00000200;
    const CLIENT_SECURE_CONNECTION = 0x00008000;
    const CLIENT_PLUGIN_AUTH = 0x00080000;

    const capabilityFlags =
      CLIENT_LONG_PASSWORD |
      CLIENT_PROTOCOL_41 |
      CLIENT_SECURE_CONNECTION |
      CLIENT_PLUGIN_AUTH;

    const fixedFlags = capabilityFlags >>> 0;

    console.log(fixedFlags); // 숫자가 음수로 출력되면 문제 있음
    console.log(fixedFlags >>> 0); // 이게 4294967263이어야 OK

    const maxPacketSize = 0x01000000;
    const charset = 0x21; // utf8_general_ci

    const clientFlags = Buffer.alloc(4);
    clientFlags.writeUInt32LE(fixedFlags);

    const maxPacket = Buffer.alloc(4);
    maxPacket.writeUInt32LE(maxPacketSize);

    const filler = Buffer.alloc(23, 0);

    const unameBuf = Buffer.from(parsedHandshake.username + "\0");

    // caching_sha2_password password scramble
    // 1단계: SHA256(password)
    const passwordSha1 = this.sha256(parsedHandshake.password);

    // 2단계: SHA256(SHA256(password))
    const passwordSha2 = this.sha256(passwordSha1);

    // 3단계: SHA256(SHA256(password) + salt)
    const hashInput = Buffer.concat([passwordSha2, parsedHandshake.salt]);
    const passwordSha3 = this.sha256(hashInput);

    // 4단계: scramble = SHA256(password) XOR SHA256(SHA256(password) + salt)
    const scrambled = this.xorBuffers(passwordSha1, passwordSha3);

    const passBuf = Buffer.concat([Buffer.from([scrambled.length]), scrambled]);

    const dbBuf = parsedHandshake.database
      ? Buffer.from(parsedHandshake.database + "\0")
      : Buffer.alloc(0);
    const pluginBuf = Buffer.from(parsedHandshake.authPluginName + "\0");

    // 전체 payload (패킷 헤더 제외)
    const payload = Buffer.concat([
      clientFlags,
      maxPacket,
      Buffer.from([charset]),
      filler,
      unameBuf,
      passBuf,
      dbBuf,
      pluginBuf,
    ]);

    // 패킷 헤더 (length + packet number)
    const length = payload.length;
    const header = Buffer.alloc(4);
    header.writeUIntLE(length, 0, 3); // 3바이트 길이
    header.writeUInt8(1, 3); // 패킷 번호 = 1

    console.log(
      "전송 패킷(hex):",
      Buffer.concat([header, payload]).toString("hex")
    );

    return Buffer.concat([header, payload]);
  }

  private sha256(input: Buffer): Buffer {
    return crypto.createHash("sha256").update(input).digest();
  }

  private xorBuffers(buf1: Buffer, buf2: Buffer): Buffer {
    const len = Math.min(buf1.length, buf2.length);
    const result = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      result[i] = buf1[i] ^ buf2[i];
    }
    return result;
  }
}
